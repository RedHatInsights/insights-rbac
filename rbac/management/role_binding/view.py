#
# Copyright 2025 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""View for role binding management."""
import logging
from typing import Iterable, Optional, Sequence

from django.conf import settings
from django.db.models import Count, Max, Prefetch, Q
from google.protobuf import json_format
from internal.jwt_utils import JWTManager, JWTProvider
from kessel.relations.v1beta1 import common_pb2, lookup_pb2, lookup_pb2_grpc
from management.base_viewsets import BaseV2ViewSet
from management.cache import JWTCache
from management.models import Group
from management.permissions.workspace_access import WorkspaceAccessPermission
from management.principal.model import Principal
from management.role.v2_model import RoleBinding, RoleBindingGroup
from management.utils import create_client_channel
from management.workspace.model import Workspace
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.response import Response

from .pagination import RoleBindingCursorPagination
from .serializer import RoleBindingBySubjectSerializer

logger = logging.getLogger(__name__)


class RoleBindingViewSet(BaseV2ViewSet):
    """Role Binding ViewSet.

    Provides read-only access to role bindings currently.
    """

    permission_classes = (WorkspaceAccessPermission,)
    serializer_class = RoleBindingBySubjectSerializer
    pagination_class = RoleBindingCursorPagination

    @action(detail=False, methods=["get"], url_path="by-subject")
    def by_subject(self, request, *args, **kwargs):
        """List role bindings grouped by subject.

        Required query parameters:
            - resource_id: Filter by resource ID
            - resource_type: Filter by resource type

        Optional query parameters:
            - subject_type: Filter by subject type (user/group)
            - subject_id: Filter by subject ID
            - fields: Control which fields are included in response
            - order_by: Sort by specified field(s)
            - limit: Number of results per page (default: 10)
            - cursor: Cursor for pagination
        """
        # Validate required parameters
        resource_id = request.query_params.get("resource_id")
        resource_type = request.query_params.get("resource_type")

        if not resource_id:
            raise serializers.ValidationError({"resource_id": "This query parameter is required."})
        if not resource_type:
            raise serializers.ValidationError({"resource_type": "This query parameter is required."})

        # Optional parameters
        subject_type = request.query_params.get("subject_type")
        subject_id = request.query_params.get("subject_id")
        fields = request.query_params.get("fields")
        order_by = request.query_params.get("order_by")
        parent_role_bindings = request.query_params.get("parent_role_bindings")
        include_inherited = str(parent_role_bindings).lower() in {"true", "1", "yes"}

        # Determine role binding UUIDs for the resource via Relations (includes inheritance)
        binding_uuids = self._lookup_binding_uuids_via_relations(resource_type, resource_id) if include_inherited else None

        # Build queryset based on subject type
        if subject_type == "user":
            queryset = self._build_principal_queryset(
                resource_id=resource_id,
                resource_type=resource_type,
                subject_id=subject_id,
                tenant=request.tenant,
                binding_uuids=binding_uuids,
            )
        else:
            # Default to groups (both when subject_type="group" or not specified)
            queryset = self._build_group_queryset(
                resource_id=resource_id,
                resource_type=resource_type,
                subject_type=subject_type,
                subject_id=subject_id,
                tenant=request.tenant,
                binding_uuids=binding_uuids,
            )

        # Apply ordering
        if order_by:
            queryset = self._apply_ordering(queryset, order_by)
        else:
            # Default ordering for cursor pagination
            queryset = queryset.order_by("-latest_modified")

        # Store resource info in request context for serializer
        request.resource_id = resource_id
        request.resource_type = resource_type
        request.resource_name = self._get_resource_name(resource_id, resource_type, request.tenant)
        request.include_inherited = include_inherited

        # Paginate results
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True, fields=fields, context={"request": request})
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True, fields=fields, context={"request": request})
        return Response(serializer.data)

    def _build_group_queryset(
        self,
        resource_id,
        resource_type,
        subject_type,
        subject_id,
        tenant,
        binding_uuids: Optional[Sequence[str]] = None,
    ):
        """Build a queryset of groups with their role bindings for the specified resource.

        Returns a queryset of Group objects annotated with:
        - principalCount: Count of user principals in the group
        - latest_modified: Latest modification timestamp from associated roles

        Each group will have prefetched role bindings filtered by resource.
        """
        # Start with groups that have bindings to the specified resource
        rb_filters = {
            "tenant": tenant,
        }
        if binding_uuids:
            # Use relations-derived binding UUIDs for inherited bindings
            queryset = Group.objects.filter(
                **rb_filters,
                role_binding_entries__binding__uuid__in=binding_uuids,
            ).distinct()
        else:
            # Fallback: only direct bindings on the resource
            queryset = Group.objects.filter(
                **rb_filters,
                role_binding_entries__binding__resource_type=resource_type,
                role_binding_entries__binding__resource_id=resource_id,
            ).distinct()

        # Apply subject filtering if specified
        if subject_type == "group" and subject_id:
            queryset = queryset.filter(uuid=subject_id)
        elif subject_id and not subject_type:
            # If subject_id is provided without type, try to match on group uuid
            queryset = queryset.filter(uuid=subject_id)

        # Annotate with principal count
        queryset = queryset.annotate(
            principalCount=Count("principals", filter=Q(principals__type=Principal.Types.USER), distinct=True)
        )

        # Prefetch the role bindings for this resource with their roles
        if binding_uuids:
            binding_queryset = RoleBinding.objects.filter(uuid__in=binding_uuids).select_related("role")
        else:
            binding_queryset = RoleBinding.objects.filter(
                resource_type=resource_type, resource_id=resource_id
            ).select_related("role")

        # Prefetch the join table entries with the filtered bindings
        if binding_uuids:
            rolebinding_group_queryset = RoleBindingGroup.objects.filter(
                binding__uuid__in=binding_uuids
            ).prefetch_related(Prefetch("binding", queryset=binding_queryset))
        else:
            rolebinding_group_queryset = RoleBindingGroup.objects.filter(
                binding__resource_type=resource_type, binding__resource_id=resource_id
            ).prefetch_related(Prefetch("binding", queryset=binding_queryset))

        queryset = queryset.prefetch_related(
            Prefetch("role_binding_entries", queryset=rolebinding_group_queryset, to_attr="filtered_bindings")
        )

        # Annotate with latest modified timestamp from roles (restricted to relevant bindings when available)
        if binding_uuids:
            queryset = queryset.annotate(
                latest_modified=Max(
                    "role_binding_entries__binding__role__modified",
                    filter=Q(role_binding_entries__binding__uuid__in=binding_uuids),
                )
            )
        else:
            queryset = queryset.annotate(latest_modified=Max("role_binding_entries__binding__role__modified"))

        return queryset

    def _build_principal_queryset(
        self,
        resource_id,
        resource_type,
        subject_id,
        tenant,
        binding_uuids: Optional[Sequence[str]] = None,
    ):
        """Build a queryset of principals (users) with their role bindings for the specified resource.

        Returns a queryset of Principal objects annotated with:
        - latest_modified: Latest modification timestamp from associated roles

        Each principal will have prefetched groups and their role bindings filtered by resource.
        """
        # Start with principals that belong to groups with bindings to the specified resource
        if binding_uuids:
            queryset = Principal.objects.filter(
                tenant=tenant,
                type=Principal.Types.USER,
                group__role_binding_entries__binding__uuid__in=binding_uuids,
            ).distinct()
        else:
            queryset = Principal.objects.filter(
                tenant=tenant,
                type=Principal.Types.USER,
                group__role_binding_entries__binding__resource_type=resource_type,
                group__role_binding_entries__binding__resource_id=resource_id,
            ).distinct()

        # Apply subject filtering if specified
        if subject_id:
            queryset = queryset.filter(uuid=subject_id)

        # Prefetch the role bindings through groups
        if binding_uuids:
            binding_queryset = RoleBinding.objects.filter(uuid__in=binding_uuids).select_related("role")
        else:
            binding_queryset = RoleBinding.objects.filter(
                resource_type=resource_type, resource_id=resource_id
            ).select_related("role")

        # Prefetch the join table entries with the filtered bindings
        if binding_uuids:
            rolebinding_group_queryset = RoleBindingGroup.objects.filter(
                binding__uuid__in=binding_uuids
            ).prefetch_related(Prefetch("binding", queryset=binding_queryset))
        else:
            rolebinding_group_queryset = RoleBindingGroup.objects.filter(
                binding__resource_type=resource_type, binding__resource_id=resource_id
            ).prefetch_related(Prefetch("binding", queryset=binding_queryset))

        # Prefetch groups with their filtered bindings
        group_queryset = Group.objects.prefetch_related(
            Prefetch("role_binding_entries", queryset=rolebinding_group_queryset, to_attr="filtered_bindings")
        )

        queryset = queryset.prefetch_related(Prefetch("group", queryset=group_queryset, to_attr="filtered_groups"))

        # Annotate with latest modified timestamp from roles (restricted to relevant bindings when available)
        if binding_uuids:
            queryset = queryset.annotate(
                latest_modified=Max(
                    "group__role_binding_entries__binding__role__modified",
                    filter=Q(group__role_binding_entries__binding__uuid__in=binding_uuids),
                )
            )
        else:
            queryset = queryset.annotate(
                latest_modified=Max("group__role_binding_entries__binding__role__modified")
            )

        return queryset

    def _get_resource_name(self, resource_id, resource_type, tenant):
        """Get the name of the resource."""
        if resource_type == "workspace":
            try:
                workspace = Workspace.objects.get(id=resource_id, tenant=tenant)
                return workspace.name
            except Workspace.DoesNotExist:
                logger.warning(f"Workspace {resource_id} not found for tenant {tenant}")
                return None
        return None

    def _apply_ordering(self, queryset, order_by):
        """Apply ordering to queryset."""
        order_fields = [field.strip() for field in order_by.split(",")]
        return queryset.order_by(*order_fields)

    def _lookup_binding_uuids_via_relations(self, resource_type: str, resource_id: str) -> list[str]:
        """Use Relations to find role binding UUIDs effective for the given resource.

        This leverages graph inheritance (parents, etc.) and returns binding UUIDs.
        Falls back to an empty list on errors so callers can choose DB-only filtering.
        """
        try:
            resource_ns, resource_name = self._parse_resource_type(resource_type)

            # Acquire JWT for Relations
            jwt_cache = JWTCache()
            jwt_provider = JWTProvider()
            jwt_manager = JWTManager(jwt_provider, jwt_cache)
            token = jwt_manager.get_jwt_from_redis()

            binding_ids: set[str] = set()

            # Use LookupSubjects to find effective role bindings via graph traversal
            with create_client_channel(settings.RELATION_API_SERVER) as channel:
                lookup_stub = lookup_pb2_grpc.KesselLookupServiceStub(channel)
                req = lookup_pb2.LookupSubjectsRequest(
                    resource=common_pb2.ObjectReference(
                        type=common_pb2.ObjectType(namespace=resource_ns, name=resource_name),
                        id=str(resource_id),
                    ),
                    permission="role_binding",
                    subject_type=common_pb2.ObjectType(namespace="rbac", name="role_binding"),
                )
                metadata = [("authorization", f"Bearer {token}")]
                responses: Iterable[lookup_pb2.LookupSubjectsResponse] = lookup_stub.LookupSubjects(req, metadata=metadata)
                for r in responses:
                    r_dict = json_format.MessageToDict(r)
                    # Expect subject.id under response
                    subject = r_dict.get("subject", {})
                    subject_id = subject.get("id") or subject.get("subject", {}).get("id")
                    if subject_id:
                        binding_ids.add(subject_id)

            return list(binding_ids)
        except Exception:  # noqa: BLE001
            logger.exception("Failed to lookup role binding UUIDs via Relations; falling back to direct bindings.")
            return []

    @staticmethod
    def _parse_resource_type(resource_type: str) -> tuple[str, str]:
        """Parse resource_type into (namespace, name). Defaults namespace to 'rbac'."""
        if "/" in resource_type:
            namespace, name = resource_type.split("/", 1)
            return namespace, name
        return "rbac", resource_type
