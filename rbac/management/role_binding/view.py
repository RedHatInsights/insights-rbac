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
from __future__ import annotations

import logging
from typing import Iterable, Optional, Sequence

from django.conf import settings
from django.db import models
from django.db.models import Count, Max, Prefetch, Q, Value
from google.protobuf import json_format
from internal.jwt_utils import JWTManager, JWTProvider
from kessel.relations.v1beta1 import common_pb2, lookup_pb2, lookup_pb2_grpc
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.response import Response

from management.base_viewsets import BaseV2ViewSet
from management.cache import JWTCache
from management.group.model import Group
from management.permissions.workspace_access import WorkspaceAccessPermission
from management.principal.model import Principal
from management.role.v2_model import RoleBinding, RoleBindingGroup
from management.utils import create_client_channel_relation
from management.workspace.model import Workspace

from .pagination import RoleBindingCursorPagination
from .serializer import RoleBindingBySubjectSerializer

logger = logging.getLogger(__name__)

# Lazily instantiate the JWT helpers once so all requests reuse the same objects.
_jwt_cache = JWTCache()
_jwt_provider = JWTProvider()
_jwt_manager = JWTManager(_jwt_provider, _jwt_cache)


class RoleBindingViewSet(BaseV2ViewSet):
    """Role Binding ViewSet providing read-only access to bindings by subject."""

    serializer_class = RoleBindingBySubjectSerializer
    permission_classes = (WorkspaceAccessPermission,)
    pagination_class = RoleBindingCursorPagination

    @action(detail=False, methods=["get"], url_path="by-subject")
    def by_subject(self, request, *args, **kwargs):
        """List role bindings grouped by subject."""
        resource_id = request.query_params.get("resource_id")
        resource_type_param = request.query_params.get("resource_type")
        if not resource_id:
            raise serializers.ValidationError({"resource_id": "This query parameter is required."})
        if not resource_type_param:
            raise serializers.ValidationError({"resource_type": "This query parameter is required."})

        # Normalize resource_type for internal use. For RBAC-local resources we only
        # store the short name (e.g. "workspace") in the database, but the caller
        # may provide either "workspace" or "rbac/workspace".
        if resource_type_param in {"workspace", "rbac/workspace"}:
            resource_type_db = "workspace"
        else:
            resource_type_db = resource_type_param

        # Validate resource_id where we know the shape (workspaces are UUIDs).
        if resource_type_db == "workspace" and not self._is_valid_uuid(resource_id):
            raise serializers.ValidationError({"resource_id": "A valid UUID is required for workspace resources."})

        subject_type = request.query_params.get("subject_type")
        subject_id = request.query_params.get("subject_id")
        fields = request.query_params.get("fields")
        order_by = request.query_params.get("order_by")
        parent_role_bindings = str(request.query_params.get("parent_role_bindings", "false")).lower()
        include_inherited = parent_role_bindings in {"true", "1", "yes"}

        binding_uuids: Optional[Sequence[str]] = None
        if include_inherited:
            # Pass the original resource_type through to Relations so that both
            # "workspace" and "rbac/workspace" work as callers expect.
            binding_uuids = self._lookup_binding_uuids_via_relations(resource_type_param, resource_id)
            if binding_uuids is None:
                include_inherited = False

        queryset = self._build_queryset(
            subject_type=subject_type,
            subject_id=subject_id,
            resource_id=resource_id,
            resource_type=resource_type_db,
            tenant=request.tenant,
            binding_uuids=binding_uuids,
        )

        queryset = self._apply_ordering(queryset, order_by)

        request.resource_id = resource_id
        # Expose the original resource_type back to the client while using the
        # normalized type for internal lookups.
        request.resource_type = resource_type_param
        request.resource_name = self._get_resource_name(resource_id, resource_type_db, request.tenant)
        request.include_inherited = include_inherited and binding_uuids is not None

        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(
            page if page is not None else queryset,
            many=True,
            fields=fields,
            context={"request": request},
        )

        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)

    #
    # Queryset construction helpers
    #
    def _build_queryset(
        self,
        subject_type: Optional[str],
        subject_id: Optional[str],
        resource_id: str,
        resource_type: str,
        tenant,
        binding_uuids: Optional[Sequence[str]] = None,
    ):
        """Select the correct queryset builder depending on subject type."""
        if subject_type and subject_type not in {"group", "user"}:
            raise serializers.ValidationError({"subject_type": "Valid options are 'group' or 'user'."})

        if subject_type == "group" and subject_id and not self._is_valid_uuid(subject_id):
            raise serializers.ValidationError({"subject_id": "A valid UUID is required for group subjects."})
        if subject_type == "user" and subject_id and not self._is_valid_uuid(subject_id):
            raise serializers.ValidationError({"subject_id": "A valid UUID is required for user subjects."})

        if subject_type == "user":
            return self._build_principal_queryset(
                resource_id=resource_id,
                resource_type=resource_type,
                subject_id=subject_id,
                tenant=tenant,
                binding_uuids=binding_uuids,
            )

        return self._build_group_queryset(
            resource_id=resource_id,
            resource_type=resource_type,
            subject_id=subject_id,
            tenant=tenant,
            binding_uuids=binding_uuids,
        )

    def _build_group_queryset(
        self,
        resource_id: str,
        resource_type: str,
        subject_id: Optional[str],
        tenant,
        binding_uuids: Optional[Sequence[str]] = None,
    ):
        """Return a queryset of groups with role bindings for the given resource."""
        if binding_uuids is not None and len(binding_uuids) == 0:
            # Return an empty queryset that is still compatible with ordering on
            # the annotated "latest_modified" field used by pagination.
            return Group.objects.none().annotate(latest_modified=Max("modified"))

        if binding_uuids is not None:
            queryset = Group.objects.filter(
                tenant=tenant,
                role_binding_entries__binding__uuid__in=binding_uuids,
            ).distinct()
        else:
            queryset = Group.objects.filter(
                tenant=tenant,
                role_binding_entries__binding__resource_type=resource_type,
                role_binding_entries__binding__resource_id=resource_id,
            ).distinct()

        if subject_id:
            queryset = queryset.filter(uuid=subject_id)

        queryset = queryset.annotate(
            principalCount=Count("principals", filter=Q(principals__type=Principal.Types.USER), distinct=True)
        )

        binding_queryset = self._binding_queryset(binding_uuids, resource_type, resource_id)

        rolebinding_group_queryset = self._rolebinding_group_queryset(
            binding_uuids=binding_uuids,
            resource_type=resource_type,
            resource_id=resource_id,
            binding_queryset=binding_queryset,
        )

        queryset = queryset.prefetch_related(
            Prefetch("role_binding_entries", queryset=rolebinding_group_queryset, to_attr="filtered_bindings")
        )

        if binding_uuids is not None:
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
        resource_id: str,
        resource_type: str,
        subject_id: Optional[str],
        tenant,
        binding_uuids: Optional[Sequence[str]] = None,
    ):
        """Return a queryset of principals (users) with bindings via their groups."""
        if binding_uuids is not None and len(binding_uuids) == 0:
            # Return an empty queryset that is still compatible with ordering on
            # the annotated "latest_modified" field used by pagination.
            # Principal doesn't have a 'modified' field, so we use Value(None) for empty querysets.
            # Specify output_field as DateTimeField to match the expected type for latest_modified.
            return Principal.objects.none().annotate(latest_modified=Value(None, output_field=models.DateTimeField()))

        if binding_uuids is not None:
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

        if subject_id:
            queryset = queryset.filter(uuid=subject_id)

        binding_queryset = self._binding_queryset(binding_uuids, resource_type, resource_id)
        rolebinding_group_queryset = self._rolebinding_group_queryset(
            binding_uuids=binding_uuids,
            resource_type=resource_type,
            resource_id=resource_id,
            binding_queryset=binding_queryset,
        )

        group_queryset = Group.objects.prefetch_related(
            Prefetch("role_binding_entries", queryset=rolebinding_group_queryset, to_attr="filtered_bindings")
        )

        queryset = queryset.prefetch_related(Prefetch("group", queryset=group_queryset, to_attr="filtered_groups"))

        if binding_uuids is not None:
            queryset = queryset.annotate(
                latest_modified=Max(
                    "group__role_binding_entries__binding__role__modified",
                    filter=Q(group__role_binding_entries__binding__uuid__in=binding_uuids),
                )
            )
        else:
            queryset = queryset.annotate(latest_modified=Max("group__role_binding_entries__binding__role__modified"))

        return queryset

    def _binding_queryset(self, binding_uuids, resource_type, resource_id):
        """Return the base RoleBinding queryset used for Prefetch operations."""
        if binding_uuids is not None:
            if len(binding_uuids) == 0:
                return RoleBinding.objects.none()
            return RoleBinding.objects.filter(uuid__in=binding_uuids).select_related("role")

        return RoleBinding.objects.filter(resource_type=resource_type, resource_id=resource_id).select_related("role")

    def _rolebinding_group_queryset(self, binding_uuids, resource_type, resource_id, binding_queryset):
        """Return the RoleBindingGroup queryset used for Prefetch."""
        if binding_uuids is not None:
            if len(binding_uuids) == 0:
                return RoleBindingGroup.objects.none()
            base = RoleBindingGroup.objects.filter(binding__uuid__in=binding_uuids)
        else:
            base = RoleBindingGroup.objects.filter(
                binding__resource_type=resource_type, binding__resource_id=resource_id
            )

        return base.prefetch_related(Prefetch("binding", queryset=binding_queryset))

    #
    # Utility helpers
    #
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
        """Apply ordering with validation."""
        # Default ordering: use -latest_modified when it has been annotated,
        # otherwise leave the queryset ordering unchanged (e.g. for .none()).
        if not order_by:
            if "latest_modified" in getattr(queryset.query, "annotations", {}):
                return queryset.order_by("-latest_modified")
            return queryset

        fields = [field.strip() for field in order_by.split(",") if field.strip()]
        if not fields:
            if "latest_modified" in getattr(queryset.query, "annotations", {}):
                return queryset.order_by("-latest_modified")
            return queryset

        allowed = {"latest_modified", "-latest_modified"}
        unknown = [field for field in fields if field not in allowed]
        if unknown:
            raise serializers.ValidationError({"order_by": f"Unsupported ordering fields: {', '.join(unknown)}"})

        return queryset.order_by(*fields)

    def _lookup_binding_uuids_via_relations(self, resource_type: str, resource_id: str) -> Optional[list[str]]:
        """Use the Relations API to resolve binding UUIDs that affect the given resource."""
        if not settings.RELATION_API_SERVER:
            logger.warning("RELATION_API_SERVER is not configured; skipping inheritance lookup.")
            return None

        try:
            logger.info(
                "Calling _lookup_binding_uuids_via_relations for resource_type=%s, resource_id=%s",
                resource_type,
                resource_id,
            )
            resource_ns, resource_name = self._parse_resource_type(resource_type)
            token = _jwt_manager.get_jwt_from_redis()
            metadata = [("authorization", f"Bearer {token}")] if token else []
            binding_ids = set()

            with create_client_channel_relation(settings.RELATION_API_SERVER) as channel:
                stub = lookup_pb2_grpc.KesselLookupServiceStub(channel)

                # Build request in a way that is compatible with multiple proto versions.
                request_kwargs = {
                    # Mirrors: zed permission lookup-subjects rbac/workspace <id> user_grant rbac/role_binding
                    "resource": common_pb2.ObjectReference(
                        type=common_pb2.ObjectType(namespace=resource_ns, name=resource_name),
                        id=str(resource_id),
                    ),
                    "subject_type": common_pb2.ObjectType(namespace="rbac", name="role_binding"),
                }

                # Newer API versions use a 'permission' field; older ones may use 'relation'.
                # In the current schema, the permission is `user_grant` on rbac/workspace.
                request_fields = lookup_pb2.LookupSubjectsRequest.DESCRIPTOR.fields_by_name
                if "permission" in request_fields:
                    request_kwargs["permission"] = "user_grant"
                elif "relation" in request_fields:
                    request_kwargs["relation"] = "user_grant"

                request = lookup_pb2.LookupSubjectsRequest(**request_kwargs)
                logger.info("LookupSubjects request payload: %s", request)

                responses: Iterable[lookup_pb2.LookupSubjectsResponse] = stub.LookupSubjects(
                    request, metadata=metadata
                )
                for idx, response in enumerate(responses, start=1):
                    payload = json_format.MessageToDict(response)
                    logger.info("LookupSubjects response #%s: %s", idx, payload)
                    subject = payload.get("subject", {})
                    subject_id = subject.get("id") or subject.get("subject", {}).get("id")
                    if subject_id:
                        logger.info("Adding binding subject_id from Relations: %s", subject_id)
                        binding_ids.add(subject_id)

            result = list(binding_ids)
            logger.info(
                "Resolved %d binding UUID(s) via Relations for resource_type=%s, resource_id=%s: %s",
                len(result),
                resource_type,
                resource_id,
                result,
            )
            return result
        except Exception:  # noqa: BLE001
            logger.exception("Failed to lookup inherited bindings through Relations")
            return None

    @staticmethod
    def _parse_resource_type(resource_type: str) -> tuple[str, str]:
        """Split resource_type into namespace and name."""
        if "/" in resource_type:
            namespace, name = resource_type.split("/", 1)
            return namespace, name
        return "rbac", resource_type

    @staticmethod
    def _is_valid_uuid(value: str) -> bool:
        """Return True if the provided value looks like a UUID."""
        try:
            from uuid import UUID

            UUID(value)
            return True
        except Exception:  # noqa: BLE001
            return False
