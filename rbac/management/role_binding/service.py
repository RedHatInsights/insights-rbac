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
"""Service layer for role binding management."""
import logging
from typing import Iterable, Optional, Sequence

from django.conf import settings
from django.db.models import Max, Prefetch, Q, QuerySet
from django.db.models.aggregates import Count
from google.protobuf import json_format
from internal.jwt_utils import JWTManager, JWTProvider
from kessel.relations.v1beta1 import common_pb2, lookup_pb2, lookup_pb2_grpc
from management.cache import JWTCache
from management.group.model import Group
from management.principal.model import Principal
from management.role.v2_model import RoleBinding, RoleBindingGroup
from management.utils import create_client_channel_relation
from management.workspace.model import Workspace

from api.models import Tenant


logger = logging.getLogger(__name__)

# Lazily instantiate the JWT helpers once so all requests reuse the same objects.
_jwt_cache = JWTCache()
_jwt_provider = JWTProvider()
_jwt_manager = JWTManager(_jwt_provider, _jwt_cache)


class RoleBindingService:
    """Service for role binding queries and operations."""

    def __init__(self, tenant: Tenant):
        """Initialize the service with a tenant."""
        self.tenant = tenant

    def get_role_bindings_by_subject(self, params: dict) -> QuerySet:
        """Get role bindings grouped by subject (group) from a dictionary of parameters.

        Args:
            params: Dictionary of validated query parameters (from input serializer)

        Returns:
            QuerySet of Group objects annotated with role binding information

        Note:
            Ordering is handled by V2CursorPagination.get_ordering() to ensure
            cursor pagination works correctly with the requested order_by parameter.
        """
        resource_id = params["resource_id"]
        resource_type = params["resource_type"]
        include_inherited = params.get("parent_role_bindings", False)

        # If parent_role_bindings is requested, lookup inherited binding UUIDs via Relations API
        binding_uuids = None
        if include_inherited:
            binding_uuids = self._lookup_binding_uuids_via_relations(resource_type, resource_id)

        # Build base queryset for the specified resource
        queryset = self._build_base_queryset(resource_id, resource_type, binding_uuids)

        # Apply subject filters
        queryset = self._apply_subject_filters(queryset, params.get("subject_type"), params.get("subject_id"))

        return queryset

    def get_resource_name(self, resource_id: str, resource_type: str) -> Optional[str]:
        """Get the name of a resource by ID and type.

        Args:
            resource_id: The resource identifier
            resource_type: The type of resource (e.g., 'workspace')

        Returns:
            Resource name or None if not found
        """
        if resource_type == "workspace":
            try:
                workspace = Workspace.objects.get(id=resource_id, tenant=self.tenant)
                return workspace.name
            except Workspace.DoesNotExist:
                logger.warning(f"Workspace {resource_id} not found for tenant {self.tenant}")
                return None
        return None

    def build_context(self, params: dict) -> dict:
        """Build serializer context with resource information from a dictionary.

        Args:
            params: Dictionary of validated query parameters (from input serializer).
                    The 'fields' key contains an already-parsed FieldSelection object or None.

        Returns:
            Context dict for output serializer
        """
        resource_id = params["resource_id"]
        resource_type = params["resource_type"]

        return {
            "resource_id": resource_id,
            "resource_type": resource_type,
            "resource_name": self.get_resource_name(resource_id, resource_type),
            "field_selection": params.get("fields"),
        }

    def _build_base_queryset(
        self, resource_id: str, resource_type: str, binding_uuids: Optional[Sequence[str]] = None
    ) -> QuerySet:
        """Build base queryset of groups with role bindings for a resource.

        Args:
            resource_id: The resource identifier
            resource_type: The type of resource
            binding_uuids: Optional list of binding UUIDs to include (for inherited bindings)

        Returns:
            Annotated QuerySet of Group objects
        """
        # Build filter for bindings - either by resource or by explicit UUIDs
        if binding_uuids is not None:
            # Include both direct bindings and inherited bindings by UUID
            binding_filter = Q(
                role_binding_entries__binding__resource_type=resource_type,
                role_binding_entries__binding__resource_id=resource_id,
            ) | Q(role_binding_entries__binding__uuid__in=binding_uuids)
        else:
            # Only direct bindings for the specified resource
            binding_filter = Q(
                role_binding_entries__binding__resource_type=resource_type,
                role_binding_entries__binding__resource_id=resource_id,
            )

        # Start with groups that have bindings matching our filter
        queryset = Group.objects.filter(tenant=self.tenant).filter(binding_filter).distinct()

        # Annotate with principal count
        queryset = queryset.annotate(
            principalCount=Count("principals", filter=Q(principals__type=Principal.Types.USER), distinct=True)
        )

        # Prefetch role bindings for this resource with their roles
        binding_queryset = RoleBinding.objects.filter(
            resource_type=resource_type, resource_id=resource_id
        ).select_related("role")

        # Prefetch the join table entries with the filtered bindings
        rolebinding_group_queryset = RoleBindingGroup.objects.filter(
            binding__resource_type=resource_type, binding__resource_id=resource_id
        ).prefetch_related(Prefetch("binding", queryset=binding_queryset))

        queryset = queryset.prefetch_related(
            Prefetch(
                "role_binding_entries",
                queryset=rolebinding_group_queryset,
                to_attr="filtered_bindings",
            )
        )

        # Annotate with latest modified timestamp from roles
        queryset = queryset.annotate(
            latest_modified=Max(
                "role_binding_entries__binding__role__modified",
                filter=Q(
                    role_binding_entries__binding__resource_type=resource_type,
                    role_binding_entries__binding__resource_id=resource_id,
                ),
            )
        )

        return queryset

    def _apply_subject_filters(
        self,
        queryset: QuerySet,
        subject_type: Optional[str],
        subject_id: Optional[str],
    ) -> QuerySet:
        """Apply subject type and ID filters to queryset.

        Args:
            queryset: Base queryset to filter
            subject_type: Optional subject type filter (e.g., 'group', 'user')
            subject_id: Optional subject ID filter

        Returns:
            Filtered queryset
        """
        if subject_type:
            # Currently only 'group' subject type is supported
            if subject_type != "group":
                # Filter out all results for unsupported subject types
                return queryset.none()

        if subject_id:
            queryset = queryset.filter(uuid=subject_id)

        return queryset

    def _parse_resource_type(self, resource_type: str) -> tuple[str, str]:
        """Parse resource type into namespace and name.

        Args:
            resource_type: Resource type string, optionally prefixed with namespace
                          (e.g., "workspace" or "rbac/workspace")

        Returns:
            Tuple of (namespace, name)
        """
        if "/" in resource_type:
            parts = resource_type.split("/", 1)
            return (parts[0], parts[1])
        return ("rbac", resource_type)  # Default namespace

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
