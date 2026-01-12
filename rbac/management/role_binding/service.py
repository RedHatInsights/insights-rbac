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
from typing import Optional

from django.db.models import Max, Prefetch, Q, QuerySet
from django.db.models.aggregates import Count
from internal.utils import read_tuples_from_kessel
from management.group.model import Group
from management.permission.scope_service import Scope
from management.principal.model import Principal
from management.role.v2_model import RoleBinding, RoleBindingGroup, RoleV2
from management.tenant_mapping.model import DefaultAccessType, TenantMapping
from management.workspace.model import Workspace

from api.models import Tenant


logger = logging.getLogger(__name__)


class RoleBindingService:
    """Service for role binding queries and operations."""

    def __init__(self, tenant: Tenant):
        """Initialize the service with a tenant."""
        self.tenant = tenant

    def get_role_bindings_by_subject(self, params: dict) -> QuerySet:
        """Get role bindings grouped by subject (group) from a dictionary of parameters.

        Includes both database role bindings and virtual role bindings from Relations API.

        Args:
            params: Dictionary of validated query parameters (from input serializer)

        Returns:
            QuerySet of Group objects annotated with role binding information

        Note:
            Ordering is handled by V2CursorPagination.get_ordering() to ensure
            cursor pagination works correctly with the requested order_by parameter.
        """
        # Build base queryset for the specified resource
        queryset = self._build_base_queryset(params["resource_id"], params["resource_type"])

        # Ensure groups with virtual bindings are included in queryset
        queryset = self._add_virtual_bindings(queryset, params["resource_id"], params["resource_type"])

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

    def _build_base_queryset(self, resource_id: str, resource_type: str) -> QuerySet:
        """Build base queryset of groups with role bindings for a resource.

        Args:
            resource_id: The resource identifier
            resource_type: The type of resource

        Returns:
            Annotated QuerySet of Group objects
        """
        # Start with groups that have bindings to the specified resource
        queryset = Group.objects.filter(
            tenant=self.tenant,
            role_binding_entries__binding__resource_type=resource_type,
            role_binding_entries__binding__resource_id=resource_id,
        ).distinct()

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

    def get_virtual_bindings(self, resource_id: str, resource_type: str) -> dict:
        """Get virtual role bindings from Relations API.

        Virtual bindings are default role bindings that exist only in Relations API,
        not in the database. These occur when a tenant doesn't have a custom default group.

        Args:
            resource_id: The resource identifier
            resource_type: The type of resource

        Returns:
            Dict mapping group_uuid to list of (binding_id, role) tuples
        """
        virtual_groups_map = {}

        try:
            tenant_mapping = self.tenant.tenant_mapping
        except TenantMapping.DoesNotExist:
            # Tenant not bootstrapped, no virtual bindings
            return virtual_groups_map

        # Check if tenant has custom default group
        has_custom_default_group = Group.platform_default_set().filter(tenant=self.tenant).exists()

        if has_custom_default_group:
            # Virtual bindings don't exist if custom default group exists
            return virtual_groups_map

        # Determine scope for the resource
        scope = None
        if resource_type == "workspace":
            try:
                workspace = Workspace.objects.get(id=resource_id, tenant=self.tenant)
                if workspace.type == Workspace.Types.DEFAULT:
                    scope = Scope.DEFAULT
                elif workspace.type == Workspace.Types.ROOT:
                    scope = Scope.ROOT
                # Standard workspaces don't have virtual bindings
            except Workspace.DoesNotExist:
                return virtual_groups_map
        elif resource_type == "tenant":
            scope = Scope.TENANT
        else:
            # Unknown resource type, no virtual bindings
            return virtual_groups_map

        if scope is None:
            return virtual_groups_map

        # Get default role binding UUIDs for this scope from TenantMapping
        # Track access_type along with binding_uuid so we can get group UUID directly
        binding_info = []
        for access_type in DefaultAccessType:
            try:
                binding_uuid = str(tenant_mapping.default_role_binding_uuid_for(access_type, scope))
                group_uuid = str(tenant_mapping.group_uuid_for(access_type))
                binding_info.append((binding_uuid, group_uuid, access_type))
            except Exception:
                continue

        if not binding_info:
            return virtual_groups_map

        # Query Relations API for each builtin binding UUID to avoid reading all bindings
        virtual_bindings = []
        for binding_uuid, group_uuid, access_type in binding_info:
            try:
                binding_tuples = read_tuples_from_kessel(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    relation="binding",
                    subject_type="role_binding",
                    subject_id=binding_uuid,
                )
                # If tuple exists, this binding is attached to the resource
                if binding_tuples:
                    virtual_bindings.append((binding_uuid, group_uuid))
            except Exception as e:
                logger.warning(f"Failed to read virtual binding {binding_uuid} from Relations API: {e}")
                continue

        if not virtual_bindings:
            return virtual_groups_map

        # For each virtual binding, get its role (group is already known from TenantMapping)
        for binding_id, group_id in virtual_bindings:
            try:
                # Get role from binding
                # TODO: can cache this to improve performance
                role_tuples = read_tuples_from_kessel(
                    resource_type="role_binding",
                    resource_id=binding_id,
                    relation="role",
                    subject_type="role",
                    subject_id="",
                )
                if not role_tuples:
                    continue

                role_id = role_tuples[0].get("tuple", {}).get("subject", {}).get("subject", {}).get("id")
                if not role_id:
                    continue

                # Get role object
                try:
                    role = RoleV2.objects.get(uuid=role_id)
                except RoleV2.DoesNotExist:
                    logger.warning(f"Virtual binding references non-existent role: {role_id}")
                    continue

                # Add to map
                if group_id not in virtual_groups_map:
                    virtual_groups_map[group_id] = []
                virtual_groups_map[group_id].append((binding_id, role))

            except Exception as e:
                logger.warning(f"Error processing virtual binding {binding_id}: {e}")
                continue

        return virtual_groups_map

    def _add_virtual_bindings(self, queryset: QuerySet, resource_id: str, resource_type: str) -> QuerySet:
        """Ensure groups with virtual bindings are included in queryset.

        Args:
            queryset: Base queryset from database
            resource_id: The resource identifier
            resource_type: The type of resource

        Returns:
            QuerySet that includes groups with virtual bindings
        """
        virtual_groups_map = self.get_virtual_bindings(resource_id, resource_type)

        if not virtual_groups_map:
            return queryset

        # Get group UUIDs that have virtual bindings but aren't in queryset
        group_uuids_in_queryset = set(queryset.values_list("uuid", flat=True))
        virtual_group_uuids = set(virtual_groups_map.keys())
        missing_group_uuids = virtual_group_uuids - group_uuids_in_queryset

        if missing_group_uuids:
            # Instead of union (which doesn't work with prefetch_related),
            # filter the base queryset to include missing groups using Q objects

            # Build a filter for missing groups
            missing_filter = Q(uuid__in=list(missing_group_uuids))

            # Rebuild queryset with expanded filter
            # Start fresh with groups that have bindings OR are in virtual bindings
            queryset = (
                Group.objects.filter(
                    tenant=self.tenant,
                )
                .filter(
                    Q(
                        role_binding_entries__binding__resource_type=resource_type,
                        role_binding_entries__binding__resource_id=resource_id,
                    )
                    | missing_filter
                )
                .distinct()
            )

            # Re-apply annotations
            queryset = queryset.annotate(
                principalCount=Count("principals", filter=Q(principals__type=Principal.Types.USER), distinct=True)
            )

            # Re-apply prefetch for bindings
            binding_queryset = RoleBinding.objects.filter(
                resource_type=resource_type, resource_id=resource_id
            ).select_related("role")

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

            # Re-apply latest_modified annotation
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
