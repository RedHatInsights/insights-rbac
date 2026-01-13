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
from typing import Literal, Optional

from django.db.models import Max, Prefetch, Q, QuerySet
from django.db.models.aggregates import Count
from management.group.model import Group
from management.principal.model import Principal
from management.role.v2_model import RoleBinding, RoleBindingGroup
from management.workspace.model import Workspace

from api.models import Tenant

SubjectType = Literal["group", "user"]


logger = logging.getLogger(__name__)


class RoleBindingService:
    """Service for role binding queries and operations."""

    def __init__(self, tenant: Tenant):
        """Initialize the service with a tenant."""
        self.tenant = tenant

    def get_role_bindings_by_subject(self, params: dict) -> QuerySet:
        """Get role bindings grouped by subject from a dictionary of parameters.

        Args:
            params: Dictionary of validated query parameters (from input serializer)

        Returns:
            QuerySet of Group or Principal objects annotated with role binding information,
            depending on subject_type parameter.

        Note:
            Ordering is handled by V2CursorPagination.get_ordering() to ensure
            cursor pagination works correctly with the requested order_by parameter.
        """
        subject_type = params.get("subject_type")
        resource_id = params["resource_id"]
        resource_type = params["resource_type"]
        subject_id = params.get("subject_id")

        if subject_type == "user":
            # Build user queryset
            queryset = self._build_user_queryset(resource_id, resource_type)
            queryset = self._apply_user_filters(queryset, subject_id)
        else:
            # Default to group queryset (includes when subject_type is None or "group")
            queryset = self._build_base_queryset(resource_id, resource_type)
            queryset = self._apply_subject_filters(queryset, subject_type, subject_id)

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
            "subject_type": params.get("subject_type"),
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
        """Apply subject type and ID filters to group queryset.

        Args:
            queryset: Base queryset to filter (Group objects)
            subject_type: Optional subject type filter (e.g., 'group')
            subject_id: Optional subject ID filter

        Returns:
            Filtered queryset
        """
        if subject_type:
            # For group queryset, only 'group' subject type is valid
            # 'user' type is handled separately in _build_user_queryset
            if subject_type != "group":
                # Filter out all results for unsupported subject types
                return queryset.none()

        if subject_id:
            queryset = queryset.filter(uuid=subject_id)

        return queryset

    def _build_user_queryset(self, resource_id: str, resource_type: str) -> QuerySet:
        """Build queryset of users (principals) with role bindings for a resource.

        Users are queried through their group memberships to groups that have
        role bindings to the specified resource.

        Args:
            resource_id: The resource identifier
            resource_type: The type of resource

        Returns:
            Annotated QuerySet of Principal objects (users only)
        """
        # Get users who are members of groups that have bindings to the specified resource
        queryset = Principal.objects.filter(
            tenant=self.tenant,
            type=Principal.Types.USER,
            group__role_binding_entries__binding__resource_type=resource_type,
            group__role_binding_entries__binding__resource_id=resource_id,
        ).distinct()

        # Prefetch role bindings for this resource through groups
        binding_queryset = RoleBinding.objects.filter(
            resource_type=resource_type, resource_id=resource_id
        ).select_related("role")

        rolebinding_group_queryset = RoleBindingGroup.objects.filter(
            binding__resource_type=resource_type, binding__resource_id=resource_id
        ).prefetch_related(Prefetch("binding", queryset=binding_queryset))

        # Prefetch groups with their filtered role bindings
        group_queryset = Group.objects.filter(
            role_binding_entries__binding__resource_type=resource_type,
            role_binding_entries__binding__resource_id=resource_id,
        ).prefetch_related(
            Prefetch(
                "role_binding_entries",
                queryset=rolebinding_group_queryset,
                to_attr="filtered_bindings",
            )
        )

        queryset = queryset.prefetch_related(Prefetch("group", queryset=group_queryset, to_attr="filtered_groups"))

        # Annotate with latest modified timestamp from roles
        queryset = queryset.annotate(
            latest_modified=Max(
                "group__role_binding_entries__binding__role__modified",
                filter=Q(
                    group__role_binding_entries__binding__resource_type=resource_type,
                    group__role_binding_entries__binding__resource_id=resource_id,
                ),
            )
        )

        return queryset

    def _apply_user_filters(
        self,
        queryset: QuerySet,
        subject_id: Optional[str],
    ) -> QuerySet:
        """Apply filters to user queryset.

        Args:
            queryset: Base queryset to filter (Principal objects)
            subject_id: Optional subject ID filter (UUID)

        Returns:
            Filtered queryset
        """
        if subject_id:
            queryset = queryset.filter(uuid=subject_id)

        return queryset
