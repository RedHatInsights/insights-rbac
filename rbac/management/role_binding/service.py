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
import re
from dataclasses import dataclass, field
from typing import Optional

from django.db.models import Max, Prefetch, Q, QuerySet
from django.db.models.aggregates import Count
from management.group.model import Group
from management.principal.model import Principal
from management.role.v2_model import RoleBinding, RoleBindingGroup
from management.workspace.model import Workspace
from rest_framework import serializers

from api.models import Tenant


logger = logging.getLogger(__name__)


@dataclass
class RoleBindingQueryParams:
    """Data class to hold validated query parameters for role binding queries."""

    resource_id: str
    resource_type: str
    subject_type: Optional[str] = None
    subject_id: Optional[str] = None
    fields: Optional[str] = None
    order_by: Optional[str] = None

    def __post_init__(self):
        """Validate required fields after initialization."""
        if not self.resource_id:
            raise serializers.ValidationError({"resource_id": "This query parameter is required."})
        if not self.resource_type:
            raise serializers.ValidationError({"resource_type": "This query parameter is required."})


@dataclass
class FieldSelection:
    """Data class representing parsed field selections from the fields parameter."""

    subject_fields: set = field(default_factory=set)
    role_fields: set = field(default_factory=set)
    resource_fields: set = field(default_factory=set)
    root_fields: set = field(default_factory=set)

    @classmethod
    def parse(cls, fields_param: Optional[str]) -> Optional["FieldSelection"]:
        """Parse fields parameter string into FieldSelection.

        Syntax:
        - object(field1,field2) - nested fields for an object
        - field - root level field
        - Multiple specs separated by commas outside parentheses

        Examples:
        - subject(group.name,group.user_count),role(name)
        - last_modified
        - subject(user.username),role(name),resource(name,type)
        """
        if not fields_param:
            return None

        selection = cls()

        # Pattern to match object(fields) or plain field
        # Split by comma but not inside parentheses
        parts = cls._split_fields(fields_param)

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Check if it's object(fields) pattern
            match = re.match(r"(\w+)\(([^)]+)\)", part)
            if match:
                obj_name = match.group(1)
                obj_fields = {f.strip() for f in match.group(2).split(",")}

                if obj_name == "subject":
                    selection.subject_fields.update(obj_fields)
                elif obj_name == "role":
                    selection.role_fields.update(obj_fields)
                elif obj_name == "resource":
                    selection.resource_fields.update(obj_fields)
            else:
                # Root level field
                selection.root_fields.add(part)

        return selection

    @staticmethod
    def _split_fields(fields_str: str) -> list:
        """Split fields string by comma, respecting parentheses."""
        parts = []
        current = []
        depth = 0

        for char in fields_str:
            if char == "(":
                depth += 1
                current.append(char)
            elif char == ")":
                depth -= 1
                current.append(char)
            elif char == "," and depth == 0:
                parts.append("".join(current))
                current = []
            else:
                current.append(char)

        if current:
            parts.append("".join(current))

        return parts


class RoleBindingService:
    """Service for role binding queries and operations."""

    def __init__(self, tenant: Tenant):
        """Initialize the service with a tenant."""
        self.tenant = tenant

    def parse_query_params(self, query_params: dict) -> RoleBindingQueryParams:
        """Parse and validate query parameters from request.

        Args:
            query_params: Dict-like object with query parameters

        Returns:
            RoleBindingQueryParams with validated parameters

        Raises:
            serializers.ValidationError: If required parameters are missing
        """
        # Sanitize inputs (remove null bytes)
        resource_id = query_params.get("resource_id", "").replace("\x00", "")
        resource_type = query_params.get("resource_type", "").replace("\x00", "")
        subject_type = query_params.get("subject_type", "").replace("\x00", "") or None
        subject_id = query_params.get("subject_id", "").replace("\x00", "") or None
        fields = query_params.get("fields", "").replace("\x00", "") or None
        order_by = query_params.get("order_by", "").replace("\x00", "") or None

        return RoleBindingQueryParams(
            resource_id=resource_id,
            resource_type=resource_type,
            subject_type=subject_type,
            subject_id=subject_id,
            fields=fields,
            order_by=order_by,
        )

    def get_role_bindings_by_subject(self, params: RoleBindingQueryParams) -> QuerySet:
        """Get role bindings grouped by subject (group).

        Args:
            params: Validated query parameters

        Returns:
            QuerySet of Group objects annotated with role binding information
        """
        # Build base queryset for the specified resource
        queryset = self._build_base_queryset(params.resource_id, params.resource_type)

        # Apply subject filters
        queryset = self._apply_subject_filters(queryset, params.subject_type, params.subject_id)

        # Apply ordering
        queryset = self._apply_ordering(queryset, params.order_by)

        return queryset

    def get_field_selection(self, params: RoleBindingQueryParams) -> Optional[FieldSelection]:
        """Parse and return field selection from parameters.

        Args:
            params: Query parameters containing fields string

        Returns:
            FieldSelection object or None if no fields specified
        """
        return FieldSelection.parse(params.fields)

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

    def build_context(self, params: RoleBindingQueryParams) -> dict:
        """Build serializer context with resource information.

        Args:
            params: Query parameters

        Returns:
            Context dict for serializer
        """
        return {
            "resource_id": params.resource_id,
            "resource_type": params.resource_type,
            "resource_name": self.get_resource_name(params.resource_id, params.resource_type),
            "field_selection": self.get_field_selection(params),
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

    def _apply_ordering(self, queryset: QuerySet, order_by: Optional[str]) -> QuerySet:
        """Apply ordering to queryset.

        Args:
            queryset: QuerySet to order
            order_by: Comma-separated order fields (prefix '-' for descending)

        Returns:
            Ordered queryset
        """
        default_ordering = "-modified"

        if not order_by:
            return queryset.order_by(default_ordering)

        try:
            order_fields = [f.strip() for f in order_by.split(",") if f.strip()]
            ordered = queryset.order_by(*order_fields)
            str(ordered.query)  # Validate field names
            return ordered
        except Exception:
            return queryset.order_by(default_ordering)
