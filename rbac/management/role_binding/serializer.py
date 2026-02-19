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
"""Serializers for role binding management.

This module contains:
- Input serializers: For validating query parameters
- Output serializers: For serializing response data
"""

from typing import Optional

from management.models import Group
from management.role.v2_model import RoleBinding, RoleV2
from management.utils import FieldSelection, FieldSelectionValidationError
from rest_framework import serializers


class RoleBindingFieldSelection(FieldSelection):
    """Field selection for role-bindings endpoint."""

    VALID_ROOT_FIELDS = {"last_modified"}
    VALID_NESTED_FIELDS = {
        "subject": {"id", "type", "group.name", "group.description", "group.user_count"},
        "role": {"id", "name"},
        "resource": {"id", "name", "type"},
    }


class RoleBindingInputSerializerMixin:
    """Shared validation methods for role binding input serializers."""

    def to_internal_value(self, data):
        """Sanitize input data by stripping NUL bytes before field validation."""
        sanitized = {
            key: value.replace("\x00", "") if isinstance(value, str) else value for key, value in data.items()
        }
        return super().to_internal_value(sanitized)

    def validate_fields(self, value):
        """Parse and validate fields parameter into RoleBindingFieldSelection object."""
        if not value:
            return None
        try:
            return RoleBindingFieldSelection.parse(value)
        except FieldSelectionValidationError as e:
            raise serializers.ValidationError(e.message)

    def validate_order_by(self, value):
        """Return None for empty values."""
        return value or None


class RoleBindingListInputSerializer(RoleBindingInputSerializerMixin, serializers.Serializer):
    """Input serializer for role binding list endpoint query parameters.

    GET /role-bindings/
    """

    role_id = serializers.UUIDField(required=False, allow_null=True, help_text="Filter by role ID")
    fields = serializers.CharField(required=False, allow_blank=True, help_text="Control which fields are included")
    order_by = serializers.CharField(required=False, allow_blank=True, help_text="Sort by specified field(s)")

    def validate_role_id(self, value):
        """Return None for empty values."""
        return value or None


class RoleBindingBySubjectInputSerializer(RoleBindingInputSerializerMixin, serializers.Serializer):
    """Input serializer for role binding by-subject endpoint query parameters.

    GET /role-bindings/by-subject/
    """

    resource_id = serializers.CharField(required=True, help_text="Filter by resource ID")
    resource_type = serializers.CharField(required=True, help_text="Filter by resource type")
    subject_type = serializers.CharField(required=False, allow_blank=True, help_text="Filter by subject type")
    subject_id = serializers.CharField(required=False, allow_blank=True, help_text="Filter by subject ID (UUID)")
    parent_role_bindings = serializers.BooleanField(
        required=False, allow_null=True, help_text="Include role bindings inherited from parent resources"
    )
    fields = serializers.CharField(required=False, allow_blank=True, help_text="Control which fields are included")
    order_by = serializers.CharField(required=False, allow_blank=True, help_text="Sort by specified field(s)")

    def validate_resource_id(self, value):
        """Return None for empty values."""
        return value or None

    def validate_resource_type(self, value):
        """Return None for empty values."""
        return value or None

    def validate_subject_type(self, value):
        """Return None for empty values."""
        return value or None

    def validate_parent_role_bindings(self, value):
        """Return None for empty values."""
        return value or None

    def validate_subject_id(self, value):
        """Return None for empty values."""
        return value or None


class RoleBindingSerializerMixin:
    """Shared serializer methods for role binding output serializers.

    Provides common functionality for field selection parsing and data building.
    """

    context: dict

    def _get_field_selection(self) -> Optional[FieldSelection]:
        """Get field selection from context."""
        return self.context.get("field_selection")

    def _extract_group_details(self, group: Group, field_selection: FieldSelection) -> dict:
        """Extract group.* fields from a Group object based on field selection.

        Args:
            group: The Group object to extract fields from
            field_selection: The field selection specifying which fields to include

        Returns:
            Dictionary with extracted group details, or empty dict if none requested
        """
        subject_fields = field_selection.get_nested("subject")
        # Extract field names from "group.X" paths
        fields_to_include = set()
        for field_path in subject_fields:
            if field_path.startswith("group."):
                fields_to_include.add(field_path[6:])  # Remove "group." prefix

        if not fields_to_include:
            return {}

        group_details = {}
        for field_name in fields_to_include:
            # Handle special case for user_count -> principalCount
            if field_name == "user_count":
                group_details[field_name] = getattr(group, "principalCount", 0)
            else:
                value = getattr(group, field_name, None)
                if value is not None:
                    group_details[field_name] = value

        return group_details

    def _build_subject_data(self, group: Group, field_selection: Optional[FieldSelection]) -> dict:
        """Build subject data dictionary from a Group object.

        Args:
            group: The Group object to build subject data from
            field_selection: Optional field selection to determine which fields to include

        Returns:
            Dictionary with subject data (always includes 'type')
        """
        # Default behavior: only basic fields
        if field_selection is None:
            return {
                "id": group.uuid,
                "type": "group",
            }

        # With fields param: type is always included
        subject: dict = {"type": "group"}

        # Check if id is explicitly requested
        if "id" in field_selection.subject_fields:
            subject["id"] = group.uuid

        # Extract group.* fields
        group_details = self._extract_group_details(group, field_selection)
        if group_details:
            subject["group"] = group_details

        return subject

    def _build_role_data(self, role: RoleV2, field_selection: Optional[FieldSelection]) -> dict:
        """Build role data dictionary from a role object.

        Args:
            role: The role to build data for
            field_selection: Optional field selection to determine which fields to include

        Returns:
            Dictionary with role data (always includes 'id')
        """
        role_data = {"id": role.uuid}

        if field_selection is not None:
            # Add explicitly requested fields
            for field_name in field_selection.get_nested("role"):
                if field_name != "id":
                    value = getattr(role, field_name, None)
                    if value is not None:
                        role_data[field_name] = value

        return role_data


class RoleBindingListOutputSerializer(RoleBindingSerializerMixin, serializers.Serializer):
    """Output serializer for the role binding list endpoint.

    Handles RoleBinding objects and returns {role, subject, resource}.

    Supports dynamic field selection through the 'field_selection' context parameter.
    Fields are accessed directly on the model using dot notation from the query parameter.

    Field selection syntax:
    - subject(group.name, group.description) - accesses obj.name, obj.description
    - role(name) - accesses role.name
    - resource(type) - accesses resource type from the binding
    """

    subject = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def get_subject(self, obj: RoleBinding):
        """Extract subject information from the RoleBinding.

        Gets subject from prefetched group_entries (populated by service layer).

        Default (no fields param): Returns only id and type.
        With fields param: Only type is always included. Other fields
        (including id) are only included if explicitly requested.
        """
        field_selection = self._get_field_selection()

        # Get the first group from prefetched group_entries
        group_entries = getattr(obj, "group_entries", None)
        if group_entries is None:
            return {"type": "group"}

        first_entry = group_entries.all()[:1]
        if not first_entry:
            return {"type": "group"}

        group = first_entry[0].group
        return self._build_subject_data(group, field_selection)

    def get_role(self, obj: RoleBinding):
        """Extract role information from the RoleBinding.

        Default (no fields param): Returns only role id.
        With fields param: id is always included, plus explicitly requested fields.
        """
        if not obj.role:
            return None

        field_selection = self._get_field_selection()
        return self._build_role_data(obj.role, field_selection)

    def get_resource(self, obj: RoleBinding):
        """Extract resource information from the RoleBinding.

        Default (no fields param): Returns only resource id.
        With fields param: id is always included, plus explicitly requested fields.
        """
        field_selection = self._get_field_selection()

        resource_data = {"id": obj.resource_id}

        if field_selection is not None:
            if "type" in field_selection.resource_fields:
                resource_data["type"] = obj.resource_type

        return resource_data


class RoleBindingBySubjectOutputSerializer(RoleBindingSerializerMixin, serializers.Serializer):
    """Output serializer for the role binding by-subject endpoint.

    Handles Group objects and returns {subject, roles, resource, last_modified}.

    Supports dynamic field selection through the 'field_selection' context parameter.
    Fields are accessed directly on the model using dot notation from the query parameter.

    Field selection syntax:
    - subject(group.name, group.description, group.user_count) - accesses group fields
    - role(name) - accesses role.name for each role
    - resource(name, type) - accesses resource name and type from context
    - last_modified - include root-level field
    """

    last_modified = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def to_representation(self, instance):
        """Override to conditionally include last_modified based on field selection."""
        ret = super().to_representation(instance)

        field_selection = self._get_field_selection()

        filtered = {
            "subject": ret.get("subject"),
            "roles": ret.get("roles"),
            "resource": ret.get("resource"),
        }

        # Include last_modified only if explicitly requested
        if field_selection and "last_modified" in field_selection.root_fields:
            filtered["last_modified"] = ret.get("last_modified")

        return filtered

    def get_last_modified(self, obj: Group):
        """Extract last modified timestamp."""
        if isinstance(obj, dict):
            return obj.get("modified") or obj.get("latest_modified")
        return getattr(obj, "latest_modified", None)

    def get_subject(self, obj: Group):
        """Extract subject information from the Group object.

        Default (no fields param): Returns only id and type.
        With fields param: Only type is always included. Other fields
        (including id) are only included if explicitly requested.
        """
        if not isinstance(obj, Group):
            return None

        field_selection = self._get_field_selection()
        return self._build_subject_data(obj, field_selection)

    def get_roles(self, obj: Group):
        """Extract roles from the prefetched role bindings.

        Default (no fields param): Returns only role id.
        With fields param: id is always included, plus explicitly requested fields.

        For platform roles, returns their children instead of the platform role itself.
        """
        if isinstance(obj, dict):
            return obj.get("roles", [])

        if not isinstance(obj, Group):
            return None

        if not hasattr(obj, "filtered_bindings"):
            return []

        field_selection = self._get_field_selection()

        # Normalize roles: collect all roles to process (children for platform, role itself for non-platform)
        roles_to_process = []
        seen_role_ids = set()

        for binding_group in obj.filtered_bindings:
            if not hasattr(binding_group, "binding") or not binding_group.binding:
                continue

            role = binding_group.binding.role
            if not role:
                continue

            # For platform roles, use children; for others, use the role itself
            # Note: role.children.all() uses prefetched data from service layer's
            # prefetch_related("role__children"), so this should not cause N+1 queries
            if role.type == RoleV2.Types.PLATFORM:
                roles_to_process.extend(role.children.all())
            else:
                roles_to_process.append(role)

        # Process all normalized roles in a single loop
        roles = []
        for role in roles_to_process:
            if role.uuid in seen_role_ids:
                continue

            role_data = self._build_role_data(role, field_selection)
            roles.append(role_data)
            seen_role_ids.add(role.uuid)

        return roles

    def get_resource(self, obj: Group):
        """Extract resource information from the request context.

        Default (no fields param): Returns only resource id.
        With fields param: id is always included, plus explicitly requested fields.
        """
        if isinstance(obj, dict):
            return obj.get("resource", {})

        resource_id = self.context.get("resource_id")
        resource_name = self.context.get("resource_name")
        resource_type = self.context.get("resource_type")

        if not any([resource_id, resource_name, resource_type]):
            return None

        field_selection = self._get_field_selection()

        # id is always included
        resource_data = {"id": resource_id}

        if field_selection is not None:
            # Add explicitly requested fields
            field_values = {
                "name": resource_name,
                "type": resource_type,
            }

            for field_name in field_selection.get_nested("resource"):
                if field_name != "id":
                    value = field_values.get(field_name)
                    if value is not None:
                        resource_data[field_name] = value

        return resource_data
