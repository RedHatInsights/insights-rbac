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
"""Serializers for role binding management."""

import re
from dataclasses import dataclass, field
from typing import Optional

from management.models import Group
from management.role.v2_model import RoleBinding, RoleV2
from rest_framework import serializers


class FieldSelectionValidationError(Exception):
    """Exception raised when field selection validation fails."""

    def __init__(self, message: str):
        """Initialize with error message."""
        self.message = message
        super().__init__(self.message)


@dataclass
class FieldSelection:
    """Data class representing parsed field selections from the fields parameter."""

    # Valid fields for each object type
    # subject: id and type are always included; group.* fields available when type="group"
    VALID_SUBJECT_FIELDS = {"id", "type", "group.name", "group.description", "group.user_count"}
    VALID_ROLE_FIELDS = {"id", "name"}
    VALID_RESOURCE_FIELDS = {"id", "name", "type"}
    VALID_ROOT_FIELDS = {"last_modified"}
    VALID_OBJECT_NAMES = {"subject", "role", "resource"}

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
        - subject(id),role(name),resource(name,type)

        Args:
            fields_param: The fields parameter string to parse

        Returns:
            FieldSelection object or None if fields_param is empty

        Raises:
            FieldSelectionValidationError: If invalid fields are found
        """
        if not fields_param:
            return None

        selection = cls()
        invalid_fields = []

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
                    invalid = obj_fields - cls.VALID_SUBJECT_FIELDS
                    if invalid:
                        invalid_fields.extend([f"subject({f})" for f in invalid])
                    selection.subject_fields.update(obj_fields)
                elif obj_name == "role":
                    invalid = obj_fields - cls.VALID_ROLE_FIELDS
                    if invalid:
                        invalid_fields.extend([f"role({f})" for f in invalid])
                    selection.role_fields.update(obj_fields)
                elif obj_name == "resource":
                    invalid = obj_fields - cls.VALID_RESOURCE_FIELDS
                    if invalid:
                        invalid_fields.extend([f"resource({f})" for f in invalid])
                    selection.resource_fields.update(obj_fields)
                else:
                    invalid_fields.append(f"Unknown object type: '{obj_name}'")
            else:
                # Root level field
                if part not in cls.VALID_ROOT_FIELDS:
                    invalid_fields.append(f"Unknown field: '{part}'")
                selection.root_fields.add(part)

        if invalid_fields:
            raise FieldSelectionValidationError(
                f"Invalid field(s): {', '.join(invalid_fields)}. "
                f"Valid subject fields: {sorted(cls.VALID_SUBJECT_FIELDS)}. "
                f"Valid role fields: {sorted(cls.VALID_ROLE_FIELDS)}. "
                f"Valid resource fields: {sorted(cls.VALID_RESOURCE_FIELDS)}. "
                f"Valid root fields: {sorted(cls.VALID_ROOT_FIELDS)}."
            )

        return selection

    @staticmethod
    def _split_fields(fields_str: str) -> list[str]:
        """Split fields string by comma, respecting parentheses."""
        if not fields_str:
            return []

        parts = []
        start = 0
        depth = 0

        for i, char in enumerate(fields_str):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "," and depth == 0:
                parts.append(fields_str[start:i].strip())
                start = i + 1

        parts.append(fields_str[start:].strip())
        return parts


class RoleBindingInputSerializer(serializers.Serializer):
    """Input serializer for role binding query parameters.

    Handles validation of query parameters for both:
    - GET /role-bindings/ (list endpoint)
    - GET /role-bindings/by-subject/ (by-subject endpoint)

    Use context={'endpoint': 'by_subject'} to enforce resource_id/resource_type requirements.
    """

    # List endpoint parameters
    role_id = serializers.UUIDField(required=False, allow_null=True, help_text="Filter by role ID")

    # By-subject endpoint parameters (required when endpoint='by_subject')
    resource_id = serializers.CharField(required=False, allow_blank=True, help_text="Filter by resource ID")
    resource_type = serializers.CharField(required=False, allow_blank=True, help_text="Filter by resource type")
    subject_type = serializers.CharField(required=False, allow_blank=True, help_text="Filter by subject type")
    subject_id = serializers.CharField(required=False, allow_blank=True, help_text="Filter by subject ID (UUID)")
    parent_role_bindings = serializers.BooleanField(
        required=False, allow_null=True, help_text="Include role bindings inherited from parent resources"
    )

    # Common parameters
    fields = serializers.CharField(required=False, allow_blank=True, help_text="Control which fields are included")
    order_by = serializers.CharField(required=False, allow_blank=True, help_text="Sort by specified field(s)")

    def to_internal_value(self, data):
        """Sanitize input data by stripping NUL bytes before field validation."""
        sanitized = {
            key: value.replace("\x00", "") if isinstance(value, str) else value for key, value in data.items()
        }
        return super().to_internal_value(sanitized)

    def validate(self, attrs):
        """Validate fields based on endpoint context."""
        endpoint = self.context.get("endpoint")

        if endpoint == "by_subject":
            if not attrs.get("resource_id"):
                raise serializers.ValidationError(
                    {"resource_id": "resource_id is required to identify the resource for role bindings."}
                )
            if not attrs.get("resource_type"):
                raise serializers.ValidationError(
                    {"resource_type": "resource_type is required to specify the type of resource (e.g., 'workspace')."}
                )

        return attrs

    def validate_role_id(self, value):
        """Return None for empty values."""
        return value or None

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

    def validate_fields(self, value):
        """Parse and validate fields parameter into FieldSelection object."""
        if not value:
            return None
        try:
            return FieldSelection.parse(value)
        except FieldSelectionValidationError as e:
            raise serializers.ValidationError(e.message)

    def validate_order_by(self, value):
        """Return None for empty values."""
        return value or None


class RoleBindingOutputSerializer(serializers.Serializer):
    """Serializer for role bindings.

    Handles both:
    - RoleBinding objects (list endpoint): returns {role, subject, resource}
    - Group objects (by-subject endpoint): returns {roles, subject, resource, last_modified}

    Supports dynamic field selection through the 'field_selection' context parameter.
    Fields are accessed directly on the model using dot notation from the query parameter.

    Field selection syntax:
    - subject(group.name, group.description) - accesses obj.name, obj.description
    - role(name, description) - accesses role.name, role.description
    - resource(name, type) - accesses resource name and type from context
    - last_modified - include root-level field (by-subject only)
    """

    last_modified = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def _get_field_selection(self):
        """Get field selection from context."""
        return self.context.get("field_selection")

    def _is_role_binding(self, instance):
        """Check if instance is a RoleBinding object."""
        return isinstance(instance, RoleBinding)

    def to_representation(self, instance):
        """Override to support field selection and different object types.

        For RoleBinding objects (list endpoint):
            Returns {role, subject, resource}
        For Group objects (by-subject endpoint):
            Returns {roles, subject, resource} plus last_modified if requested
        """
        ret = super().to_representation(instance)

        field_selection = self._get_field_selection()

        if self._is_role_binding(instance):
            # List endpoint: RoleBinding objects
            filtered = {
                "role": ret.get("role"),
                "subject": ret.get("subject"),
                "resource": ret.get("resource"),
            }
        else:
            # By-subject endpoint: Group objects
            filtered = {
                "subject": ret.get("subject"),
                "roles": ret.get("roles"),
                "resource": ret.get("resource"),
            }

            # Include last_modified only if explicitly requested
            if field_selection and "last_modified" in field_selection.root_fields:
                filtered["last_modified"] = ret.get("last_modified")

        return filtered

    def get_last_modified(self, obj):
        """Extract last modified timestamp."""
        if isinstance(obj, dict):
            return obj.get("modified") or obj.get("latest_modified")
        return getattr(obj, "latest_modified", None)

    def _extract_group_details(self, group: Group, field_selection: FieldSelection) -> dict:
        """Extract group.* fields from a Group object based on field selection.

        Args:
            group: The Group object to extract fields from
            field_selection: The field selection specifying which fields to include

        Returns:
            Dictionary with extracted group details, or empty dict if none requested
        """
        # Extract field names from "group.X" paths
        fields_to_include = set()
        for field_path in field_selection.subject_fields:
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
        subject = {"type": "group"}

        # Check if id is explicitly requested
        if "id" in field_selection.subject_fields:
            subject["id"] = group.uuid

        # Extract group.* fields
        group_details = self._extract_group_details(group, field_selection)
        if group_details:
            subject["group"] = group_details

        return subject

    def get_subject(self, obj):
        """Extract subject information.

        For RoleBinding: gets subject from bound groups.
        For Group: gets subject from the Group object itself.

        Default (no fields param): Returns only id and type.
        With fields param: Only type is always included. Other fields
        (including id) are only included if explicitly requested.
        """
        field_selection = self._get_field_selection()

        # Handle RoleBinding objects
        if self._is_role_binding(obj):
            # Get the first group from the binding
            group = obj.bound_groups().first()
            if not group:
                return {"type": "group"}

            return self._build_subject_data(group, field_selection)

        # Handle Group objects
        if not isinstance(obj, Group):
            return None

        return self._build_subject_data(obj, field_selection)

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
            for field_name in field_selection.role_fields:
                if field_name != "id":
                    value = getattr(role, field_name, None)
                    if value is not None:
                        role_data[field_name] = value

        return role_data

    def get_role(self, obj):
        """Extract role information from a RoleBinding (list endpoint only).

        Default (no fields param): Returns only role id.
        With fields param: id is always included, plus explicitly requested fields.
        """
        if not self._is_role_binding(obj) or not obj.role:
            return None

        field_selection = self._get_field_selection()
        return self._build_role_data(obj.role, field_selection)

    def get_roles(self, obj):
        """Extract roles from the prefetched role bindings (by-subject endpoint only).

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

    def get_resource(self, obj):
        """Extract resource information.

        For RoleBinding: gets resource from the object itself.
        For Group: gets resource from the request context.

        Default (no fields param): Returns only resource id.
        With fields param: id is always included, plus explicitly requested fields.
        """
        if isinstance(obj, dict):
            return obj.get("resource", {})

        field_selection = self._get_field_selection()

        # Handle RoleBinding objects
        if self._is_role_binding(obj):
            resource_data = {"id": obj.resource_id}

            if field_selection is not None:
                if "type" in field_selection.resource_fields:
                    resource_data["type"] = obj.resource_type

            return resource_data

        # Handle Group objects - get resource from context
        resource_id = self.context.get("resource_id")
        resource_name = self.context.get("resource_name")
        resource_type = self.context.get("resource_type")

        if not any([resource_id, resource_name, resource_type]):
            return None

        # id is always included
        resource_data = {"id": resource_id}

        if field_selection is not None:
            # Add explicitly requested fields
            field_values = {
                "name": resource_name,
                "type": resource_type,
            }

            for field_name in field_selection.resource_fields:
                if field_name != "id":
                    value = field_values.get(field_name)
                    if value is not None:
                        resource_data[field_name] = value

        return resource_data


# Backward compatibility alias
RoleBindingByGroupSerializer = RoleBindingOutputSerializer
