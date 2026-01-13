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
from management.principal.model import Principal
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
    # subject: id and type are always included
    # group.* fields available when type="group"
    # user.* fields available when type="user"
    VALID_SUBJECT_FIELDS = {"id", "type", "group.name", "group.description", "group.user_count", "user.username"}
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

    Handles validation of query parameters for the role binding API.
    """

    resource_id = serializers.CharField(required=True, help_text="Filter by resource ID")
    resource_type = serializers.CharField(required=True, help_text="Filter by resource type")
    subject_type = serializers.CharField(required=False, allow_blank=True, help_text="Filter by subject type")
    subject_id = serializers.CharField(required=False, allow_blank=True, help_text="Filter by subject ID (UUID)")
    fields = serializers.CharField(required=False, allow_blank=True, help_text="Control which fields are included")
    order_by = serializers.CharField(required=False, allow_blank=True, help_text="Sort by specified field(s)")

    def to_internal_value(self, data):
        """Sanitize input data by stripping NUL bytes before field validation."""
        sanitized = {
            key: value.replace("\x00", "") if isinstance(value, str) else value for key, value in data.items()
        }
        return super().to_internal_value(sanitized)

    def validate_resource_id(self, value):
        """Validate resource_id is provided."""
        if not value:
            raise serializers.ValidationError("resource_id is required to identify the resource for role bindings.")
        return value

    def validate_resource_type(self, value):
        """Validate resource_type is provided."""
        if not value:
            raise serializers.ValidationError(
                "resource_type is required to specify the type of resource (e.g., 'workspace')."
            )
        return value

    def validate_subject_type(self, value):
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
    """Serializer for role bindings by subject (group or user).

    This serializer formats Group or Principal objects that have been annotated with
    role binding information via the service layer.

    Supports dynamic field selection through the 'field_selection' context parameter.
    Fields are accessed directly on the model using dot notation from the query parameter.

    Field selection syntax:
    - subject(group.name, group.description) - accesses group fields when type="group"
    - subject(user.username) - accesses user fields when type="user"
    - role(name, description) - accesses role.name, role.description
    - resource(name, type) - accesses resource name and type from context
    - last_modified - include root-level field
    """

    last_modified = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def _get_field_selection(self):
        """Get field selection from context."""
        return self.context.get("field_selection")

    def to_representation(self, instance):
        """Override to support field selection.

        Default (no fields param): Returns only basic required fields.
        With fields param: Only explicitly requested fields are included,
        except subject.type which is always included.
        """
        ret = super().to_representation(instance)

        field_selection = self._get_field_selection()

        # Base response always includes core objects
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

    # Field name mapping for special cases (e.g., API field name -> model attribute)
    SUBJECT_FIELD_MAPPING = {
        "group": {"user_count": "principalCount"},
        "user": {},
    }

    def get_subject(self, obj):
        """Extract subject information from the Group or Principal.

        Default (no fields param): Returns only id and type.
        With fields param: Only type is always included. Other fields
        (including id) are only included if explicitly requested.
        """
        if isinstance(obj, Principal):
            return self._build_subject(obj, "user")
        elif isinstance(obj, Group):
            return self._build_subject(obj, "group")
        return None

    def _build_subject(self, obj, subject_type: str):
        """Build subject dict for a Group or Principal.

        Args:
            obj: Group or Principal object
            subject_type: The subject type string ("group" or "user")

        Returns:
            Subject dict with type and requested fields
        """
        field_selection = self._get_field_selection()

        # Default behavior: only basic fields
        if field_selection is None:
            return {
                "id": obj.uuid,
                "type": subject_type,
            }

        # With fields param: type is always included
        subject = {"type": subject_type}

        # Check if id is explicitly requested
        if "id" in field_selection.subject_fields:
            subject["id"] = obj.uuid

        # Extract field names from "{subject_type}.X" paths
        prefix = f"{subject_type}."
        prefix_len = len(prefix)
        fields_to_include = set()
        for field_path in field_selection.subject_fields:
            if field_path.startswith(prefix):
                fields_to_include.add(field_path[prefix_len:])

        # Dynamically extract requested fields from the object
        if fields_to_include:
            field_mapping = self.SUBJECT_FIELD_MAPPING.get(subject_type, {})
            details = {}
            for field_name in fields_to_include:
                # Map API field name to model attribute if needed
                model_attr = field_mapping.get(field_name, field_name)
                value = getattr(obj, model_attr, None)
                if value is not None:
                    details[field_name] = value

            if details:
                subject[subject_type] = details

        return subject

    def get_roles(self, obj):
        """Extract roles from the prefetched role bindings.

        Default (no fields param): Returns only role id.
        With fields param: id is always included, plus explicitly requested fields.
        """
        if isinstance(obj, dict):
            return obj.get("roles", [])

        if isinstance(obj, Principal):
            return self._get_roles_from_user(obj)
        elif isinstance(obj, Group):
            return self._get_roles_from_group(obj)
        return []

    def _get_roles_from_group(self, obj: Group):
        """Extract roles from a Group's prefetched role bindings.

        Args:
            obj: Group object with filtered_bindings prefetch

        Returns:
            List of role dicts
        """
        if not hasattr(obj, "filtered_bindings"):
            return []

        field_selection = self._get_field_selection()

        roles = []
        seen_role_ids = set()

        for binding_group in obj.filtered_bindings:
            if not hasattr(binding_group, "binding") or not binding_group.binding:
                continue

            role = binding_group.binding.role
            if not role or role.uuid in seen_role_ids:
                continue

            # id is always included
            role_data = {"id": role.uuid}

            if field_selection is not None:
                # Add explicitly requested fields
                for field_name in field_selection.role_fields:
                    if field_name != "id":
                        value = getattr(role, field_name, None)
                        if value is not None:
                            role_data[field_name] = value

            roles.append(role_data)
            seen_role_ids.add(role.uuid)

        return roles

    def _get_roles_from_user(self, obj: Principal):
        """Extract roles from a Principal's groups' prefetched role bindings.

        Args:
            obj: Principal object with filtered_groups prefetch

        Returns:
            List of role dicts
        """
        if not hasattr(obj, "filtered_groups"):
            return []

        field_selection = self._get_field_selection()

        roles = []
        seen_role_ids = set()

        # Iterate through user's groups to get roles
        for group in obj.filtered_groups:
            if not hasattr(group, "filtered_bindings"):
                continue

            for binding_group in group.filtered_bindings:
                if not hasattr(binding_group, "binding") or not binding_group.binding:
                    continue

                role = binding_group.binding.role
                if not role or role.uuid in seen_role_ids:
                    continue

                # id is always included
                role_data = {"id": role.uuid}

                if field_selection is not None:
                    # Add explicitly requested fields
                    for field_name in field_selection.role_fields:
                        if field_name != "id":
                            value = getattr(role, field_name, None)
                            if value is not None:
                                role_data[field_name] = value

                roles.append(role_data)
                seen_role_ids.add(role.uuid)

        return roles

    def get_resource(self, obj):
        """Extract resource information from the request context.

        Default (no fields param): Returns only resource id.
        With fields param: id is always included, plus explicitly requested fields.
        Returns None if context has no resource information.
        """
        if isinstance(obj, dict):
            return obj.get("resource", {})

        # Check if context has any resource information
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

            for field_name in field_selection.resource_fields:
                if field_name != "id":
                    value = field_values.get(field_name)
                    if value is not None:
                        resource_data[field_name] = value

        return resource_data


# Backward compatibility alias
RoleBindingByGroupSerializer = RoleBindingOutputSerializer
