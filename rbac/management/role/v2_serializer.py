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
"""Serializers for V2 Role API."""

from dataclasses import dataclass, field
from typing import Optional

from rest_framework import serializers


class FieldSelectionValidationError(Exception):
    """Exception raised when field selection validation fails."""

    def __init__(self, message: str):
        """Initialize with error message."""
        self.message = message
        super().__init__(self.message)


@dataclass
class FieldSelection:
    """Data class representing parsed field selections for roles from the fields parameter."""

    # All valid fields that can be requested
    VALID_FIELDS = {"id", "name", "description", "permissions_count", "last_modified", "permissions"}

    # Fields returned when no fields param is provided
    DEFAULT_FIELDS = {"id", "name", "description", "last_modified"}

    selected_fields: set = field(default_factory=set)

    @classmethod
    def parse(cls, fields_param: Optional[str]) -> Optional["FieldSelection"]:
        """Parse fields parameter string into FieldSelection.

        Syntax:
        - Comma-separated list of field names

        Examples:
        - id,name - returns only id and name
        - permissions - returns only permissions
        - id,name,description,permissions_count - returns those four fields

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

        # Split by comma and strip whitespace
        parts = []
        for f in fields_param.split(","):
            stripped = f.strip()
            if stripped:
                parts.append(stripped)

        for part in parts:
            if part in cls.VALID_FIELDS:
                selection.selected_fields.add(part)
            else:
                invalid_fields.append(part)

        if invalid_fields:
            raise FieldSelectionValidationError(
                f"Invalid field(s): {', '.join(sorted(invalid_fields))}. "
                f"Valid fields are: {sorted(cls.VALID_FIELDS)}."
            )

        return selection


class RoleInputSerializer(serializers.Serializer):
    """Input serializer for role query parameters.

    Handles validation of query parameters for the V2 roles API.
    """

    # Allowed fields for order_by parameter
    VALID_ORDER_BY_FIELDS = {"name", "last_modified"}

    name = serializers.CharField(
        required=False, allow_blank=True, help_text="Filter by role name (case-sensitive exact match)"
    )
    fields = serializers.CharField(required=False, allow_blank=True, help_text="Control which fields are included")
    order_by = serializers.CharField(required=False, allow_blank=True, help_text="Sort by specified field(s)")

    def to_internal_value(self, data):
        """Sanitize input data by stripping NUL bytes before field validation."""
        sanitized = {
            key: value.replace("\x00", "") if isinstance(value, str) else value for key, value in data.items()
        }
        return super().to_internal_value(sanitized)

    def validate_name(self, value):
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
        """Validate order_by parameter against allowed fields."""
        if not value:
            return None

        invalid_fields = []
        for f in value.split(","):
            f = f.strip()
            if not f:
                continue
            # Strip leading '-' for descending order
            field_name = f.lstrip("-")
            if field_name not in self.VALID_ORDER_BY_FIELDS:
                invalid_fields.append(field_name)

        if invalid_fields:
            raise serializers.ValidationError(
                f"Invalid order_by field(s): {', '.join(sorted(invalid_fields))}. "
                f"Allowed fields are: {sorted(self.VALID_ORDER_BY_FIELDS)}."
            )

        return value


class PermissionSerializer(serializers.Serializer):
    """Serializer for Permission in role responses."""

    application = serializers.CharField(read_only=True)
    resource_type = serializers.CharField(read_only=True)
    operation = serializers.CharField(source="verb", read_only=True)


class RoleOutputSerializer(serializers.Serializer):
    """Serializer for V2 Role output.

    This serializer formats RoleV2 objects with dynamic field selection.

    Supports dynamic field selection through the 'field_selection' context parameter.
    """

    id = serializers.SerializerMethodField()
    name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    permissions_count = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()

    def _get_field_selection(self) -> Optional[FieldSelection]:
        """Get field selection from context."""
        return self.context.get("field_selection")

    def to_representation(self, instance):
        """Override to support field selection.

        Works as a field mask:
        - No fields param: Returns id, name, description, and permissions_count.
        - With fields param: Returns exactly the requested fields.
        """
        ret = super().to_representation(instance)

        field_selection = self._get_field_selection()

        if field_selection is None:
            return {field_name: ret.get(field_name) for field_name in FieldSelection.DEFAULT_FIELDS}

        # Field mask: return exactly what was requested
        filtered = {}
        for field_name in field_selection.selected_fields:
            filtered[field_name] = ret.get(field_name)
        return filtered

    def get_id(self, obj):
        """Return the UUID as the id field."""
        return obj.uuid

    def get_permissions_count(self, obj) -> int:
        """Return the number of permissions assigned to this role."""
        if hasattr(obj, "permissions_count_annotation"):
            return obj.permissions_count_annotation
        return obj.permissions.count()

    def get_permissions(self, obj) -> list:
        """Return the list of permissions assigned to this role."""
        # Only fetch permissions if this field is requested
        field_selection = self._get_field_selection()
        if field_selection is None or "permissions" not in field_selection.selected_fields:
            return []

        if hasattr(obj, "prefetched_permissions"):
            permissions = obj.prefetched_permissions
        else:
            permissions = obj.permissions.all()

        return PermissionSerializer(permissions, many=True).data

    def get_last_modified(self, obj):
        """Return the last modification timestamp."""
        return obj.modified


# Backward compatibility alias
RoleV2Serializer = RoleOutputSerializer
