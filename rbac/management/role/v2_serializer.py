#
# Copyright 2026 Red Hat, Inc.
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
"""Serializers for RoleV2 API."""

from management.role_binding.serializer import FieldSelection, FieldSelectionValidationError
from rest_framework import serializers

from .v2_model import RoleV2


class PermissionSerializer(serializers.Serializer):
    """Serializer for Permission objects."""

    application = serializers.CharField()
    resource_type = serializers.CharField()
    operation = serializers.CharField(source="verb")


class RoleV2ResponseSerializer(serializers.ModelSerializer):
    """Response serializer for RoleV2 model."""

    DEFAULT_LIST_FIELDS = {"id", "name", "description", "last_modified"}

    id = serializers.UUIDField(source="uuid", read_only=True)
    permissions_count = serializers.IntegerField(source="permissions_count_annotation", read_only=True)
    permissions = PermissionSerializer(many=True, required=False)
    last_modified = serializers.DateTimeField(source="modified", read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = RoleV2
        fields = ("id", "name", "description", "permissions_count", "permissions", "last_modified")

    def __init__(self, *args, **kwargs):
        """Initialize with dynamic field selection from request."""
        super().__init__(*args, **kwargs)

        allowed = self._get_allowed_fields()
        for field_name in set(self.fields) - allowed:
            self.fields.pop(field_name)

    def _get_allowed_fields(self) -> set:
        """Get allowed fields from serializer context."""
        field_selection = self.context.get("field_selection")
        if not field_selection:
            return self.DEFAULT_LIST_FIELDS

        return field_selection.root_fields & set(self.Meta.fields) or self.DEFAULT_LIST_FIELDS


class RoleFieldSelection(FieldSelection):
    """Field selection for roles endpoint."""

    VALID_ROOT_FIELDS = set(RoleV2ResponseSerializer.Meta.fields)
    VALID_SUBJECT_FIELDS: set = set()
    VALID_ROLE_FIELDS: set = set()
    VALID_RESOURCE_FIELDS: set = set()

    @classmethod
    def parse(cls, fields_param: str | None) -> "FieldSelection | None":
        """Parse fields parameter with NUL byte sanitization."""
        if fields_param:
            fields_param = fields_param.replace("\x00", "")
        return super().parse(fields_param)


class RoleV2InputSerializer(serializers.Serializer):
    """Input serializer for RoleV2 query parameters."""

    name = serializers.CharField(required=False, allow_blank=True, help_text="Filter by exact role name")
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
            return RoleFieldSelection.parse(value)
        except FieldSelectionValidationError as e:
            raise serializers.ValidationError(e.message)

    def validate_order_by(self, value):
        """Return None for empty values."""
        return value or None
