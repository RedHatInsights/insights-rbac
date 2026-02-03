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

from management.role_binding.serializer import FieldSelection, FieldSelectionValidationError
from rest_framework import serializers

from .v2_model import RoleV2


class RoleFieldSelection(FieldSelection):
    """Field selection for roles endpoint."""

    VALID_ROOT_FIELDS = {"id", "name", "description", "permissions", "permissions_count", "last_modified"}
    VALID_SUBJECT_FIELDS: set = set()
    VALID_ROLE_FIELDS: set = set()
    VALID_RESOURCE_FIELDS: set = set()

    @classmethod
    def parse(cls, fields_param: str | None) -> "FieldSelection | None":
        """Parse fields parameter with NUL byte sanitization."""
        if fields_param:
            fields_param = fields_param.replace("\x00", "")
        return super().parse(fields_param)


class PermissionSerializer(serializers.Serializer):
    """Serializer for Permission objects."""

    application = serializers.CharField()
    resource_type = serializers.CharField()
    operation = serializers.CharField(source="verb")


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for V2 Role model."""

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
        """Parse fields from request query params."""
        request = self.context.get("request")
        if not request:
            return self.DEFAULT_LIST_FIELDS

        try:
            field_selection = RoleFieldSelection.parse(request.query_params.get("fields"))
        except FieldSelectionValidationError as e:
            raise serializers.ValidationError(e.message)

        if not field_selection:
            return self.DEFAULT_LIST_FIELDS

        # return the valid requested fields or default
        return field_selection.root_fields & set(self.Meta.fields) or self.DEFAULT_LIST_FIELDS
