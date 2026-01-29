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

from rest_framework import serializers

from .v2_model import RoleV2


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

        fields_param = request.query_params.get("fields", "").replace("\x00", "")
        if not fields_param:
            return self.DEFAULT_LIST_FIELDS

        # return the requested fields or default
        valid_fields = set(self.Meta.fields)
        requested = {f.strip() for f in fields_param.split(",") if f.strip()}
        return requested & valid_fields or self.DEFAULT_LIST_FIELDS
