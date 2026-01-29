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
    """Serializer for Permission in role responses."""

    application = serializers.CharField(read_only=True)
    resource_type = serializers.CharField(read_only=True)
    operation = serializers.CharField(source="verb", read_only=True)


class RoleOutputSerializer(serializers.ModelSerializer):
    """Serializer for V2 Role output."""

    # All valid fields that can be requested via ?fields= param
    VALID_FIELDS = {"id", "name", "description", "permissions_count", "last_modified", "permissions"}

    # Fields returned when no ?fields= param is provided
    DEFAULT_FIELDS = {"id", "name", "description", "last_modified"}

    id = serializers.UUIDField(source="uuid", read_only=True, required=False)
    permissions_count = serializers.IntegerField(source="permissions_count_annotation", read_only=True, required=False)
    permissions = PermissionSerializer(many=True, read_only=True, required=False)
    last_modified = serializers.DateTimeField(source="modified", read_only=True, required=False)

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
            return self.DEFAULT_FIELDS

        fields_param = request.query_params.get("fields", "").replace("\x00", "")
        if not fields_param:
            return self.DEFAULT_FIELDS

        # return the requested fields or default
        requested = {f.strip() for f in fields_param.split(",") if f.strip()}
        return requested & self.VALID_FIELDS or self.DEFAULT_FIELDS
