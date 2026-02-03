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

from management.role.v2_model import RoleV2
from rest_framework import serializers


class PermissionSerializer(serializers.Serializer):
    """Serializer for Permission objects."""

    application = serializers.CharField(required=True, help_text="Application name")
    resource_type = serializers.CharField(required=True, help_text="Resource type")
    operation = serializers.CharField(required=True, source="verb", help_text="Operation/verb")


class RoleV2ResponseSerializer(serializers.ModelSerializer):
    """Serializer for RoleV2 response data."""

    id = serializers.UUIDField(source="uuid", read_only=True)
    name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    permissions = PermissionSerializer(many=True, read_only=True)
    last_modified = serializers.DateTimeField(source="modified", read_only=True)
    permissions_count = serializers.SerializerMethodField()

    class Meta:

        model = RoleV2
        fields = (
            "id",
            "name",
            "description",
            "permissions",
            "last_modified",
            "permissions_count",
        )

    def __init__(self, *args, **kwargs):
        """Initialize serializer with optional field filtering."""
        super().__init__(*args, **kwargs)

        # Apply field filtering based on 'fields' query parameter from context
        fields_param = self.context.get("fields")
        if fields_param is not None:
            # Parse comma-separated fields
            allowed = set(fields_param.split(","))
            existing = set(self.fields.keys())

            # Remove fields that are not in the allowed list
            for field_name in existing - allowed:
                self.fields.pop(field_name)

    def get_permissions_count(self, obj):
        """Get the count of permissions for the role."""
        return obj.permissions.count()
