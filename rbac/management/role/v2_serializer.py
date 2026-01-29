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

    id = serializers.UUIDField(source="uuid", read_only=True)
    permissions = PermissionSerializer(many=True, required=False)
    last_modified = serializers.DateTimeField(source="modified", read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = RoleV2
        fields = ("id", "name", "description", "permissions", "last_modified")
