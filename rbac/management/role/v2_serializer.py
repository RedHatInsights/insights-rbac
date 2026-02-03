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

from management.role.v2_exceptions import (
    EmptyDescriptionError,
    EmptyPermissionsError,
    PermissionsNotFoundError,
    RoleAlreadyExistsError,
    RoleDatabaseError,
)
from management.role.v2_model import RoleV2
from management.role.v2_service import RoleV2Service
from rest_framework import serializers

# Centralized mapping from domain exceptions to API error fields
ERROR_MAPPING = {
    EmptyDescriptionError: "description",
    EmptyPermissionsError: "permissions",
    PermissionsNotFoundError: "permissions",
    RoleAlreadyExistsError: "name",
    RoleDatabaseError: "detail",
}


class PermissionSerializer(serializers.Serializer):

    application = serializers.CharField(required=True, help_text="Application name")
    resource_type = serializers.CharField(required=True, help_text="Resource type")
    operation = serializers.CharField(required=True, source="verb", help_text="Operation/verb")


class RoleV2ResponseSerializer(serializers.ModelSerializer):

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

    def get_permissions_count(self, obj):
        return obj.permissions.count()


class RoleV2RequestSerializer(serializers.ModelSerializer):

    service_class = RoleV2Service

    id = serializers.UUIDField(source="uuid", read_only=True)
    name = serializers.CharField()
    description = serializers.CharField()
    permissions = PermissionSerializer(many=True, write_only=True)

    class Meta:

        model = RoleV2
        fields = ("id", "name", "description", "permissions")

    @property
    def service(self):
        return self.context.get("role_service") or self.service_class()

    def create(self, validated_data):
        tenant = self.context["request"].tenant
        permission_data = validated_data.pop("permissions", [])

        try:
            permissions = self.service.resolve_permissions(permission_data)
            return self.service.create(
                name=validated_data.get("name"),
                description=validated_data.get("description"),
                permissions=permissions,
                tenant=tenant,
            )
        except tuple(ERROR_MAPPING.keys()) as e:
            field = ERROR_MAPPING[type(e)]
            raise serializers.ValidationError({field: str(e)})
