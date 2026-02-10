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

from management.exceptions import RequiredFieldError
from management.role.v2_exceptions import (
    InvalidRolePermissionsError,
    PermissionsNotFoundError,
    RoleAlreadyExistsError,
    RoleDatabaseError,
)
from management.role.v2_model import RoleV2
from management.role.v2_service import RoleV2Service
from rest_framework import serializers

# Centralized mapping from domain exceptions to API error fields
ERROR_MAPPING = {
    InvalidRolePermissionsError: "permissions",
    PermissionsNotFoundError: "permissions",
    RoleAlreadyExistsError: "name",
    RoleDatabaseError: "detail",
}


class PermissionSerializer(serializers.Serializer):
    """Serializer for permission data."""

    application = serializers.CharField(required=True, help_text="Application name")
    resource_type = serializers.CharField(required=True, help_text="Resource type")
    operation = serializers.CharField(required=True, source="verb", help_text="Operation/verb")


class RoleV2ResponseSerializer(serializers.ModelSerializer):
    """Serializer for RoleV2 API responses."""

    id = serializers.UUIDField(source="uuid", read_only=True)
    name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    permissions = serializers.SerializerMethodField()
    permissions_count = serializers.SerializerMethodField()
    last_modified = serializers.DateTimeField(source="modified", read_only=True)

    class Meta:
        model = RoleV2
        fields = (
            "id",
            "name",
            "description",
            "permissions",
            "permissions_count",
            "last_modified",
        )

    def get_permissions(self, obj):
        """Return permissions, ordered by input order if available, otherwise alphabetically."""
        permissions = list(obj.permissions.all())
        input_permissions = self.context.get("input_permissions")

        if input_permissions:
            # Sort by input order (for create responses)
            order_map = {}
            for i, p in enumerate(input_permissions):
                key = f"{p.get('application')}:{p.get('resource_type')}:{p.get('operation')}"
                order_map[key] = i
            permissions.sort(key=lambda p: order_map.get(p.permission, float("inf")))
        else:
            # Sort alphabetically by permission string (for retrieve/list responses)
            permissions.sort(key=lambda p: p.permission)

        return PermissionSerializer(permissions, many=True).data

    def get_permissions_count(self, obj):
        """Return the number of permissions assigned to this role."""
        return obj.permissions.count()


class RoleV2RequestSerializer(serializers.ModelSerializer):
    """Serializer for RoleV2 create/update requests."""

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
        """Return the service instance from context or create a new one."""
        if "role_service" in self.context:
            return self.context["role_service"]
        # Create service with tenant from request context
        tenant = self.context["request"].tenant
        return self.service_class(tenant=tenant)

    def create(self, validated_data):
        """Create a new RoleV2 using the service layer."""
        tenant = self.context["request"].tenant
        permission_data = validated_data.pop("permissions", [])

        try:
            return self.service.create(
                name=validated_data.get("name"),
                description=validated_data.get("description"),
                permission_data=permission_data,
                tenant=tenant,
            )
        except RequiredFieldError as e:
            raise serializers.ValidationError({e.field_name: str(e)})
        except tuple(ERROR_MAPPING.keys()) as e:
            field = ERROR_MAPPING[type(e)]
            raise serializers.ValidationError({field: str(e)})
