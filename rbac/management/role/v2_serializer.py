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
"""Serializers for RoleV2 API."""

from management.role.v2_exceptions import (
    EmptyPermissionsError,
    PermissionsNotFoundError,
    RoleAlreadyExistsError,
    RoleDatabaseError,
)
from management.role.v2_model import CustomRoleV2
from management.role.v2_service import RoleV2Service
from rest_framework import serializers


class PermissionSerializer(serializers.Serializer):
    """Serializer for permission input/output."""

    application = serializers.CharField(required=True, help_text="Application name")
    resource_type = serializers.CharField(required=True, help_text="Resource type")
    operation = serializers.CharField(required=True, help_text="Operation/verb")


class RoleV2CreateRequestSerializer(serializers.Serializer):
    """
    Serializer for role creation request.

    Matches the OpenAPI spec: Roles.CreateOrUpdateRoleRequest
    """

    name = serializers.CharField(
        required=True,
        max_length=175,
        help_text="A human readable name for the role.",
    )
    description = serializers.CharField(
        required=True,
        allow_blank=True,
        help_text="A description of the role to help clarify its purpose.",
    )
    permissions = PermissionSerializer(
        many=True,
        required=True,
        help_text="List of permissions to assign to this role",
    )

    def validate_permissions(self, value):
        """Validate that at least one permission is provided."""
        if not value:
            raise serializers.ValidationError("At least one permission is required.")
        return value


class RoleV2ResponseSerializer(serializers.ModelSerializer):
    """
    Serializer for role response.

    Matches the OpenAPI spec: Roles.Role
    """

    id = serializers.UUIDField(source="uuid", read_only=True)
    name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    permissions = serializers.SerializerMethodField()
    last_modified = serializers.DateTimeField(source="modified", read_only=True)
    permissions_count = serializers.SerializerMethodField()

    class Meta:
        """Metadata for the serializer."""

        model = CustomRoleV2
        fields = (
            "id",
            "name",
            "description",
            "permissions",
            "last_modified",
            "permissions_count",
        )

    def get_permissions(self, obj):
        """Get permissions in the API response format."""
        return [
            {
                "application": p.application,
                "resource_type": p.resource_type,
                "operation": p.verb,
            }
            for p in obj.permissions.all()
        ]

    def get_permissions_count(self, obj):
        """Get the count of permissions."""
        return obj.permissions.count()


class RoleV2Serializer(serializers.ModelSerializer):
    """
    Combined serializer for RoleV2 CRUD operations.

    Uses separate request/response serializers internally but provides
    a unified interface for the viewset.

    This serializer is responsible for:
    - Validating HTTP-level concerns (field presence, format)
    - Calling the Service layer for business logic
    - Converting domain exceptions to HTTP-level ValidationErrors
    """

    id = serializers.UUIDField(source="uuid", read_only=True)
    name = serializers.CharField(required=True, max_length=175)
    description = serializers.CharField(required=True, allow_blank=True)
    permissions = PermissionSerializer(many=True, required=True, write_only=True)
    last_modified = serializers.DateTimeField(source="modified", read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = CustomRoleV2
        fields = (
            "id",
            "name",
            "description",
            "permissions",
            "last_modified",
        )

    def __init__(self, *args, **kwargs):
        """Initialize with service dependency."""
        super().__init__(*args, **kwargs)
        self._service = RoleV2Service()

    def validate_permissions(self, value):
        """Validate that at least one permission is provided."""
        if not value:
            raise serializers.ValidationError("At least one permission is required.")
        return value

    def create(self, validated_data):
        """
        Create the role using the domain service.

        Catches domain exceptions and converts them to HTTP-level ValidationErrors.
        """
        tenant = self.context["request"].tenant
        permission_data = validated_data.pop("permissions")

        try:
            # Resolve permission dicts to Permission model instances
            permissions = self._service.resolve_permissions(permission_data)

            # Delegate to service for domain logic
            return self._service.create(
                name=validated_data["name"],
                description=validated_data["description"],
                permissions=permissions,
                tenant=tenant,
            )
        except EmptyPermissionsError as e:
            raise serializers.ValidationError({"permissions": str(e)})
        except PermissionsNotFoundError as e:
            raise serializers.ValidationError({"permissions": str(e)})
        except RoleAlreadyExistsError as e:
            raise serializers.ValidationError({"name": str(e)})
        except RoleDatabaseError as e:
            raise serializers.ValidationError({"detail": str(e)})

    def to_representation(self, instance):
        """Use the response serializer for output."""
        return RoleV2ResponseSerializer(instance, context=self.context).data
