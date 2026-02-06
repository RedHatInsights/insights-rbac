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
from management.utils import FieldSelection, FieldSelectionValidationError
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

    application = serializers.CharField(help_text="Application name")
    resource_type = serializers.CharField(help_text="Resource type")
    operation = serializers.CharField(source="verb", help_text="Operation/verb")


class RoleV2ResponseSerializer(serializers.ModelSerializer):
    """Serializer for RoleV2 API responses."""

    id = serializers.UUIDField(source="uuid", read_only=True)
    name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    permissions_count = serializers.IntegerField(source="permissions_count_annotation", read_only=True)
    permissions = serializers.SerializerMethodField()
    last_modified = serializers.DateTimeField(source="modified", read_only=True)

    class Meta:

        model = RoleV2
        fields = ("id", "name", "description", "permissions_count", "permissions", "last_modified")

    def __init__(self, *args, **kwargs):
        """Initialize with dynamic field selection from context."""
        super().__init__(*args, **kwargs)

        allowed = self.context.get("fields")
        if allowed is not None:
            for field_name in set(self.fields) - allowed:
                self.fields.pop(field_name)

    def get_permissions(self, obj):
        """Return permissions, ordered by input order if available."""
        permissions = list(obj.permissions.all())
        input_permissions = self.context.get("input_permissions")

        if input_permissions:
            order_map = {}
            for i, p in enumerate(input_permissions):
                key = f"{p.get('application')}:{p.get('resource_type')}:{p.get('operation')}"
                order_map[key] = i

            # Sort permissions by input order
            permissions.sort(key=lambda p: order_map.get(p.permission, float("inf")))

        return PermissionSerializer(permissions, many=True).data

    def get_permissions_count(self, obj):
        """Return permissions count, using annotation if available."""
        count = getattr(obj, "permissions_count_annotation", None)
        if count is not None:
            return count
        return obj.permissions.count()


class RoleFieldSelection(FieldSelection):
    """Field selection for roles endpoint."""

    VALID_ROOT_FIELDS = set(RoleV2ResponseSerializer.Meta.fields)


class RoleV2ListSerializer(serializers.Serializer):
    """Input serializer for RoleV2 list query parameters."""

    service_class = RoleV2Service

    DEFAULT_FIELDS = {"id", "name", "description", "last_modified"}

    name = serializers.CharField(required=False, allow_blank=True, help_text="Filter by exact role name")
    fields = serializers.CharField(required=False, default="", allow_blank=True, help_text="Control included fields")
    order_by = serializers.CharField(required=False, allow_blank=True, help_text="Sort by specified field(s)")

    @property
    def service(self):
        """Return the service instance from context or create a new one."""
        return self.context.get("role_service") or self.service_class(tenant=self.context["request"].tenant)

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
        """Parse, validate, and resolve fields parameter into a set of field names."""
        if not value:
            return self.DEFAULT_FIELDS
        try:
            field_selection = RoleFieldSelection.parse(value)
        except FieldSelectionValidationError as e:
            raise serializers.ValidationError(e.message)

        if not field_selection:
            return self.DEFAULT_FIELDS

        resolved = field_selection.root_fields & set(RoleV2ResponseSerializer.Meta.fields)
        return resolved or self.DEFAULT_FIELDS

    def validate_order_by(self, value):
        """Return None for empty values."""
        return value or None

    def list(self):
        """Get a list of roles using the service layer."""
        return self.service.list(self.validated_data)


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
        return self.context.get("role_service") or self.service_class()

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
