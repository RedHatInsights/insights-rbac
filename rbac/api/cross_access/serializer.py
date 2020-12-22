#
# Copyright 2020 Red Hat, Inc.
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

"""Serializer for CrossAccountRequest."""
from management.models import Role
from management.permission.serializer import PermissionSerializer
from rest_framework import serializers
from tenant_schemas.utils import tenant_context

from api.models import CrossAccountRequest, Tenant


class CrossAccountRequestSerializer(serializers.ModelSerializer):
    """Serializer for the cross access request model."""

    request_id = serializers.UUIDField(read_only=True)
    target_account = serializers.CharField(max_length=15)
    user_id = serializers.CharField(max_length=15)
    start_date = serializers.DateTimeField(format="%d %b %Y")
    end_date = serializers.DateTimeField(format="%d %b %Y")
    created = serializers.DateTimeField(format="%d %b %Y, %H:%M UTC")
    status = serializers.CharField(max_length=10)

    class Meta:
        """Metadata for the serializer."""

        model = CrossAccountRequest
        fields = ("request_id", "target_account", "user_id", "start_date", "end_date", "created", "status")


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for the roles of cross access request model."""

    display_name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    permissions = serializers.SerializerMethodField()

    class Meta:
        """Metadata for the serializer."""

        model = Role
        fields = ("display_name", "description", "permissions")

    def get_permissions(self, obj):
        """Permissions constructor for the serializer."""
        serialized_permissions = [PermissionSerializer(access.permission).data for access in obj.access.all()]
        return serialized_permissions


class CrossAccountRequestDetailSerializer(serializers.ModelSerializer):
    """Serializer for the cross access request model with details."""

    request_id = serializers.UUIDField(read_only=True)
    target_account = serializers.CharField(max_length=15)
    user_id = serializers.CharField(max_length=15)
    start_date = serializers.DateTimeField(format="%m/%d/%Y")
    end_date = serializers.DateTimeField(format="%m/%d/%Y")
    created = serializers.DateTimeField(format="%m/%d/%Y")
    status = serializers.CharField(max_length=10)
    roles = serializers.SerializerMethodField()

    class Meta:
        """Metadata for the serializer."""

        model = CrossAccountRequest
        fields = ("request_id", "target_account", "user_id", "start_date", "end_date", "created", "status", "roles")

    def get_roles(self, obj):
        """Roles constructor for the serializer."""
        with tenant_context(Tenant.objects.get(schema_name="public")):
            serialized_roles = [RoleSerializer(role).data for role in obj.roles.all()]
        return serialized_roles
