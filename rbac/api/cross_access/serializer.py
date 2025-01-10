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
from django.db import transaction
from management.models import Role
from management.notifications.notification_handlers import cross_account_access_handler
from management.permission.serializer import PermissionSerializer
from rest_framework import serializers

from api.models import CrossAccountRequest


class CrossAccountRequestSerializer(serializers.ModelSerializer):
    """Serializer for the cross access request model."""

    request_id = serializers.UUIDField(read_only=True)
    target_account = serializers.CharField(max_length=36, required=False)
    target_org = serializers.CharField(max_length=36)
    user_id = serializers.CharField(max_length=15)
    start_date = serializers.DateTimeField(format="%d %b %Y")
    end_date = serializers.DateTimeField(format="%d %b %Y")
    created = serializers.DateTimeField(format="%d %b %Y, %H:%M UTC")
    status = serializers.CharField(max_length=10)

    class Meta:
        """Metadata for the serializer."""

        model = CrossAccountRequest
        fields = (
            "request_id",
            "target_account",
            "target_org",
            "user_id",
            "start_date",
            "end_date",
            "created",
            "status",
        )


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for the roles of cross access request model."""

    uuid = serializers.UUIDField(read_only=True)
    display_name = serializers.CharField(max_length=150, read_only=True)
    description = serializers.CharField(max_length=150, read_only=True)
    permissions = serializers.SerializerMethodField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Role
        fields = ("uuid", "display_name", "description", "permissions")

    def get_permissions(self, obj):
        """Permissions constructor for the serializer."""
        serialized_permissions = [PermissionSerializer(access.permission).data for access in obj.access.all()]
        return serialized_permissions


class CrossAccountRequestDetailSerializer(serializers.ModelSerializer):
    """Serializer for the cross access request model with details."""

    request_id = serializers.UUIDField(read_only=True)
    target_account = serializers.CharField(max_length=36, required=False, allow_null=True, allow_blank=True)
    target_org = serializers.CharField(max_length=36)
    user_id = serializers.CharField(max_length=15)
    start_date = serializers.DateTimeField(format="%m/%d/%Y", input_formats=["%m/%d/%Y"])
    end_date = serializers.DateTimeField(format="%m/%d/%Y", input_formats=["%m/%d/%Y"])
    created = serializers.DateTimeField(format="%m/%d/%Y", read_only=True)
    status = serializers.CharField(max_length=10, read_only=True)
    roles = RoleSerializer(many=True)

    class Meta:
        """Metadata for the serializer."""

        model = CrossAccountRequest
        fields = (
            "request_id",
            "target_account",
            "target_org",
            "user_id",
            "start_date",
            "end_date",
            "created",
            "status",
            "roles",
        )

    def get_roles(self, obj):
        """Roles constructor for the serializer."""
        serialized_roles = [RoleSerializer(role).data for role in obj.roles.all()]
        return serialized_roles

    def create(self, validated_data):
        """Override the create method to associate the roles to cross account request after it is created."""
        validated_data.pop("roles")
        request = CrossAccountRequest.objects.create(**validated_data)
        cross_account_access_handler(request, self.context["user"])
        role_uuids = [role["uuid"] for role in self.context["request"].data["roles"]]
        request.roles.add(*role_uuids)
        return request

    @transaction.atomic
    def update(self, instance, validated_data):
        """Override the update method to associate the roles to cross account request after it is updated."""
        if "roles" in validated_data:
            validated_data.pop("roles")
            role_uuids = [role["uuid"] for role in self.context["request"].data["roles"]]
            instance.roles.clear()
            instance.roles.add(*role_uuids)

        for field in validated_data:
            setattr(instance, field, validated_data.get(field))

        instance.save()
        return instance
