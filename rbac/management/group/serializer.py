#
# Copyright 2019 Red Hat, Inc.
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

"""Serializer for group management."""
import logging
from management.group.model import Group
from management.notifications.notification_hanlders import group_obj_change_notification_handler
from management.principal.proxy import PrincipalProxy
from management.principal.serializer import PrincipalInputSerializer, PrincipalSerializer
from management.role.serializer import RoleMinimumSerializer
from management.serializer_override_mixin import SerializerCreateOverrideMixin
from rest_framework import serializers, status

logger = logging.getLogger(__name__)


class GroupInputSerializer(SerializerCreateOverrideMixin, serializers.ModelSerializer):
    """Serializer for Group input model."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True, max_length=150)
    description = serializers.CharField(allow_null=True, required=False)
    principalCount = serializers.IntegerField(read_only=True)
    platform_default = serializers.BooleanField(read_only=True)
    admin_default = serializers.BooleanField(read_only=True)
    system = serializers.BooleanField(read_only=True)
    roleCount = serializers.SerializerMethodField()
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)

    def get_roleCount(self, obj):
        """Role count for the serializer."""
        return obj.role_count()

    class Meta:
        """Metadata for the serializer."""

        model = Group
        fields = (
            "uuid",
            "name",
            "description",
            "principalCount",
            "platform_default",
            "admin_default",
            "roleCount",
            "created",
            "modified",
            "system",
        )

    def create(self, validated_data):
        """Create the role object in the database."""
        group = super().create(validated_data)
        logger.info("Sending out notifications of creating the group************************")
        group_obj_change_notification_handler(self.context["request"].user, group, "created")
        logger.info("Notifications of creating the group is done******************************")
        return group

    def update(self, instance, validated_data):
        """Update the role object in the database."""
        group = super().update(instance, validated_data)
        group_obj_change_notification_handler(self.context["request"].user, group, "updated")
        return group


class GroupSerializer(SerializerCreateOverrideMixin, serializers.ModelSerializer):
    """Serializer for the Group model."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True, max_length=150)
    description = serializers.CharField(allow_null=True, required=False)
    principals = PrincipalSerializer(read_only=True, many=True)
    platform_default = serializers.BooleanField(read_only=True)
    admin_default = serializers.BooleanField(read_only=True)
    system = serializers.BooleanField(read_only=True)
    roles = serializers.SerializerMethodField()
    roleCount = serializers.SerializerMethodField()
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Group
        fields = (
            "uuid",
            "name",
            "description",
            "principals",
            "platform_default",
            "admin_default",
            "created",
            "modified",
            "roles",
            "roleCount",
            "system",
        )

    def to_representation(self, obj):
        """Convert representation to dictionary object."""
        proxy = PrincipalProxy()
        formatted = super().to_representation(obj)
        principals = formatted.pop("principals")
        users = [principal.get("username") for principal in principals]
        resp = proxy.request_filtered_principals(users, limit=len(users))
        if resp.get("status_code") == status.HTTP_200_OK:
            principals = resp.get("data")
        formatted["principals"] = principals
        return formatted

    def get_roleCount(self, obj):
        """Role count for the serializer."""
        return obj.role_count()

    def get_roles(self, obj):
        """Role constructor for the serializer."""
        serialized_roles = [RoleMinimumSerializer(role).data for role in obj.roles_with_access()]
        return serialized_roles


class GroupPrincipalInputSerializer(serializers.Serializer):
    """Serializer for adding principals to a group."""

    principals = PrincipalInputSerializer(many=True)

    class Meta:
        """Metadata for the serializer."""

        fields = ("principals",)


class GroupRoleSerializerOut(serializers.Serializer):
    """Serializer for getting roles for a group."""

    def to_representation(self, obj):
        """Return the collection to be serialized."""
        return obj


class GroupRoleSerializerIn(serializers.Serializer):
    """Serializer for managing roles for a group."""

    roles = serializers.ListField(child=serializers.UUIDField())

    def to_representation(self, obj):
        """Convert representation to dictionary object."""
        serialized_roles = [RoleMinimumSerializer(role).data for role in obj.roles_with_access()]
        return {"data": serialized_roles}
