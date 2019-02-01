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

"""Serializer for policy management."""
from management.group.model import Group
from management.group.serializer import GroupSerializer
from management.policy.model import Policy
from management.role.model import Role
from management.role.serializer import RoleSerializer
from rest_framework import serializers


class UUIDListField(serializers.ListField):
    """List of UUID Fields."""

    child = serializers.UUIDField()


class PolicyInputSerializer(serializers.ModelSerializer):
    """Serializer for the policy model."""

    group = serializers.UUIDField(required=True)
    roles = UUIDListField(required=True)

    class Meta:
        """Metadata for the serializer."""

        model = Policy
        fields = ('uuid', 'name', 'group', 'roles')

    def create(self, validated_data):
        """Create the policy object in the database."""
        name = validated_data.pop('name')
        group_uuid = validated_data.pop('group')
        role_uuids = validated_data.pop('roles')
        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            msg = 'Group with uuid {} could not be found.'
            error = {'group': msg.format(group_uuid)}
            raise serializers.ValidationError(error)

        policy = Policy(name=name, group=group)
        roles = []
        for role_uuid in role_uuids:
            try:
                role = Role.objects.get(uuid=role_uuid)
                roles.append(role)
            except Role.DoesNotExist:
                msg = 'Role with uuid {} could not be found.'
                error = {'roles': msg.format(group_uuid)}
                raise serializers.ValidationError(error)

        policy.save()
        for role in roles:
            policy.roles.add(role)
        policy.save()
        return policy

    def update(self, instance, validated_data):
        """Update the policy object in the database."""
        instance.name = validated_data.get('name', instance.name)
        group_uuid = validated_data.pop('group')
        if instance.group.uuid != group_uuid:
            try:
                group = Group.objects.get(uuid=group_uuid)
                instance.group = group
                instance.save()
            except Group.DoesNotExist:
                msg = 'Group with uuid {} could not be found.'
                error = {'group': msg.format(group_uuid)}
                raise serializers.ValidationError(error)

        role_uuids = validated_data.pop('roles')
        roles = []
        for role_uuid in role_uuids:
            try:
                role = Role.objects.get(uuid=role_uuid)
                roles.append(role)
            except Role.DoesNotExist:
                msg = 'Role with uuid {} could not be found.'
                error = {'roles': msg.format(group_uuid)}
                raise serializers.ValidationError(error)

        instance.roles.clear()
        for role in roles:
            instance.roles.add(role)
        instance.save()
        return instance

    def to_representation(self, obj):
        """Convert representation to dictionary object."""
        group = GroupSerializer(obj.group)
        roles = []
        for role in obj.roles.all():
            serializer = RoleSerializer(role)
            roles.append(serializer.data)
        return {
            'uuid': obj.uuid,
            'name': obj.name,
            'group': group.data,
            'roles': roles
        }


class PolicySerializer(serializers.ModelSerializer):
    """Serializer for the policy model."""

    group = GroupSerializer(required=True)
    roles = RoleSerializer(many=True, required=True)

    class Meta:
        """Metadata for the serializer."""

        model = Policy
        fields = ('uuid', 'name', 'group', 'roles')

    def to_representation(self, obj):
        """Convert representation to dictionary object."""
        group = GroupSerializer(obj.group)
        roles = []
        for role in obj.roles.all():
            serializer = RoleSerializer(role)
            roles.append(serializer.data)
        return {
            'uuid': obj.uuid,
            'name': obj.name,
            'group': group.data,
            'roles': roles
        }
