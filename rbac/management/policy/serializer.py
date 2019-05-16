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
from management.group.serializer import GroupInputSerializer
from management.policy.model import Policy
from management.role.model import Role
from management.role.serializer import RoleMinimumSerializer
from rest_framework import serializers
from rest_framework.validators import UniqueValidator


class UUIDListField(serializers.ListField):
    """List of UUID Fields."""

    child = serializers.UUIDField()


class PolicyInputSerializer(serializers.ModelSerializer):
    """Serializer for the policy model."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True,
                                 max_length=150,
                                 validators=[UniqueValidator(queryset=Policy.objects.all())])
    description = serializers.CharField(allow_null=True, required=False)
    group = serializers.UUIDField(required=True)
    roles = UUIDListField(required=True)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Policy
        fields = ('uuid', 'name', 'description', 'group', 'roles', 'created', 'modified')

    def create(self, validated_data):
        """Create the policy object in the database."""
        name = validated_data.pop('name')
        description = validated_data.pop('description', None)
        group_uuid = validated_data.pop('group')
        role_uuids = validated_data.pop('roles')
        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            msg = 'Group with uuid {} could not be found.'
            error = {'detail': msg.format(group_uuid)}
            raise serializers.ValidationError(error)

        policy = Policy(name=name, description=description, group=group)
        roles = []
        for role_uuid in role_uuids:
            try:
                role = Role.objects.get(uuid=role_uuid)
                roles.append(role)
            except Role.DoesNotExist:
                msg = 'Role with uuid {} could not be found.'
                error = {'detail': msg.format(role_uuid)}
                raise serializers.ValidationError(error)
        if len(roles) == 0:
            msg = 'Policy must have at least one role.'
            error = {'detail': msg}
            raise serializers.ValidationError(error)
        policy.save()
        for role in roles:
            policy.roles.add(role)
        policy.save()
        return policy

    def update(self, instance, validated_data):
        """Update the policy object in the database."""
        instance.name = validated_data.get('name', instance.name)
        instance.description = validated_data.get('description',
                                                  instance.description)
        group_uuid = validated_data.pop('group')
        if instance.group.uuid != group_uuid:
            try:
                group = Group.objects.get(uuid=group_uuid)
                instance.group = group
                instance.save()
            except Group.DoesNotExist:
                msg = 'Group with uuid {} could not be found.'
                error = {'detail': msg.format(group_uuid)}
                raise serializers.ValidationError(error)

        role_uuids = validated_data.pop('roles')
        roles = []
        for role_uuid in role_uuids:
            try:
                role = Role.objects.get(uuid=role_uuid)
                roles.append(role)
            except Role.DoesNotExist:
                msg = 'Role with uuid {} could not be found.'
                error = {'detail': msg.format(role_uuid)}
                raise serializers.ValidationError(error)

        if len(roles) == 0:
            msg = 'Policy must have at least one role.'
            error = {'detail': msg}
            raise serializers.ValidationError(error)

        instance.roles.clear()
        for role in roles:
            instance.roles.add(role)
        instance.save()
        return instance

    def to_representation(self, obj):
        """Convert representation to dictionary object."""
        group = GroupInputSerializer(obj.group)
        roles = []
        for role in obj.roles.all():
            serializer = RoleMinimumSerializer(role)
            roles.append(serializer.data)
        return {
            'uuid': obj.uuid,
            'name': obj.name,
            'description': obj.description,
            'group': group.data,
            'roles': roles,
            'created': obj.created,
            'modified': obj.modified,
        }


class PolicySerializer(serializers.ModelSerializer):
    """Serializer for the policy model."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True, max_length=150)
    description = serializers.CharField(allow_null=True, required=False)
    group = GroupInputSerializer(required=True)
    roles = RoleMinimumSerializer(many=True, required=True)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Policy
        fields = ('uuid', 'name', 'description',
                  'group', 'roles', 'created', 'modified')

    def to_representation(self, obj):
        """Convert representation to dictionary object."""
        group = GroupInputSerializer(obj.group)
        roles = []
        for role in obj.roles.all():
            serializer = RoleMinimumSerializer(role)
            roles.append(serializer.data)
        return {
            'uuid': obj.uuid,
            'name': obj.name,
            'description': obj.description,
            'group': group.data,
            'roles': roles,
            'created': obj.created,
            'modified': obj.modified
        }
