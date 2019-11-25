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

"""Serializer for role management."""
from django.utils.translation import gettext as _
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .model import Access, ResourceDefinition, Role


class ResourceDefinitionSerializer(serializers.ModelSerializer):
    """Serializer for the ResourceDefinition model."""

    attributeFilter = serializers.JSONField()

    class Meta:
        """Metadata for the serializer."""

        model = ResourceDefinition
        fields = ('attributeFilter',)


class AccessSerializer(serializers.ModelSerializer):
    """Serializer for the Access model."""

    resourceDefinitions = ResourceDefinitionSerializer(many=True)

    def validate_permission(self, value):
        """Validate the permissions input."""
        split_value = value.split(':')
        split_value_len = len(split_value)
        if split_value_len != 3:
            key = 'format'
            message = 'Permission must be of the format "application:resource_type:operation".'
            error = {
                key: [_(message)]
            }
            raise serializers.ValidationError(error)
        return value

    class Meta:
        """Metadata for the serializer."""

        model = Access
        fields = ('permission', 'resourceDefinitions')


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for the Role model."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True,
                                 max_length=150,
                                 validators=[UniqueValidator(queryset=Role.objects.all())])
    description = serializers.CharField(allow_null=True, required=False)
    access = AccessSerializer(many=True)
    policyCount = serializers.IntegerField(read_only=True)
    applications = serializers.SerializerMethodField()
    system = serializers.BooleanField(read_only=True)
    platform_default = serializers.BooleanField(read_only=True)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Role
        fields = ('uuid', 'name', 'description',
                  'access', 'policyCount',
                  'applications', 'system',
                  'platform_default', 'created',
                  'modified')

    def get_applications(self, obj):
        """Get the list of applications in the role."""
        apps = []
        for access_item in obj.access.all():
            perm_list = access_item.permission.split(':')
            perm_len = len(perm_list)
            if perm_len == 3:
                apps.append(perm_list[0])
        return list(set(apps))

    def create(self, validated_data):
        """Create the role object in the database."""
        name = validated_data.pop('name')
        description = validated_data.pop('description', None)
        access_list = validated_data.pop('access')
        role = Role.objects.create(name=name, description=description)
        role.save()
        for access_item in access_list:
            resource_def_list = access_item.pop('resourceDefinitions')
            access_obj = Access.objects.create(**access_item, role=role)
            access_obj.save()
            for resource_def_item in resource_def_list:
                res_def = ResourceDefinition.objects.create(**resource_def_item, access=access_obj)
                res_def.save()
        return role

    def update(self, instance, validated_data):
        """Update the role object in the database."""
        if instance.system:
            key = 'role.update'
            message = 'System roles may not be updated.'
            error = {
                key: [_(message)]
            }
            raise serializers.ValidationError(error)
        access_list = validated_data.pop('access')
        instance.name = validated_data.get('name', instance.name)
        instance.description = validated_data.get('description', instance.description)
        instance.save()
        instance.access.all().delete()

        for access_item in access_list:
            resource_def_list = access_item.pop('resourceDefinitions')
            access_obj = Access.objects.create(**access_item, role=instance)
            access_obj.save()
            for resource_def_item in resource_def_list:
                res_def = ResourceDefinition.objects.create(**resource_def_item, access=access_obj)
                res_def.save()

        instance.save()
        return instance


class RoleMinimumSerializer(serializers.ModelSerializer):
    """Serializer for the Role model that doesn't return access info."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True, max_length=150)
    description = serializers.CharField(allow_null=True, required=False)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Role
        fields = ('uuid', 'name', 'description', 'created', 'modified')
