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
from rest_framework import serializers

from .model import Access, ResourceDefinition, Role


class ResourceDefinitionSerializer(serializers.ModelSerializer):
    """Serializer for the ResourceDefinition model."""

    class Meta:
        """Metadata for the serializer."""

        model = ResourceDefinition
        fields = ('attributeFilter',)


class AccessSerializer(serializers.ModelSerializer):
    """Serializer for the Access model."""

    resourceDefinitions = ResourceDefinitionSerializer(many=True)

    class Meta:
        """Metadata for the serializer."""

        model = Access
        fields = ('permission', 'resourceDefinitions')


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for the Role model."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True, max_length=150)
    description = serializers.CharField(allow_null=True, required=False)
    access = AccessSerializer(many=True)

    class Meta:
        """Metadata for the serializer."""

        model = Role
        fields = ('uuid', 'name', 'description', 'access')

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

    class Meta:
        """Metadata for the serializer."""

        model = Role
        fields = ('uuid', 'name', 'description')
