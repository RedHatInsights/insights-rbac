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
from management.group.model import Group
from management.serializer_override_mixin import SerializerCreateOverrideMixin
from management.utils import get_principal_from_request
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .model import Access, Permission, ResourceDefinition, Role

ALLOWED_OPERATIONS = ["in", "equal"]
FILTER_FIELDS = set(["key", "value", "operation"])


class ResourceDefinitionSerializer(SerializerCreateOverrideMixin, serializers.ModelSerializer):
    """Serializer for the ResourceDefinition model."""

    attributeFilter = serializers.JSONField()

    def validate_attributeFilter(self, value):
        """Validate the given attributeFilter."""
        if value.keys() != FILTER_FIELDS:
            key = "format"
            message = f"attributeFilter fields must be {FILTER_FIELDS}"
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)

        op = value.get("operation")
        if op not in ALLOWED_OPERATIONS:
            key = "format"
            message = f"attributeFilter operation must be one of {ALLOWED_OPERATIONS}"
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
        return value

    class Meta:
        """Metadata for the serializer."""

        model = ResourceDefinition
        fields = ("attributeFilter",)


class AccessSerializer(SerializerCreateOverrideMixin, serializers.ModelSerializer):
    """Serializer for the Access model."""

    resourceDefinitions = ResourceDefinitionSerializer(many=True)
    permission = serializers.CharField(source="permission.permission")

    def validate_permission(self, value):
        """Validate the permissions input."""
        split_value = value.split(":")
        split_value_len = len(split_value)
        if split_value_len != 3:
            key = "format"
            message = 'Permission must be of the format "application:resource_type:operation".'
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
        return value

    class Meta:
        """Metadata for the serializer."""

        model = Access
        fields = ("resourceDefinitions", "permission")


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for the Role model."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(
        required=True, max_length=150, validators=[UniqueValidator(queryset=Role.objects.all())]
    )
    display_name = serializers.CharField(
        required=False, max_length=150, allow_blank=True, validators=[UniqueValidator(queryset=Role.objects.all())]
    )
    description = serializers.CharField(allow_null=True, required=False)
    access = AccessSerializer(many=True)
    policyCount = serializers.IntegerField(read_only=True)
    accessCount = serializers.IntegerField(read_only=True)
    applications = serializers.SerializerMethodField()
    system = serializers.BooleanField(read_only=True)
    platform_default = serializers.BooleanField(read_only=True)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Role
        fields = (
            "uuid",
            "name",
            "display_name",
            "description",
            "access",
            "policyCount",
            "accessCount",
            "applications",
            "system",
            "platform_default",
            "created",
            "modified",
        )

    def get_applications(self, obj):
        """Get the list of applications in the role."""
        return obtain_applications(obj)

    def create(self, validated_data):
        """Create the role object in the database."""
        name = validated_data.pop("name")
        display_name = validated_data.pop("display_name", name)
        description = validated_data.pop("description", None)
        access_list = validated_data.pop("access")
        tenant = self.context["request"].tenant
        role = Role.objects.create(name=name, description=description, display_name=display_name, tenant=tenant)
        role.save()
        for access_item in access_list:
            resource_def_list = access_item.pop("resourceDefinitions")
            access_permission = access_item.pop("permission")
            permission, created = Permission.objects.get_or_create(**access_permission)

            # NOTE: after we ensure/enforce all object have a tenant_id FK, we can add tenant=tenant
            # to the get_or_create. We cannot currently, because records without would fail the GET
            # and would create duplicate records. This ensures we temporarily do an update if
            # obj.tenant_id is NULL
            if not permission.tenant:
                permission.tenant = tenant
                permission.save()

            access_obj = Access.objects.create(permission=permission, role=role, tenant=tenant)
            for resource_def_item in resource_def_list:
                ResourceDefinition.objects.create(**resource_def_item, access=access_obj, tenant=tenant)
        return role

    def update(self, instance, validated_data):
        """Update the role object in the database."""
        if instance.system:
            key = "role.update"
            message = "System roles may not be updated."
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
        access_list = validated_data.pop("access")
        instance.name = validated_data.get("name", instance.name)
        instance.display_name = validated_data.get("display_name", instance.display_name)
        instance.description = validated_data.get("description", instance.description)
        tenant = self.context["request"].tenant
        instance.save()
        instance.access.all().delete()

        for access_item in access_list:
            resource_def_list = access_item.pop("resourceDefinitions")
            access_permission = access_item.pop("permission")
            permission, created = Permission.objects.get_or_create(**access_permission)

            # NOTE: after we ensure/enforce all object have a tenant_id FK, we can add tenant=tenant
            # to the get_or_create. We cannot currently, because records without would fail the GET
            # and would create duplicate records. This ensures we temporarily do an update if
            # obj.tenant_id is NULL
            if not permission.tenant:
                permission.tenant = tenant
                permission.save()

            access_obj = Access.objects.create(permission=permission, role=instance, tenant=tenant)
            for resource_def_item in resource_def_list:
                ResourceDefinition.objects.create(**resource_def_item, access=access_obj, tenant=tenant)

        instance.save()
        return instance


class RoleMinimumSerializer(SerializerCreateOverrideMixin, serializers.ModelSerializer):
    """Serializer for the Role model that doesn't return access info."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True, max_length=150)
    display_name = serializers.CharField(required=False, max_length=150, allow_blank=True)
    description = serializers.CharField(allow_null=True, required=False)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)
    policyCount = serializers.IntegerField(read_only=True)
    accessCount = serializers.IntegerField(read_only=True)
    applications = serializers.SerializerMethodField()
    system = serializers.BooleanField(read_only=True)
    platform_default = serializers.BooleanField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Role
        fields = (
            "uuid",
            "name",
            "display_name",
            "description",
            "created",
            "modified",
            "policyCount",
            "accessCount",
            "applications",
            "system",
            "platform_default",
        )

    def get_applications(self, obj):
        """Get the list of applications in the role."""
        return obtain_applications(obj)


class DynamicFieldsModelSerializer(SerializerCreateOverrideMixin, serializers.ModelSerializer):
    """A ModelSerializer that controls which fields should be displayed."""

    def __init__(self, *args, **kwargs):
        """Instantiate the serializer."""
        fields = kwargs.pop("fields", None)

        # Instantiate the superclass normally
        super(DynamicFieldsModelSerializer, self).__init__(*args, **kwargs)

        if fields is not None:
            # Drop any fields that are not specified in the `fields` argument.
            allowed = set(fields)
            existing = set(self.fields)
            for field_name in existing - allowed:
                self.fields.pop(field_name)


class RoleDynamicSerializer(DynamicFieldsModelSerializer):
    """Serializer for the Role model that could dynamically return required field."""

    uuid = serializers.UUIDField(read_only=True)
    name = serializers.CharField(required=True, max_length=150)
    display_name = serializers.CharField(required=False, max_length=150, allow_blank=True)
    description = serializers.CharField(allow_null=True, required=False)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)
    policyCount = serializers.IntegerField(read_only=True)
    groups_in = serializers.SerializerMethodField()
    groups_in_count = serializers.SerializerMethodField()
    accessCount = serializers.IntegerField(read_only=True)
    applications = serializers.SerializerMethodField()
    system = serializers.BooleanField(read_only=True)
    platform_default = serializers.BooleanField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Role
        fields = (
            "uuid",
            "name",
            "display_name",
            "description",
            "created",
            "modified",
            "policyCount",
            "groups_in",
            "groups_in_count",
            "accessCount",
            "applications",
            "system",
            "platform_default",
        )

    def get_applications(self, obj):
        """Get the list of applications in the role."""
        return obtain_applications(obj)

    def get_groups_in_count(self, obj):
        """Get the totoal count of groups where the role is in."""
        request = self.context.get("request")
        return obtain_groups_in(obj, request).count()

    def get_groups_in(self, obj):
        """Get the groups where the role is in."""
        request = self.context.get("request")
        return obtain_groups_in(obj, request).values("name", "uuid", "description")


class RolePatchSerializer(RoleSerializer):
    """Serializer for Role patch."""

    access = AccessSerializer(many=True, required=False)
    name = serializers.CharField(
        required=False, max_length=150, validators=[UniqueValidator(queryset=Role.objects.all())]
    )

    def update(self, instance, validated_data):
        """Patch the role object."""
        if instance.system:
            key = "role.update"
            message = "System roles may not be updated."
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
        instance.name = validated_data.get("name", instance.name)
        instance.display_name = validated_data.get("display_name", instance.display_name)
        instance.description = validated_data.get("description", instance.description)
        instance.save()
        return instance


def obtain_applications(obj):
    """Shared function to get the list of applications in the role."""
    apps = []
    for access_item in obj.access.all():
        apps.append(access_item.permission.application)
    return list(set(apps))


def obtain_groups_in(obj, request):
    """Shared function to get the groups the roles is in."""
    scope_param = request.query_params.get("scope")
    username_param = request.query_params.get("username")
    policy_ids = list(obj.policies.values_list("id", flat=True))

    if scope_param == "principal" or username_param:
        principal = get_principal_from_request(request)
        assigned_groups = Group.objects.filter(policies__in=policy_ids, principals__in=[principal])
        return (assigned_groups | Group.platform_default_set()).distinct()

    return Group.objects.filter(policies__in=policy_ids).distinct()
