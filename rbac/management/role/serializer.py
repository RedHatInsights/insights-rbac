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
from django.conf import settings
from django.utils.translation import gettext as _
from management.models import Group, Workspace
from management.serializer_override_mixin import SerializerCreateOverrideMixin
from management.utils import filter_queryset_by_tenant, get_principal, validate_and_get_key
from rest_framework import serializers

from api.models import Tenant
from .model import Access, BindingMapping, Permission, ResourceDefinition, Role
from ..querysets import ORG_ID_SCOPE, PRINCIPAL_SCOPE, SCOPE_KEY, VALID_SCOPES

ALLOWED_OPERATIONS = ["in", "equal"]
FILTER_FIELDS = {"key", "value", "operation"}


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

    def to_representation(self, instance):
        """Representation of ResourceDefinitions."""
        data = super().to_representation(instance)
        if self._is_workspace_filter(instance):
            data.get("attributeFilter").update({"value": self._workspace_descendant_ids(instance)})
        return data

    def _is_workspace_filter(self, instance):
        is_inventory_permission = instance.application == settings.WORKSPACE_APPLICATION_NAME
        is_inventory_group_filter = instance.attributeFilter.get("key") == settings.WORKSPACE_ATTRIBUTE_FILTER
        return is_inventory_permission and is_inventory_group_filter

    def _workspace_descendant_ids(self, instance):
        workspace_ids = instance.attributeFilter.get("value")
        workspaces = Workspace.objects.filter(id__in=workspace_ids).only("id")
        all_descendant_ids = set()
        for workspace in workspaces:
            descendant_queryset = workspace.descendants().values_list("id", flat=True)
            descendant_ids = list(map(str, descendant_queryset))
            all_descendant_ids.update(descendant_ids)
        return list(set(workspace_ids) | set(all_descendant_ids))


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
    name = serializers.CharField(required=True, max_length=150)
    display_name = serializers.CharField(required=False, max_length=150, allow_blank=True)
    description = serializers.CharField(allow_null=True, required=False)
    access = AccessSerializer(many=True)
    policyCount = serializers.IntegerField(read_only=True)
    accessCount = serializers.IntegerField(read_only=True)
    applications = serializers.SerializerMethodField()
    system = serializers.BooleanField(read_only=True)
    platform_default = serializers.BooleanField(read_only=True)
    admin_default = serializers.BooleanField(read_only=True)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)
    external_role_id = serializers.SerializerMethodField()
    external_tenant = serializers.SerializerMethodField()

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
            "admin_default",
            "created",
            "modified",
            "external_role_id",
            "external_tenant",
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
        create_access_for_role(role, access_list, tenant)

        return role

    def update(self, instance, validated_data):
        """Update the role object in the database."""
        access_list = validated_data.pop("access")
        tenant = self.context["request"].tenant

        instance = update_role(instance, validated_data)

        create_access_for_role(instance, access_list, tenant)

        return instance

    def get_external_role_id(self, obj):
        """Get the external role id if it's from an external tenant."""
        return obj.external_role_id()

    def get_external_tenant(self, obj):
        """Get the external tenant name if it's from an external tenant."""
        return obj.external_tenant_name()

    def validate(self, data):
        """Validate the input data of role."""
        if self.instance and self.instance.system:
            key = "role.update"
            message = "System roles may not be updated."
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
        return super().validate(data)


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
    admin_default = serializers.BooleanField(read_only=True)
    external_role_id = serializers.SerializerMethodField()
    external_tenant = serializers.SerializerMethodField()

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
            "admin_default",
            "external_role_id",
            "external_tenant",
        )

    def get_applications(self, obj):
        """Get the list of applications in the role."""
        return obtain_applications(obj)

    def get_external_role_id(self, obj):
        """Get the external role id if it's from an external tenant."""
        return obj.external_role_id()

    def get_external_tenant(self, obj):
        """Get the external tenant name if it's from an external tenant."""
        return obj.external_tenant_name()


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
    access = AccessSerializer(many=True)
    applications = serializers.SerializerMethodField()
    system = serializers.BooleanField(read_only=True)
    platform_default = serializers.BooleanField(read_only=True)
    admin_default = serializers.BooleanField(read_only=True)
    external_role_id = serializers.SerializerMethodField()
    external_tenant = serializers.SerializerMethodField()

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
            "access",
            "applications",
            "system",
            "platform_default",
            "admin_default",
            "external_role_id",
            "external_tenant",
        )

    def get_applications(self, obj):
        """Get the list of applications in the role."""
        return obtain_applications(obj)

    def get_groups_in_count(self, obj):
        """Get the total count of groups where the role is in."""
        request = self.context.get("request")
        return obtain_groups_in(obj, request).count()

    def get_groups_in(self, obj):
        """Get the groups where the role is in."""
        request = self.context.get("request")
        return obtain_groups_in(obj, request).values("name", "uuid", "description")

    def get_external_role_id(self, obj):
        """Get the external role id if it's from an external tenant."""
        return obj.external_role_id()

    def get_external_tenant(self, obj):
        """Get the external tenant name if it's from an external tenant."""
        return obj.external_tenant_name()


class RolePatchSerializer(RoleSerializer):
    """Serializer for Role patch."""

    access = AccessSerializer(many=True, required=False)
    name = serializers.CharField(required=False, max_length=150)

    def update(self, instance, validated_data):
        """Patch the role object."""
        instance = update_role(instance, validated_data, clear_access=False)
        return instance

    def validate(self, data):
        """Validate the input data of patching role."""
        if self.instance.system:
            key = "role.update"
            message = "System roles may not be updated."
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
        return super().validate(data)


class BindingMappingSerializer(serializers.ModelSerializer):
    """Serializer for the binding mapping."""

    class Meta:
        """Metadata for the serializer."""

        model = BindingMapping
        fields = "__all__"


def obtain_applications(obj):
    """Shared function to get the list of applications in the role."""
    apps = []
    for access_item in obj.access.all():
        apps.append(access_item.permission.application)
    return list(set(apps))


def obtain_groups_in(obj, request):
    """Shared function to get the groups the roles is in."""
    scope_param = validate_and_get_key(request.query_params, SCOPE_KEY, VALID_SCOPES, ORG_ID_SCOPE)
    username_param = request.query_params.get("username")
    policy_ids = list(obj.policies.values_list("id", flat=True))

    if scope_param == PRINCIPAL_SCOPE or username_param:
        principal = get_principal(username_param or request.user.username, request)
        assigned_groups = Group.objects.filter(policies__in=policy_ids, principals__in=[principal])
        assigned_groups = filter_queryset_by_tenant(assigned_groups, request.tenant)
    else:
        assigned_groups = filter_queryset_by_tenant(Group.objects.filter(policies__in=policy_ids), request.tenant)

    public_tenant = Tenant.objects.get(tenant_name="public")

    platform_default_groups = Group.platform_default_set().filter(tenant=request.tenant).filter(
        policies__in=policy_ids
    ) or Group.platform_default_set().filter(tenant=public_tenant).filter(policies__in=policy_ids)

    if username_param and scope_param != PRINCIPAL_SCOPE:
        is_org_admin = request.user_from_query.admin
    else:
        is_org_admin = request.user.admin

    qs = assigned_groups | platform_default_groups

    if is_org_admin:
        admin_default_groups = Group.admin_default_set().filter(tenant=request.tenant).filter(
            policies__in=policy_ids
        ) or Group.admin_default_set().filter(tenant=public_tenant).filter(policies__in=policy_ids)

        qs = qs | admin_default_groups

    return qs.distinct()


def create_access_for_role(role, access_list, tenant):
    """Create access objects and relate it to role."""
    for access_item in access_list:
        resource_def_list = access_item.get("resourceDefinitions")
        access_permission = access_item.get("permission")
        permission = Permission.objects.get(**access_permission)

        access_obj = Access.objects.create(permission=permission, role=role, tenant=tenant)
        for resource_def_item in resource_def_list:
            ResourceDefinition.objects.create(**resource_def_item, access=access_obj, tenant=tenant)


def update_role(instance, validated_data, clear_access=True):
    """Update role attribute."""
    update_fields = []

    for field_name in ["name", "display_name", "description"]:
        if field_name not in validated_data:
            continue
        setattr(instance, field_name, validated_data[field_name])
        update_fields.append(field_name)

    instance.save(update_fields=update_fields)

    if clear_access:
        instance.access.all().delete()

    return instance
