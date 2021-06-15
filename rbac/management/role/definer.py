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

"""Handler for system defined roles."""
import json
import logging
import os

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from management.permission.model import Permission
from management.role.model import Access, ResourceDefinition, Role
from tenant_schemas.utils import tenant_context

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def _make_role(tenant, data):
    """Create the role object in the database."""
    name = data.pop("name")
    display_name = data.get("display_name", name)
    access_list = data.get("access")
    defaults = dict(
        description=data.get("description", None),
        system=True,
        version=data.get("version", 1),
        platform_default=data.get("platform_default", False),
    )
    role, created = Role.objects.get_or_create(name=name, defaults=defaults)

    # NOTE: after we ensure/enforce all object have a tenant_id FK, we can add tenant=tenant
    # to the get_or_create. We cannot currently, because records without would fail the GET
    # and would create duplicate records. This ensures we temporarily do an update if
    # obj.tenant_id is NULL
    if not role.tenant:
        role.tenant = tenant
        role.save()

    if created:
        if role.display_name != display_name:
            role.display_name = display_name
            role.save()
        logger.info("Created role %s for tenant %s.", name, tenant.schema_name)
    else:
        if role.version != defaults["version"]:
            Role.objects.filter(name=name).update(**defaults, display_name=display_name, modified=timezone.now())
            logger.info("Updated role %s for tenant %s.", name, tenant.schema_name)
            role.access.all().delete()
        else:
            logger.info("No change in role %s for tenant %s", name, tenant.schema_name)
            return role
    for access_item in access_list:
        resource_def_list = access_item.pop("resourceDefinitions", [])
        permission, created = Permission.objects.get_or_create(**access_item)

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


def _update_or_create_roles(tenant, roles):
    """Update or create roles from list."""
    current_role_ids = set()
    for role_json in roles:
        try:
            role = _make_role(tenant, role_json)
            current_role_ids.add(role.id)
        except Exception as e:
            logger.error(
                f"Failed to update or create role: {role_json.get('name')} "
                f"for tenant: {tenant.schema_name} with error: {e}"
            )
    return current_role_ids


def seed_roles(tenant):
    """For a tenant update or create system defined roles."""
    roles_directory = os.path.join(settings.BASE_DIR, "management", "role", "definitions")
    role_files = [
        f
        for f in os.listdir(roles_directory)
        if os.path.isfile(os.path.join(roles_directory, f)) and f.endswith(".json")
    ]
    current_role_ids = set()
    with tenant_context(tenant):
        with transaction.atomic():
            for role_file_name in role_files:
                role_file_path = os.path.join(roles_directory, role_file_name)
                with open(role_file_path) as json_file:
                    data = json.load(json_file)
                    role_list = data.get("roles")
                    file_role_ids = _update_or_create_roles(tenant, role_list)
                    current_role_ids.update(file_role_ids)

        roles_to_delete = Role.objects.filter(system=True).exclude(id__in=current_role_ids)
        logger.info(
            f"The following '{roles_to_delete.count()}' roles(s) eligible for removal: {roles_to_delete.values()}"
        )
        # Currently read-only to ensure we don't have any orphaned roles which should be added to the config
        # Role.objects.filter(system=True).exclude(id__in=current_role_ids).delete()
    return tenant


def seed_permissions(tenant):
    """For a tenant update or create defined permissions."""
    permission_directory = os.path.join(settings.BASE_DIR, "management", "role", "permissions")
    permission_files = [
        f
        for f in os.listdir(permission_directory)
        if os.path.isfile(os.path.join(permission_directory, f)) and f.endswith(".json")
    ]
    current_permission_ids = set()

    with tenant_context(tenant):
        with transaction.atomic():
            for permission_file_name in permission_files:
                permission_file_path = os.path.join(permission_directory, permission_file_name)
                app_name = os.path.splitext(permission_file_name)[0]
                with open(permission_file_path) as json_file:
                    data = json.load(json_file)
                    for resource, operation_objects in data.items():
                        try:
                            for operation_object in operation_objects:
                                # There are some old configs, e.g., cost-management still stay in CI
                                if not isinstance(operation_object, str):
                                    permission_description = operation_object.get("description", "")
                                    operation = operation_object.get("verb")
                                    permission, created = Permission.objects.update_or_create(
                                        permission=f"{app_name}:{resource}:{operation}",
                                        defaults={"description": permission_description},
                                    )
                                else:
                                    permission, created = Permission.objects.update_or_create(
                                        permission=f"{app_name}:{resource}:{operation_object}"
                                    )
                                # NOTE: after we ensure/enforce all object have a tenant_id FK, we can add tenant=tenant
                                # to the get_or_create. We cannot currently, because records without would fail the GET
                                # and would create duplicate records. This ensures we temporarily do an update if
                                # obj.tenant_id is NULL
                                if not permission.tenant:
                                    permission.tenant = tenant
                                    permission.save()
                                if created:
                                    logger.info(
                                        f"Created permission {permission.permission} "
                                        f"for tenant {tenant.schema_name}."
                                    )
                                current_permission_ids.add(permission.id)
                        except Exception as e:
                            logger.error(
                                f"Failed to update or create permissions for: "
                                f"{app_name}:{resource} for tenant: {tenant.schema_name} with error: {e}"
                            )
        perms_to_delete = Permission.objects.exclude(id__in=current_permission_ids)
        logger.info(
            f"The following '{perms_to_delete.count()}' permission(s) eligible for removal: {perms_to_delete.values()}"
        )
        # Currently read-only to ensure we don't have any orphaned permissions which should be added to the config
        # Permission.objects.exclude(id__in=current_permission_ids).delete()
    return tenant
