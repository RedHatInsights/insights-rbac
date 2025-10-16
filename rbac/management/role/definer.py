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

from core.utils import destructive_ok
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from management.group.model import Group
from management.notifications.notification_handlers import role_obj_change_notification_handler
from management.permission.model import Permission
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.role.model import Access, ExtRoleRelation, ExtTenant, ResourceDefinition, Role
from management.role.relation_api_dual_write_handler import (
    RelationApiDualWriteHandler,
    SeedingRelationApiDualWriteHandler,
)
from management.role.v2_model import CustomRoleV2, PlatformRoleV2, RoleBinding, RoleBindingGroup, RoleV2, SeededRoleV2

from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def _add_ext_relation_if_it_exists(external_relation, role):
    if not external_relation:
        return

    ext_id = external_relation.get("id")
    ext_tenant_name = external_relation.get("tenant")

    if hasattr(role, "ext_relation"):
        pre_relation = role.ext_relation
        # If the role already has same external relation, no-op
        if pre_relation and pre_relation.ext_id == ext_id and pre_relation.ext_tenant.name == ext_tenant_name:
            return
        else:
            pre_relation.delete()

    ext_tenant, created = ExtTenant.objects.get_or_create(name=ext_tenant_name)
    if created:
        logger.info("Created external tenant %s.", ext_tenant_name)

    defaults = dict(ext_tenant=ext_tenant, role=role)
    _, created = ExtRoleRelation.objects.update_or_create(ext_id=ext_id, defaults=defaults)

    logger.info(
        "Added external relationships %s of external tenant %s to role %s.", ext_id, ext_tenant_name, role.name
    )


def _make_role(data, force_create_relationships=False):
    """Create the role object in the database."""
    public_tenant = Tenant.objects.get(tenant_name="public")
    name = data.pop("name")
    display_name = data.get("display_name", name)
    access_list = data.get("access")
    defaults = dict(
        description=data.get("description", None),
        system=True,
        version=data.get("version", 1),
        platform_default=data.get("platform_default", False),
        admin_default=data.get("admin_default", False),
    )
    role, created = Role.objects.get_or_create(name=name, defaults=defaults, tenant=public_tenant)

    dual_write_handler = SeedingRelationApiDualWriteHandler(role)
    if created:
        if role.display_name != display_name:
            role.display_name = display_name
            role.save()
        logger.info("Created system role %s.", name)
        role_obj_change_notification_handler(role, "created")
    else:
        if role.version != defaults["version"]:
            dual_write_handler.prepare_for_update()
            Role.objects.public_tenant_only().filter(name=name).update(
                **defaults, display_name=display_name, modified=timezone.now()
            )
            logger.info("Updated system role %s.", name)
            role.access.all().delete()
            role_obj_change_notification_handler(role, "updated")
        else:
            if force_create_relationships:
                dual_write_handler.replicate_new_system_role()
                logger.info("Replicated system role %s", name)
                return role
            logger.info("No change in system role %s", name)
            return role

    if access_list:  # Allow external roles to have none access object
        for access_item in access_list:
            resource_def_list = access_item.pop("resourceDefinitions", [])
            permission, _ = Permission.objects.get_or_create(**access_item, tenant=public_tenant)

            access_obj = Access.objects.create(permission=permission, role=role, tenant=public_tenant)
            for resource_def_item in resource_def_list:
                ResourceDefinition.objects.create(**resource_def_item, access=access_obj, tenant=public_tenant)

    _add_ext_relation_if_it_exists(data.get("external"), role)

    if created:
        dual_write_handler.replicate_new_system_role()
    else:
        if role.version != defaults["version"]:
            dual_write_handler.replicate_update_system_role()

    return role


def _update_or_create_roles(roles, force_create_relationships=False):
    """Update or create roles from list (for V1 or V2)."""
    current_role_ids = set()
    for role_json in roles:
        try:
            if "type" in role_json:
                role = _make_v2_role(role_json)
            else:
                role = _make_role(role_json, force_create_relationships)
            current_role_ids.add(role.id)
        except Exception as e:
            logger.error(f"Failed to update or create system role: {role_json.get('name')} " f"with error: {e}")
    return current_role_ids


def seed_roles(force_create_relationships=False):
    """Update or create system defined roles."""
    roles_directory = os.path.join(settings.BASE_DIR, "management", "role", "definitions")
    role_files = [
        f
        for f in os.listdir(roles_directory)
        if os.path.isfile(os.path.join(roles_directory, f)) and f.endswith(".json")
    ]
    current_role_ids = set()
    with transaction.atomic():
        for role_file_name in role_files:
            role_file_path = os.path.join(roles_directory, role_file_name)
            with open(role_file_path) as json_file:
                data = json.load(json_file)
                role_list = data.get("roles")
                if role_list is None:
                    logger.info(f"Skipping {role_file_name} - no 'roles' key found")
                    continue
                file_role_ids = _update_or_create_roles(role_list, force_create_relationships)
                current_role_ids.update(file_role_ids)

    # Find roles in DB but not in config
    roles_to_delete = Role.objects.public_tenant_only().exclude(id__in=current_role_ids)
    logger.info(f"The following '{roles_to_delete.count()}' roles(s) eligible for removal: {roles_to_delete.values()}")
    if destructive_ok("seeding"):
        logger.info(f"Removing the following role(s): {roles_to_delete.values()}")
        # Actually remove roles no longer in config
        with transaction.atomic():
            for role in roles_to_delete:
                dual_write_handler = SeedingRelationApiDualWriteHandler(role)
                dual_write_handler.replicate_deleted_system_role()
            roles_to_delete.delete()


def seed_permissions():
    """Update or create defined permissions."""
    public_tenant = Tenant.objects.get(tenant_name="public")

    permission_directory = os.path.join(settings.BASE_DIR, "management", "role", "permissions")
    permission_files = [
        f
        for f in os.listdir(permission_directory)
        if os.path.isfile(os.path.join(permission_directory, f)) and f.endswith(".json")
    ]
    current_permission_ids = set()

    for permission_file_name in permission_files:
        permission_file_path = os.path.join(permission_directory, permission_file_name)
        app_name = os.path.splitext(permission_file_name)[0]
        with open(permission_file_path) as json_file:
            data = json.load(json_file)
            for resource, operation_objects in data.items():
                try:
                    with transaction.atomic():
                        for operation_object in operation_objects:
                            # There are some old configs, e.g., cost-management still stay in CI
                            if not isinstance(operation_object, str):
                                permission_description = operation_object.get("description", "")
                                operation = operation_object.get("verb")
                                permission, created = Permission.objects.update_or_create(
                                    permission=f"{app_name}:{resource}:{operation}",
                                    defaults={"description": permission_description},
                                    tenant=public_tenant,
                                )
                            else:
                                permission, created = Permission.objects.update_or_create(
                                    permission=f"{app_name}:{resource}:{operation_object}", tenant=public_tenant
                                )
                            if created:
                                logger.info(f"Created permission {permission.permission}.")
                            current_permission_ids.add(permission.id)

                        # need to iterate over the objects with requirements AFTER all perms are created
                        operation_objects_with_requires = [obj for obj in operation_objects if "requires" in obj]
                        for operation_object in operation_objects_with_requires:
                            if not isinstance(operation_object, str):
                                required_verbs = operation_object.get("requires")
                                verb = operation_object.get("verb")
                                permission = Permission.objects.get(permission=f"{app_name}:{resource}:{verb}")
                                required_permissions = Permission.objects.filter(
                                    application=app_name, resource_type=resource, verb__in=required_verbs
                                ).exclude(id=permission.id)
                                permission.permissions.add(*required_permissions)
                except Exception as e:
                    logger.error(
                        f"Failed to update or create permissions for: " f"{app_name}:{resource} with error: {e}"
                    )
    # Find perms in DB but not in config
    perms_to_delete = Permission.objects.exclude(id__in=current_permission_ids)
    logger.info(
        f"The following '{perms_to_delete.count()}' permission(s) eligible for removal: {perms_to_delete.values()}"
    )
    if destructive_ok("seeding"):
        logger.info(f"Removing the following permissions(s): {perms_to_delete.values()}")
        # Actually remove perms no longer in DB
        with transaction.atomic():
            for permission in perms_to_delete:
                delete_permission(permission)


def delete_permission(permission: Permission):
    """Delete a permission and handles relations cleanning."""
    roles = Role.objects.filter(access__permission=permission).distinct()
    dual_write_handlers = []
    for role in roles:
        role = Role.objects.filter(id=role.id).select_for_update().get()
        dual_write_handler = (
            SeedingRelationApiDualWriteHandler(role=role)
            if role.system
            else RelationApiDualWriteHandler(role, ReplicationEventType.UPDATE_CUSTOM_ROLE)
        )
        dual_write_handler.prepare_for_update()
        dual_write_handlers.append(dual_write_handler)
    permission.delete()
    for dual_write_handler in dual_write_handlers:
        role = dual_write_handler.role
        if isinstance(dual_write_handler, SeedingRelationApiDualWriteHandler):
            dual_write_handler.replicate_update_system_role()
        else:
            dual_write_handler.replicate_new_or_updated_role(role)


def _make_v2_role(data):
    """Create the v2 role object in the database."""
    public_tenant = Tenant.objects.get(tenant_name="public")
    name = data.pop("name")
    role_type = data.pop("type")
    description = data.get("description", None)
    permissions_list = data.get("permissions", [])
    children_list = data.get("children", [])

    # Map type string to model class
    model_type = {
        "platform": PlatformRoleV2,
        "custom": CustomRoleV2,
        "seeded": SeededRoleV2,
    }

    model_class = model_type.get(role_type)
    if not model_class:
        raise ValueError(f"Invalid role type: {role_type}. Must be one of: {list(model_type.keys())}")

    # Create or get the role
    role, created = model_class.objects.get_or_create(name=name, description=description, tenant=public_tenant)

    if created:
        logger.info("Created v2 %s role: %s", role_type, name)
    else:
        # Update description if changed
        if role.description != description:
            role.description = description
            role.save()
            logger.info("Updated v2 %s role: %s", role_type, name)
        else:
            logger.info("No change in v2 %s role: %s", role_type, name)

    # Handle permissions - clear existing and add new ones
    if permissions_list:
        role.permissions.clear()
        for perm_string in permissions_list:
            permission, _ = Permission.objects.get_or_create(permission=perm_string, tenant=public_tenant)
            role.permissions.add(permission)
        logger.info("Added %d permissions to role %s", len(permissions_list), name)

    # Handle children - lookup child roles by name and add them
    if children_list:
        role.children.clear()
        for child_name in children_list:
            try:
                child_role = RoleV2.objects.get(name=child_name, tenant=public_tenant)
                role.children.add(child_role)
            except RoleV2.DoesNotExist:
                logger.warning(
                    f"Child role '{child_name}' not found for parent '{name}'. Will be added when child is created."
                )
        logger.info("Added %d children to role %s", role.children.count(), name)

    return role


def seed_v2_roles():
    """Update or create V2 roles types."""
    roles_file = os.path.join(settings.BASE_DIR, "management", "role", "definitions", "rbac_v2_roles_local_test.json")
    if not os.path.isfile(roles_file):
        raise FileNotFoundError(f"Roles file does not exist: {roles_file}")

    current_role_ids = set()
    with transaction.atomic():
        with open(roles_file) as json_file:
            data = json.load(json_file)
            role_list = data.get("roles")
            if role_list is None:
                logger.warning(f"No 'roles' key found in {roles_file}")
                return
            file_role_ids = _update_or_create_roles(role_list)
            current_role_ids.update(file_role_ids)


def _make_role_binding(data):
    """Create the role binding object in the database."""
    public_tenant = Tenant.objects.get(tenant_name="public")
    name = data.get("name")
    role_name = data.get("role")
    resource_type = data.get("resource_type")
    resource_id = data.get("resource_id")

    # Get the V2 role to add to role binding
    try:
        role = RoleV2.objects.get(name=role_name, tenant=public_tenant)
    except RoleV2.DoesNotExist:
        logger.error(f"Role '{role_name}' not found for role binding '{name}'. Skipping.")
        return None

    # Create the role binding object
    role_binding, created = RoleBinding.objects.get_or_create(
        role=role, resource_type=resource_type, resource_id=resource_id, tenant=public_tenant
    )

    if created:
        logger.info("Created role binding '%s': %s -> %s/%s", name, role.name, resource_type, resource_id)
    else:
        logger.info("Role binding '%s' already exists: %s -> %s/%s", name, role.name, resource_type, resource_id)

    return role_binding


def _update_or_create_role_bindings(bindings):
    """Update or create role bindings from list."""
    current_binding_ids = set()
    binding_name_map = {}
    for binding_data in bindings:
        try:
            role_binding = _make_role_binding(binding_data)
            if role_binding:
                current_binding_ids.add(role_binding.id)
                binding_name_map[binding_data.get("name")] = role_binding
        except Exception as e:
            logger.error(f"Failed to update or create role binding: {binding_data.get('name')} with error: {e}")
    return current_binding_ids, binding_name_map


def seed_role_bindings():
    """Update or create V2 role bindings types."""
    role_bindings_file = os.path.join(
        settings.BASE_DIR, "management", "role", "definitions", "rbac_v2_role_bindings_local_test.json"
    )
    if not os.path.isfile(role_bindings_file):
        raise FileNotFoundError(f"Role bindings file does not exist: {role_bindings_file}")

    current_role_bindings = set()
    binding_name_map = {}

    with transaction.atomic():
        with open(role_bindings_file) as json_file:
            data = json.load(json_file)
            role_bindings_list = data.get("role_bindings")
            if role_bindings_list is None:
                logger.warning(f"No 'role_bindings' key found in {role_bindings_file}")
                return {}
            file_role_bindings, binding_name_map = _update_or_create_role_bindings(role_bindings_list)
            current_role_bindings.update(file_role_bindings)

    return binding_name_map


def _make_role_binding_group(binding, group):
    """Create a role binding group entry linking a binding to a group."""
    # Create the role binding group entry
    role_binding_group, created = RoleBindingGroup.objects.get_or_create(binding=binding, group=group)

    if created:
        logger.info("Created role binding group entry: binding=%s, group=%s", binding.uuid, group.name)
    else:
        logger.info("Role binding group entry already exists: binding=%s, group=%s", binding.uuid, group.name)

    return role_binding_group


def _update_or_create_role_binding_groups(binding_groups_data, binding_name_map):
    """Update or create role binding groups from list."""
    public_tenant = Tenant.objects.get(tenant_name="public")
    current_binding_group_ids = set()

    for binding_group in binding_groups_data:
        binding_name = binding_group.get("binding")
        group_names = binding_group.get("groups", [])

        # Look up the binding by name
        binding = binding_name_map.get(binding_name)
        if not binding:
            logger.error(
                f"Role binding '{binding_name}' not found in binding map. "
                f"Skipping {len(group_names)} group assignment(s) for this binding."
            )
            continue

        # For each group, create the binding group entry
        for group_name in group_names:
            try:
                # Get the group
                group = Group.objects.get(name=group_name, tenant=public_tenant)

                role_binding_group = _make_role_binding_group(binding, group)
                if role_binding_group:
                    current_binding_group_ids.add(role_binding_group.id)

            except Group.DoesNotExist:
                logger.warning(
                    f"Group '{group_name}' not found for binding '{binding_name}'. "
                    f"Will be added when group is created."
                )
            except Exception as e:
                logger.error(
                    f"Failed to create role binding group for binding '{binding_name}' "
                    f"and group '{group_name}' with error: {e}"
                )

    return current_binding_group_ids


def seed_role_binding_groups():
    """Update or create V2 role binding groups."""
    public_tenant = Tenant.objects.get(tenant_name="public")

    role_bindings_file = os.path.join(
        settings.BASE_DIR, "management", "role", "definitions", "rbac_v2_role_bindings_local_test.json"
    )
    role_binding_groups_file = os.path.join(
        settings.BASE_DIR, "management", "role", "definitions", "rbac_v2_role_binding_groups_local_test.json"
    )

    if not os.path.isfile(role_bindings_file):
        raise FileNotFoundError(f"Role bindings file does not exist: {role_bindings_file}")
    if not os.path.isfile(role_binding_groups_file):
        raise FileNotFoundError(f"Role binding groups file does not exist: {role_binding_groups_file}")

    # Build binding name map from existing bindings in database
    binding_name_map = {}
    with open(role_bindings_file) as json_file:
        data = json.load(json_file)
        role_bindings_list = data.get("role_bindings", [])

        for binding_data in role_bindings_list:
            name = binding_data.get("name")
            role_name = binding_data.get("role")
            resource_type = binding_data.get("resource_type")
            resource_id = binding_data.get("resource_id")

            try:
                role = RoleV2.objects.get(name=role_name, tenant=public_tenant)
                binding = RoleBinding.objects.get(
                    role=role, resource_type=resource_type, resource_id=resource_id, tenant=public_tenant
                )
                binding_name_map[name] = binding
            except (RoleV2.DoesNotExist, RoleBinding.DoesNotExist) as e:
                logger.warning(
                    f"Role binding '{name}' not found in database: {e.__class__.__name__}. "
                    f"Make sure role bindings are seeded before role binding groups."
                )

    current_binding_groups = set()

    with transaction.atomic():
        with open(role_binding_groups_file) as json_file:
            data = json.load(json_file)
            binding_groups_list = data.get("role_binding_groups")
            if binding_groups_list is None:
                logger.warning(f"No 'role_binding_groups' key found in {role_binding_groups_file}")
                return
            logger.info(f"Processing {len(binding_groups_list)} role binding group entries from config file")
            file_binding_groups = _update_or_create_role_binding_groups(binding_groups_list, binding_name_map)
            current_binding_groups.update(file_binding_groups)
            logger.info(f"Created/updated {len(current_binding_groups)} role binding group entries")
