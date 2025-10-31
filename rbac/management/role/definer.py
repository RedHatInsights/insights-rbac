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
import dataclasses
import json
import logging
import os

from core.utils import destructive_ok
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from management.group.platform import DefaultGroupNotAvailableError, GlobalPolicyIdService
from management.notifications.notification_handlers import role_obj_change_notification_handler
from management.permission.model import Permission
from management.permission.scope_service import ImplicitResourceService, Scope
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.role.model import Access, ExtRoleRelation, ExtTenant, ResourceDefinition, Role
from management.role.platform import platform_v2_role_uuid_for
from management.role.relation_api_dual_write_handler import (
    RelationApiDualWriteHandler,
    SeedingRelationApiDualWriteHandler,
)
from management.role.v2_model import PlatformRoleV2, SeededRoleV2
from management.tenant_mapping.model import DefaultAccessType

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


@dataclasses.dataclass
class _SeedRolesConfig:
    force_create_relationships: bool
    force_update_relationships: bool

    def __post_init__(self):
        if self.force_create_relationships and self.force_update_relationships:
            raise ValueError("force_create_relationships and force_update_relationships cannot both be True")


def _make_role(data, config: _SeedRolesConfig, platform_roles=None):
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
    updated = False

    dual_write_handler = SeedingRelationApiDualWriteHandler(role)
    if created:
        if role.display_name != display_name:
            role.display_name = display_name
            role.save()
        logger.info("Created system role %s.", name)
        role_obj_change_notification_handler(role, "created")
    else:
        if config.force_update_relationships or (role.version != defaults["version"]):
            updated = True
            dual_write_handler.prepare_for_update()
            Role.objects.public_tenant_only().filter(name=name).update(
                **defaults, display_name=display_name, modified=timezone.now()
            )
            logger.info("Updated system role %s.", name)
            role.access.all().delete()
            role_obj_change_notification_handler(role, "updated")
        else:
            if config.force_create_relationships:
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

    assert not (created and updated)

    if created:
        dual_write_handler.replicate_new_system_role()
    elif updated:
        dual_write_handler.replicate_update_system_role()

    _seed_v2_role_from_v1(role, display_name, defaults["description"], public_tenant, platform_roles)

    return role


def _update_or_create_roles(roles, config: _SeedRolesConfig, platform_roles=None):
    """Update or create roles from list."""
    current_role_ids = set()
    for role_json in roles:
        try:
            role = _make_role(role_json, config=config, platform_roles=None)
            current_role_ids.add(role.id)
        except Exception as e:
            logger.error(f"Failed to update or create system role: {role_json.get('name')} " f"with error: {e}")
    return current_role_ids


def seed_roles(force_create_relationships=False, force_update_relationships=False):
    """Update or create system defined roles."""
    roles_directory = os.path.join(settings.BASE_DIR, "management", "role", "definitions")
    role_files = [
        f
        for f in os.listdir(roles_directory)
        if os.path.isfile(os.path.join(roles_directory, f)) and f.endswith(".json")
    ]
    current_role_ids = set()
    platform_roles = _seed_platform_roles()
    with transaction.atomic():
        for role_file_name in role_files:
            role_file_path = os.path.join(roles_directory, role_file_name)
            with open(role_file_path) as json_file:
                data = json.load(json_file)
                role_list = data.get("roles")
                file_role_ids = _update_or_create_roles(
                    role_list,
                    _SeedRolesConfig(
                        force_create_relationships=force_create_relationships,
                        force_update_relationships=force_update_relationships,
                    ),
                    platform_roles,
                )
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


def _seed_v2_role_from_v1(v1_role, display_name, description, public_tenant, platform_roles):
    """Create or update V2 role from V1 role during seeding."""
    try:
        v2_role, v2_created = SeededRoleV2.objects.update_or_create(
            uuid=v1_role.uuid,
            defaults={
                "name": display_name,
                "description": description,
                "tenant": public_tenant,
                "v1_source": v1_role,
            },
        )

        if v2_created:
            logger.info("Created V2 system role %s.", display_name)
        else:
            logger.info("Updated V2 system role %s.", display_name)

        v2_role.permissions.clear()
        v1_permissions = [access.permission for access in v1_role.access.all()]
        if v1_permissions:
            v2_role.permissions.set(v1_permissions)
            logger.info("Added %d permissions to V2 role %s.", len(v1_permissions), display_name)

        resource_service = ImplicitResourceService.from_settings()
        scope = resource_service.scope_for_role(v1_role)

        if v1_role.platform_default:
            platform_role = platform_roles.get((DefaultAccessType.USER, scope))
            if platform_role:
                platform_role.children.add(v2_role)
                logger.info("Added %s as child of platform role %s", display_name, platform_role.name)
            else:
                logger.warning(
                    "Platform role for %s %s scope not available. Skipping child relationship for %s",
                    DefaultAccessType.USER.value,
                    scope.value,
                    display_name,
                )

        if v1_role.admin_default:
            admin_platform_role = platform_roles.get((DefaultAccessType.ADMIN, scope))
            if admin_platform_role:
                admin_platform_role.children.add(v2_role)
                logger.info("Added %s as child of admin platform role %s", display_name, admin_platform_role.name)
            else:
                logger.warning(
                    "Platform role for %s %s scope not available. Skipping child relationship for %s",
                    DefaultAccessType.ADMIN.value,
                    scope.value,
                    display_name,
                )
        return v2_role
    except Exception as e:
        logger.error(f"Failed to seed V2 role for {display_name}: {e}")
        return None


def _seed_platform_roles():
    """Create the 6 platform roles (3 scopes × 2 access types)."""
    public_tenant = Tenant.objects.get(tenant_name="public")
    policy_service = GlobalPolicyIdService.shared()

    platform_roles = {}

    for access_type in [DefaultAccessType.USER, DefaultAccessType.ADMIN]:
        for scope in [Scope.DEFAULT, Scope.ROOT, Scope.TENANT]:
            try:
                uuid = platform_v2_role_uuid_for(access_type, scope, policy_service)

                role_name = f"{access_type.value.capitalize()} {scope.value} Platform Role"
                description = f"Platform default role for {access_type.value} access at {scope.value} scope"

                platform_role, created = PlatformRoleV2.objects.update_or_create(
                    uuid=uuid,
                    defaults={
                        "name": role_name,
                        "description": description,
                        "tenant": public_tenant,
                    },
                )

                if created:
                    logger.info("Created platform role: %s", role_name)
                else:
                    logger.info("Updated platform role: %s", role_name)

                platform_roles[(access_type, scope)] = platform_role
            except DefaultGroupNotAvailableError:
                logger.warning(
                    "Default groups may not exist yet during seeding. "
                    "Skipping platform role creation for %s %s scope",
                    access_type.value,
                    scope.value,
                )

    return platform_roles
