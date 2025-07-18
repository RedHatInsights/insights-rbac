"""
Copyright 2019 Red Hat, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import dataclasses
import logging
import uuid
from typing import Any, Iterable, Optional, Tuple, Union

from django.conf import settings
from management.models import BindingMapping, Group, Role, RoleBinding, RoleV2, Workspace
from management.permission.model import Permission
from migration_tool.ingest import add_element
from migration_tool.models import (
    V2boundresource,
    V2role,
    cleanNameForV2SchemaCompatibility,
)


logger = logging.getLogger(__name__)

PermissionGroupings = dict[V2boundresource, set[Permission]]


def add_system_role(system_roles, role: V2role):
    """Add a system role to the system role map."""
    system_roles[frozenset(role.permissions)] = role


def inventory_to_workspace(v2_perm):
    """Convert inventory permissions to workspace permissions."""
    if v2_perm == "inventory_groups_read":
        return "workspace_read"
    elif v2_perm == "inventory_groups_write":
        return "workspace_write"
    elif v2_perm == "inventory_groups_all":
        return "workspace_all"
    return v2_perm


class SystemRole:
    """A system role."""

    SYSTEM_ROLES: dict[frozenset[str], V2role] = {}

    @classmethod
    def get_system_roles(cls):
        """Get the system roles, if empty, set them."""
        if not cls.SYSTEM_ROLES:
            cls.set_system_roles()
        return cls.SYSTEM_ROLES

    @classmethod
    def set_system_roles(cls):
        """Set the system roles."""
        for role in Role.objects.public_tenant_only():
            # Skip roles such as OCM since they don't have permission
            if role.external_role_id():
                continue
            cls.set_system_role(role)

    @classmethod
    def set_system_role(cls, role):
        """Set the system role."""
        permission_list = list()
        for access in role.access.all():
            v2_perm = cleanNameForV2SchemaCompatibility(access.permission.permission)
            v2_perm = inventory_to_workspace(v2_perm)
            permission_list.append(v2_perm)
        add_system_role(cls.SYSTEM_ROLES, V2role(str(role.uuid), True, frozenset(permission_list)))


@dataclasses.dataclass
class MigrateRoleModelsResult:
    binding_mappings: list[BindingMapping]
    role_bindings: list[RoleBinding]
    v2_roles: list[RoleV2]


def v1_role_to_v2_bindings(
    v1_role: Role,
    default_workspace: Workspace,
    role_bindings: Iterable[BindingMapping],
) -> MigrateRoleModelsResult:
    """Convert a V1 role to a set of V2 role bindings."""
    from internal.utils import get_or_create_ungrouped_workspace

    perm_groupings: PermissionGroupings = {}

    # Group V2 permissions by target resource
    for access in v1_role.access.all():
        permission = access.permission

        if not is_for_enabled_app(permission):
            continue

        default = True
        for resource_def in access.resourceDefinitions.all():
            default = False
            attri_filter = resource_def.attributeFilter

            # Deal with some malformed data in db
            if attri_filter["operation"] == "in":
                if not isinstance(attri_filter["value"], list):
                    # Override operation as "equal" if value is not a list
                    attri_filter["operation"] = "equal"
                elif attri_filter["value"] == []:
                    # Skip empty values
                    continue

            resource_type = attribute_key_to_v2_related_resource_type(attri_filter["key"])
            if resource_type is None:
                # Resource type not mapped to v2
                continue
            if not is_for_enabled_resource(resource_type):
                continue
            for resource_id in values_from_attribute_filter(attri_filter):
                if resource_id is None:
                    if resource_type != ("rbac", "workspace"):
                        raise ValueError(f"Resource ID is None for {resource_def}")
                    if settings.REMOVE_NULL_VALUE:
                        ungrouped_ws = get_or_create_ungrouped_workspace(v1_role.tenant)
                        resource_id = str(ungrouped_ws.id)
                    else:
                        continue
                add_element(perm_groupings, V2boundresource(resource_type, resource_id), permission, collection=set)
        if default:
            add_element(
                perm_groupings,
                V2boundresource(("rbac", "workspace"), str(default_workspace.id)),
                permission,
                collection=set,
            )

    # Project permission sets to roles per set of resources
    return _permission_groupings_to_v2_role_bindings(perm_groupings, v1_role, role_bindings)


def _get_or_create_v2_custom_role_from_v1(
    v2_id: Optional[str], v1_role: Role, permissions: frozenset[Permission]
) -> RoleV2:
    if v1_role.system or v1_role.tenant.tenant_name == "public":
        raise ValueError(f"Expected v1 role not to be system role; got id {v1_role.id}")

    # TODO: Replace this with a more meaningful name. This is a bit tricky because we need to avoid conflicts.

    name = f"{v1_role.uuid}: {uuid.uuid4()}"

    role_args = {
        "tenant": v1_role.tenant,
        "name": name,
        "display_name": name,
        "description": v1_role.description,
        "type": RoleV2.Types.CUSTOM,
    }

    if v2_id is not None:
        # We need to handle the case where v2_id is specified but the object does not exist. This can occur if this
        # ID was generated before the RoleV2 model was added.
        new_role, _ = RoleV2.objects.update_or_create(
            id=v2_id,
            defaults=role_args,
        )
    else:
        new_role = RoleV2.objects.create(**role_args)

    new_role.permissions.set(permissions)

    return new_role


def _get_or_create_v2_role_binding(
    v2_id: Optional[str], v2_role: RoleV2, resource: V2boundresource, groups: list[Group]
) -> RoleBinding:
    binding_args = {
        "tenant": v2_role.tenant,
        "role": v2_role,
        "resource_type_namespace": resource.resource_type[0],
        "resource_type_name": resource.resource_type[1],
        "resource_id": resource.resource_id,
    }

    if v2_id is not None:
        # Similarly to above, handle the case where an ID is passed, but the object does not exist.
        new_binding, _ = RoleBinding.objects.update_or_create(
            id=v2_id,
            defaults=binding_args,
        )
    else:
        new_binding = RoleBinding.objects.create(**binding_args)

    new_binding.groups.set(groups)

    return new_binding


def _permission_groupings_to_v2_role_bindings(
    perm_groupings: PermissionGroupings, v1_role: Role, role_bindings: Iterable[BindingMapping]
) -> MigrateRoleModelsResult:
    """Determine updated role bindings based on latest resource-permission state and current role bindings."""
    updated_mappings: list[BindingMapping] = []
    updated_role_bindings: list[RoleBinding] = []

    updated_roles: list[RoleV2] = []
    updated_role_ids: set[str] = set()
    updated_roles_by_permissions: dict[frozenset[Permission], RoleV2] = {}

    # TODO: this is broken for system roles, need to have Tenant or Policies provided
    # so that we don't look up Policies across all Tenants!
    latest_groups = [policy.group for policy in v1_role.policies.all()]

    role_bindings_by_resource = {binding.get_role_binding().resource: binding for binding in role_bindings}

    for resource, permissions in perm_groupings.items():
        mapping = role_bindings_by_resource.get(resource)
        current = mapping.get_role_binding() if mapping is not None else None
        perm_set = frozenset(permissions)

        if mapping is not None and current is None:
            raise ValueError(f"Current role binding is None for {mapping}")

        # Try to find an updated Role that matches (could be our current Role)
        new_role = updated_roles_by_permissions.get(perm_set)

        if new_role is None:
            # Is there a current role? Should update it? Only if it wasn't already updated.
            reused_role_id = (
                current.role.id if current is not None and current.role.id not in updated_role_ids else None
            )

            new_role = _get_or_create_v2_custom_role_from_v1(
                v2_id=reused_role_id,
                v1_role=v1_role,
                permissions=perm_set,
            )

        reused_binding_id = current.id if current is not None else None

        updated_binding = _get_or_create_v2_role_binding(
            v2_id=reused_binding_id,
            v2_role=new_role,
            resource=resource,
            groups=latest_groups,
        )

        # Add the role binding, reusing the existing one if possible.
        if mapping is None:
            updated_mapping = BindingMapping.for_role_binding(updated_binding.as_migration_rolebinding(), v1_role)
        else:
            updated_mapping = mapping
            updated_mapping.update_mappings_from_role_binding(updated_binding.as_migration_rolebinding())

        updated_mapping.save()

        updated_mappings.append(updated_mapping)
        updated_role_bindings.append(updated_binding)

        assert perm_set == frozenset(new_role.permissions.all())

        updated_roles.append(new_role)
        updated_role_ids.add(str(new_role.id))
        updated_roles_by_permissions[perm_set] = new_role

    return MigrateRoleModelsResult(
        binding_mappings=updated_mappings,
        role_bindings=updated_role_bindings,
        v2_roles=updated_roles,
    )


def is_for_enabled_app(perm: Permission):
    """Return true if the permission is for an app that should migrate."""
    return perm.application not in settings.V2_MIGRATION_APP_EXCLUDE_LIST


def is_for_enabled_resource(resource: Tuple[str, str]):
    """
    Return true if the resource is for an app that should migrate.

    This setting is used when the permission is valid for V2 but the resource model is not yet finalized.
    It excludes role bindings for those specific resources, and only migrates those which are bound
    at the workspace level.

    Once the resource model is finalized, we should no longer exclude that app, and should instead update
    the migration code to account for migrating those resources in whatever form they should migrate.
    """
    return f"{resource[0]}:{resource[1]}" not in settings.V2_MIGRATION_RESOURCE_EXCLUDE_LIST


def values_from_attribute_filter(attribute_filter: dict[str, Any]) -> list[str]:
    """Split a resource definition into a list of resource IDs."""
    op: str = attribute_filter["operation"]
    resource_id: Union[list[str], str] = attribute_filter["value"]

    if isinstance(resource_id, list):
        return resource_id

    return resource_id.split(",") if op == "in" else [resource_id]


V2_RESOURCE_BY_ATTRIBUTE = {"group.id": ("rbac", "workspace")}


def attribute_key_to_v2_related_resource_type(resourceType: str) -> Optional[Tuple[str, str]]:
    """Convert a V1 resource type to a V2 resource type."""
    if resourceType in V2_RESOURCE_BY_ATTRIBUTE:
        return V2_RESOURCE_BY_ATTRIBUTE[resourceType]
    return None
