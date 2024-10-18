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

import logging
import uuid
from typing import Any, Iterable, Optional, Tuple, Union

from django.conf import settings
from management.models import BindingMapping, Workspace
from management.permission.model import Permission
from management.role.model import Role
from migration_tool.ingest import add_element
from migration_tool.models import (
    V2boundresource,
    V2role,
    V2rolebinding,
    cleanNameForV2SchemaCompatibility,
)

logger = logging.getLogger(__name__)

PermissionGroupings = dict[V2boundresource, set[str]]


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
        for role in Role.objects.filter(system=True):
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


def v1_role_to_v2_bindings(
    v1_role: Role,
    default_workspace: Workspace,
    role_bindings: Iterable[BindingMapping],
) -> list[BindingMapping]:
    """Convert a V1 role to a set of V2 role bindings."""
    perm_groupings: PermissionGroupings = {}

    # Group V2 permissions by target resource
    for access in v1_role.access.all():
        v1_perm = access.permission

        if not is_for_enabled_app(v1_perm):
            continue

        v2_perm = v1_perm_to_v2_perm(v1_perm)

        default = True
        for resource_def in access.resourceDefinitions.all():
            default = False
            attri_filter = resource_def.attributeFilter

            # Deal with some malformed data in db
            if attri_filter["operation"] == "in":
                if not isinstance(attri_filter["value"], list):
                    # Override operation as "equal" if value is not a list
                    attri_filter["operation"] = "equal"
                elif attri_filter["value"] == [] or attri_filter["value"] == [None]:
                    # Skip empty values
                    continue

            resource_type = attribute_key_to_v2_related_resource_type(attri_filter["key"])
            if resource_type is None:
                # Resource type not mapped to v2
                continue
            if not is_for_enabled_resource(resource_type):
                continue
            for resource_id in values_from_attribute_filter(attri_filter):
                # TODO: Need to bind against "ungrouped hosts" for inventory
                if resource_id is None:
                    raise ValueError(f"Resource ID is None for {resource_def}")
                add_element(perm_groupings, V2boundresource(resource_type, resource_id), v2_perm, collection=set)
        if default:
            add_element(
                perm_groupings,
                V2boundresource(("rbac", "workspace"), str(default_workspace.uuid)),
                v2_perm,
                collection=set,
            )

    # Project permission sets to roles per set of resources
    return permission_groupings_to_v2_role_bindings(perm_groupings, v1_role, role_bindings)


def permission_groupings_to_v2_role_bindings(
    perm_groupings: PermissionGroupings, v1_role: Role, role_bindings: Iterable[BindingMapping]
) -> list[BindingMapping]:
    """Determine updated role bindings based on latest resource-permission state and current role bindings."""
    updated_mappings: list[BindingMapping] = []
    latest_roles_by_id: dict[str, V2role] = {}
    # TODO: this is broken for system roles, need to have Tenant or Policies provided
    # so that we don't look up Policies across all Tenants!
    latest_groups = frozenset([str(policy.group.uuid) for policy in v1_role.policies.all()])

    role_bindings_by_resource = {binding.get_role_binding().resource: binding for binding in role_bindings}

    for resource, permissions in perm_groupings.items():
        mapping = role_bindings_by_resource.get(resource)
        current = mapping.get_role_binding() if mapping is not None else None
        perm_set = frozenset(permissions)
        new_role: Optional[V2role] = None

        # Try to find an updated Role that matches (could be our current Role)
        for _, role in latest_roles_by_id.items():
            if role.permissions == perm_set:
                new_role = role
                break

        if new_role is None:
            # No updated Role matches. We need a new or reconfigured Role.
            # Is there a current role? Should update it? Only if it wasn't already updated.
            if current is not None and current.role.id not in latest_roles_by_id:
                new_role = V2role(current.role.id, False, perm_set)
            else:
                # Need to create a new role
                id = str(uuid.uuid4())
                new_role = V2role(id, False, perm_set)
            latest_roles_by_id[new_role.id] = new_role

        # Add the role binding, updating or creating as needed.
        if mapping is None:
            # No existing binding for this resource, have to create one
            id = str(uuid.uuid4())
            binding = V2rolebinding(id, new_role, resource, latest_groups)
            updated_mapping = BindingMapping.for_role_binding(binding, v1_role)
        else:
            # Reuse current binding ID and mapping ID
            if current is None:
                raise ValueError(f"Current role binding is None for {mapping}")
            binding = V2rolebinding(current.id, new_role, resource, latest_groups)
            updated_mapping = mapping
            updated_mapping.update_mappings_from_role_binding(binding)

        updated_mappings.append(updated_mapping)

    return updated_mappings


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


def v1_perm_to_v2_perm(v1_permission: Permission):
    """Convert a V1 permission to a V2 permission."""
    if v1_permission.application == "inventory" and v1_permission.resource_type == "groups":
        return cleanNameForV2SchemaCompatibility(f"workspace_{v1_permission.verb}")
    return cleanNameForV2SchemaCompatibility(
        v1_permission.application + "_" + v1_permission.resource_type + "_" + v1_permission.verb
    )


V2_RESOURCE_BY_ATTRIBUTE = {"group.id": ("rbac", "workspace")}


def attribute_key_to_v2_related_resource_type(resourceType: str) -> Optional[Tuple[str, str]]:
    """Convert a V1 resource type to a V2 resource type."""
    if resourceType in V2_RESOURCE_BY_ATTRIBUTE:
        return V2_RESOURCE_BY_ATTRIBUTE[resourceType]
    return None
