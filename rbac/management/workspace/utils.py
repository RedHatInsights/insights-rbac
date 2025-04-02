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
from uuid import UUID
from rest_framework.serializers import ValidationError


from management.role.model import Access
from management.utils import roles_for_principal
from management.workspace.model import Workspace


def is_user_allowed(request, required_operation, target_workspace):
    """Check if the user is allowed to perform the required permission on the target workspace."""
    default_workspace_id = str(Workspace.objects.get(request.tenant, type=Workspace.Types.DEFAULT).id)
    if target_workspace is None:
        # If the target workspace is not provided, check if the user has the required permission
        # on any workspace.
        target_workspace = default_workspace_id
    if required_operation == "read":
        allowed_operations = ["read", "write", "*"]
    else:
        allowed_operations = ["write", "*"]
    valid_perm_tuples = [(f"inventory:groups:{allowed_operation}", target_workspace) for allowed_operation in allowed_operations]
    tuple_set = workspace_permission_tuple_set(request, default_workspace_id)
    return any(valid_perm_tuple in tuple_set for valid_perm_tuple in valid_perm_tuples)

def get_access_permission_tuples(access, tenant, default_workspace_id):
    """Get the set of permission tuples for the given access."""
    group_list = _get_group_list_from_resource_definition(access.resourceDefinition)
    if group_list:
        workspaces = Workspace.objects.filter(tenant=tenant, id__in=group_list)
        return {
            (access.permission.permission, descendant)
            for workspace in workspaces
            for descendant in workspace.get_all_descendant_ids()
        }
    return {(access.permission.permission, default_workspace_id)}

def workspace_permission_tuple_set(request, default_workspace_id):
    """Get the set of permission tuples for the user's roles on the workspace."""
    principal = principal.objects.get(username=request.user.username, tenant=request.tenant)
    roles = roles_for_principal(
        principal,
        request.tenant,
        {
            "prefetch_lookups_for_ids": "resourceDefinitions",
            "prefetch_lookups_for_groups": "policies__roles__access",
            "is_org_admin": request.user.admin,
        }
    )
    accesses = Access.objects.filter(
        role__in=roles,
        permission__application="inventory",
        permission__resource_type="groups"
    )
    tuple_set = set()
    for access in accesses:
        tuple_set |= get_access_permission_tuples(access, request.tenant, default_workspace_id)
    return tuple_set

# Validate RBAC response, and fetch
def _get_group_list_from_resource_definition(resource_definition: dict) -> list[str]:
    """Get the list of group IDs from the resource definition."""
    attribute_filter = resource_definition.get("attributeFilter")
    if not attribute_filter:
        return []
    if attribute_filter.get("key") != "group.id":
        raise ValidationError("Invalid value for attributeFilter.key.")
    if attribute_filter.get("operation") not in ["in", "euqal"]:
        raise ValidationError("Invalid value for attributeFilter.operation.")

    value = attribute_filter.get("value")
    group_list = value if isinstance(value, list) else [value]
    try:
        for gid in group_list:
            if gid is not None:
                UUID(gid)
    except (ValueError, TypeError):
        raise ValidationError("Invalid UUIDs for attributeFilter.value.")
    return group_list
