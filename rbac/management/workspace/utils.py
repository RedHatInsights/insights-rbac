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
"""Utils for workspace model."""
from uuid import UUID

from django.conf import settings
from management.models import Access, Workspace
from management.utils import get_principal_from_request, roles_for_principal
from rest_framework.serializers import ValidationError


def is_user_allowed(request, required_operation, target_workspace):
    """Check if the user is allowed to perform the required permission on the target workspace."""
    root_workspace_id = str(Workspace.objects.root(tenant_id=request.tenant).id)
    is_get_action = request.method == "GET"
    if target_workspace is None:
        # If the target workspace is not provided, check if the user has the required permission
        # on any workspace.
        target_workspace = root_workspace_id
    if required_operation == "read":
        allowed_operations = ["read", "write", "*"]
    else:
        allowed_operations = ["write", "*"]
    valid_perm_tuples = [
        (f"inventory:groups:{allowed_operation}", target_workspace) for allowed_operation in allowed_operations
    ]
    tuple_set = workspace_permission_tuple_set(request, root_workspace_id, is_get_action)
    if is_get_action:
        # Get the set of permission tuples for later filter
        request.permission_tuples = tuple_set
    return any(valid_perm_tuple in tuple_set for valid_perm_tuple in valid_perm_tuples)


def get_access_permission_tuples(access, tenant, root_workspace_id, is_get_action):
    """Get the set of permission tuples for the given access."""
    group_list = _get_group_list_from_resource_definitions(access.resourceDefinitions.all()) or [root_workspace_id]
    workspaces = Workspace.objects.filter(tenant=tenant, id__in=group_list)
    tuple_set = set()
    for workspace in workspaces:
        for descendant in Workspace.objects.descendant_ids_with_parents([str(workspace.id)], workspace.tenant_id):
            tuple_set.add((access.permission.permission, descendant))
        if is_get_action:
            # Allow getting ancestors for a workspace they have access to
            for ancestor in workspace.ancestors():
                tuple_set.add((access.permission.permission, str(ancestor.id)))
    return tuple_set


def workspace_permission_tuple_set(request, root_workspace_id, is_get_action):
    """Get the set of permission tuples for the user's roles on the workspace."""
    principal = get_principal_from_request(request)
    roles = roles_for_principal(
        principal,
        request.tenant,
        **{
            "prefetch_lookups_for_ids": "resourceDefinitions",
            "prefetch_lookups_for_groups": "policies__roles__access",
            "is_org_admin": request.user.admin,
        },
    )
    accesses = Access.objects.filter(
        role__in=roles, permission__application="inventory", permission__resource_type="groups"
    )
    tuple_set = set()
    for access in accesses:
        tuple_set |= get_access_permission_tuples(access, request.tenant, root_workspace_id, is_get_action)
    return tuple_set


# Validate RBAC response, and fetch
def _get_group_list_from_resource_definitions(resource_definitions: dict) -> list[str]:
    """Get the list of group IDs from the resource definition."""
    group_list = []
    for resource_definition in resource_definitions:
        attribute_filter = resource_definition.attributeFilter
        if not attribute_filter:
            continue
        if attribute_filter.get("key") != "group.id":
            raise ValidationError("Invalid value for attributeFilter.key.")
        if attribute_filter.get("operation") not in ["in", "equal"]:
            raise ValidationError("Invalid value for attributeFilter.operation.")

        value = attribute_filter.get("value")
        if isinstance(value, list):
            group_list.extend(value)
        else:
            group_list.append(value)
    for gid in group_list:
        if gid is None:
            continue
        try:
            UUID(gid)
        except (ValueError, TypeError):
            group_list.remove(gid)
    return group_list


def check_total_workspace_count_exceeded(tenant) -> bool:
    """Check if the current org has exceeded the allowed amount of workspaces.

    Returns True if total number of workspaces is exceeded.
    """
    org = tenant
    max_limit = settings.WORKSPACE_ORG_CREATION_LIMIT

    workspace_count = Workspace.objects.filter(tenant=org, type="standard").count()
    return workspace_count >= max_limit
