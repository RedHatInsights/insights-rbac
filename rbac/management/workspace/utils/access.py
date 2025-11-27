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
"""Workspace access checking utilities."""
import logging
from uuid import UUID

from feature_flags import FEATURE_FLAGS
from management.models import Access, Workspace
from management.permissions.workspace_inventory_access import (
    WorkspaceInventoryAccessChecker,
)
from management.principal.model import Principal
from management.utils import get_principal_from_request, roles_for_principal
from rest_framework.serializers import ValidationError

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def filter_top_level_workspaces(queryset):
    """
    Filter workspaces to return only top-level ones.

    A workspace is top-level if none of its ancestors are in the queryset.
    Algorithm:
    - Let S be the set of workspaces in queryset
    - For each workspace w in S, check its ancestors
    - If none of w's ancestors are in S, then w is top-level

    Args:
        queryset: QuerySet of workspaces to filter

    Returns:
        QuerySet: Filtered queryset containing only top-level workspaces
    """
    accessible_workspaces = list(queryset)
    accessible_ids_set = {str(ws.id) for ws in accessible_workspaces}
    top_level_workspaces = []

    for workspace in accessible_workspaces:
        # Check if any of this workspace's ancestors are in the accessible set
        ancestor_ids = {str(ancestor.id) for ancestor in workspace.ancestors()}
        # If none of the ancestors are in accessible set, this is a top-level workspace
        if not (ancestor_ids & accessible_ids_set):
            top_level_workspaces.append(workspace)

    # Return a filtered queryset containing only top-level workspaces
    top_level_ids = [ws.id for ws in top_level_workspaces]
    return queryset.filter(id__in=top_level_ids)


def is_user_allowed(request, required_operation, target_workspace):
    """
    Check if the user is allowed to perform the required permission on the target workspace.

    This function handles V1/V2 feature flag branching for compatibility with
    code that calls it directly (outside of WorkspaceAccessPermission).
    For new code, prefer using WorkspaceAccessPermission as the single entry point.

    Args:
        request: The HTTP request object
        required_operation: The operation to check
            - For V1: "read" or "write"
            - For V2: "view", "create", "edit", "move", "delete"
        target_workspace: The workspace ID to check, or None for list operations

    Returns:
        bool: True if the user has permission, False otherwise
    """
    if FEATURE_FLAGS.is_workspace_access_check_v2_enabled():
        return is_user_allowed_v2(request, required_operation, target_workspace)
    return is_user_allowed_v1(request, required_operation, target_workspace)


def is_user_allowed_v1(request, required_operation, target_workspace):
    """
    Check if the user is allowed using V1 workspace access logic.

    This is the legacy implementation using direct role/permission checks.
    Use WorkspaceAccessPermission for the main entry point which handles
    V1/V2 feature flag branching.

    Args:
        request: The HTTP request object
        required_operation: The operation to check ("read" or "write")
        target_workspace: The workspace ID to check, or None for list operations

    Returns:
        bool: True if the user has permission, False otherwise
    """
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
    valid_perm_tuples = set()
    for valid_resource in ["groups", "*"]:
        for valid_operation in allowed_operations:
            valid_perm_tuples.add((f"inventory:{valid_resource}:{valid_operation}", target_workspace))
    tuple_set = workspace_permission_tuple_set(request, root_workspace_id, is_get_action)

    if is_get_action:
        # Get the set of permission tuples for later filter
        request.permission_tuples = tuple_set
    return any(valid_perm_tuple in tuple_set for valid_perm_tuple in valid_perm_tuples)


def is_user_allowed_v2(request, required_operation, target_workspace):
    """
    Check if the user is allowed to perform the required permission on the target workspace using Inventory API.

    This is the v2 implementation using Inventory API for permission checks.

    Args:
        request: The HTTP request object
        required_operation: The operation/relation to check (view, create, edit, move, delete)
        target_workspace: The workspace ID to check, or None for list operations

    Returns:
        bool: True if the user has permission, False otherwise
    """
    # Derive user_id from principal or fall back to BOP (request.user.user_id)
    principal = get_principal_from_request(request)
    if principal is not None:
        user_id = principal.user_id
    elif user_id := getattr(request.user, "user_id", None):
        logger.debug("Using user_id from BOP to construct principal_id")
    else:
        logger.warning("No user_id available from principal or BOP, denying access")
        return False

    # Format principal ID as required by Inventory API (e.g., "localhost/username")
    principal_id = Principal.user_id_to_principal_resource_id(user_id)

    # Create the Inventory API checker
    checker = WorkspaceInventoryAccessChecker()

    # Use the required_operation directly (already determined by permission_from_request)
    relation = required_operation

    # For list operations (None workspace_id), get all accessible workspaces
    if target_workspace is None:
        # Lookup accessible workspaces using StreamedListObjects
        accessible_workspace_ids = checker.lookup_accessible_workspaces(principal_id=principal_id, relation=relation)

        # Convert to set of UUIDs for proper filtering
        accessible_workspace_ids = set(accessible_workspace_ids)

        if accessible_workspace_ids:
            # Add ancestors only from the top-level workspace(s) in accessible workspaces (for ancestry needs)
            # Get workspace objects for accessible IDs
            accessible_workspaces = Workspace.objects.filter(id__in=accessible_workspace_ids, tenant=request.tenant)

            # Find the top-level workspace(s) - those that are not children of any other accessible workspace
            top_level_workspaces = filter_top_level_workspaces(accessible_workspaces)

            for workspace in top_level_workspaces:
                # Add ancestors directly for this top-level workspace
                ancestor_ids = {str(ancestor.id) for ancestor in workspace.ancestors()}
                accessible_workspace_ids.update(ancestor_ids)
        else:
            # If no accessible workspaces, attach at least default and ungrouped workspace
            default_workspace = Workspace.objects.filter(tenant=request.tenant, type=Workspace.Types.DEFAULT).first()
            ungrouped_workspace = Workspace.objects.filter(
                tenant=request.tenant, type=Workspace.Types.UNGROUPED_HOSTS
            ).first()

            if default_workspace:
                accessible_workspace_ids.add(str(default_workspace.id))
            if ungrouped_workspace:
                accessible_workspace_ids.add(str(ungrouped_workspace.id))

        # Store permission tuples for later filtering
        request.permission_tuples = [(None, ws_id) for ws_id in accessible_workspace_ids]
        return bool(accessible_workspace_ids)

    # For specific workspace operations, check access for that workspace
    return checker.check_workspace_access(workspace_id=target_workspace, principal_id=principal_id, relation=relation)


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
        role__in=roles,
        permission__application="inventory",
        permission__resource_type__in=["groups", "*"],
    )
    tuple_set = set()
    for access in accesses:
        tuple_set |= get_access_permission_tuples(access, request.tenant, root_workspace_id, is_get_action)
    return tuple_set


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

    # Build new list of valid UUIDs instead of modifying during iteration
    valid_group_list = []
    for gid in group_list:
        if gid is None:
            continue
        try:
            UUID(gid)
            valid_group_list.append(gid)
        except (ValueError, TypeError):
            # Skip invalid UUIDs
            pass

    return valid_group_list
