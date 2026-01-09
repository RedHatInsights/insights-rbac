#
# Copyright 2025 Red Hat, Inc.
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

"""Role binding access permissions using Kessel Inventory API."""

import logging

from management.permissions.workspace_inventory_access import (
    WorkspaceInventoryAccessChecker,
)
from management.principal.proxy import get_kessel_principal_id
from rest_framework import permissions

logger = logging.getLogger(__name__)


def _is_system_user_without_admin(user) -> bool:
    """
    Check if user is a system user without admin privileges.

    Args:
        user: The user object from the request

    Returns:
        bool: True if user is system but not admin, False otherwise
    """
    is_system = getattr(user, "system", False)
    is_admin = getattr(user, "admin", False)
    return is_system and not is_admin


class RoleBindingSystemUserAccessPermission(permissions.BasePermission):
    """
    Permission class for system user access to role bindings.

    Checks if system users (s2s communication) have proper access.
    Non-admin system users are denied.
    All other users (including admins) pass through to next permission class.
    """

    def has_permission(self, request, view):
        """
        Check if user has access based on system user status.

        Args:
            request: The HTTP request object
            view: The view being accessed

        Returns:
            bool: True to pass through to next permission, False if denied
        """
        user = request.user

        # System users without admin are denied
        if _is_system_user_without_admin(user):
            return False

        # All other users pass through to next permission class (Kessel check)
        return True


class RoleBindingKesselAccessPermission(permissions.BasePermission):
    """
    Permission class for role binding access using Kessel Inventory API.

    Checks if the user has role_binding_view permission on a resource
    using the Kessel Inventory API via WorkspaceInventoryAccessChecker.

    This permission class should be used after RoleBindingSystemUserAccessPermission
    which handles system user denial logic.
    """

    # Relation to check for role binding access
    ROLE_BINDING_VIEW_RELATION = "role_binding_view"

    # Allowlist of valid resource types for role binding access checks
    ALLOWED_RESOURCE_TYPES = {"workspace", "rbac/workspace"}

    def has_permission(self, request, view):
        """
        Check if the user has permission to view role bindings for a resource.

        Args:
            request: The HTTP request object
            view: The view being accessed

        Returns:
            bool: True if the user has permission, False otherwise
        """
        # Get resource_id and resource_type from query params (for by-subject endpoint)
        resource_id = request.query_params.get("resource_id", "").replace("\x00", "")
        resource_type = request.query_params.get("resource_type", "").replace("\x00", "").lower()

        # If no resource_id or resource_type provided, let view validation handle it
        if not resource_id or not resource_type:
            return True

        # Normalize and validate resource_type against allowlist and fail closed on unknown types
        if resource_type not in self.ALLOWED_RESOURCE_TYPES:
            logger.debug("Denied access for unknown resource_type: %s", resource_type)
            return False
        if resource_type == "rbac/workspace":
            resource_type = "workspace"

        # Get principal_id for Kessel API check using the reusable utility
        principal_id = get_kessel_principal_id(request)
        if not principal_id:
            return False

        # Use WorkspaceInventoryAccessChecker for the Kessel permission check
        checker = WorkspaceInventoryAccessChecker()
        return checker.check_resource_access(
            resource_type=resource_type,
            resource_id=resource_id,
            principal_id=principal_id,
            relation=self.ROLE_BINDING_VIEW_RELATION,
        )
