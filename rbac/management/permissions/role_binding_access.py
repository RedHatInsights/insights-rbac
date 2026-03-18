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

from feature_flags import FEATURE_FLAGS
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

    Checks if the user has the appropriate permission on a resource using the
    Kessel Inventory API via WorkspaceInventoryAccessChecker.

    Relation selection by operation and resource_type:
    - tenant: list/retrieve -> rbac_assignments_read, create/update -> rbac_assignments_write
    - workspace (and other types): create -> role_binding_grant, update -> role_binding_grant AND
      role_binding_revoke (both required), list/retrieve -> role_binding_view (or view when
      feature flag disabled)

    This permission class should be used after RoleBindingSystemUserAccessPermission
    which handles system user denial logic.
    """

    # Relations for workspace (non-tenant) resources
    ROLE_BINDING_VIEW_RELATION = "role_binding_view"
    ROLE_BINDING_GRANT_RELATION = "role_binding_grant"
    ROLE_BINDING_REVOKE_RELATION = "role_binding_revoke"
    # Fallback relation when feature flag is disabled (general permission)
    VIEW_RELATION = "view"

    # Relations for tenant resources
    TENANT_READ_RELATION = "rbac_assignments_read"
    TENANT_WRITE_RELATION = "rbac_assignments_write"

    # Allowlist of valid resource types for role binding access checks
    ALLOWED_RESOURCE_TYPES = {"workspace", "tenant"}

    # Actions that map to create/update operations for relation selection
    CREATE_ACTIONS = {"batch_create"}
    UPDATE_ACTIONS = {"by_subject"}  # by_subject with PUT

    def _get_operation(self, view) -> str:
        """Determine the operation from the view (create, update, or list)."""
        action = getattr(view, "action", None)
        if action in self.CREATE_ACTIONS:
            return "create"
        if action in self.UPDATE_ACTIONS:
            request = getattr(view, "request", None)
            if request and getattr(request, "method", None) == "PUT":
                return "update"
        return "list"  # list, by_subject GET, etc.

    def _get_relations(self, resource_type: str, view) -> list[str]:
        """Get the relation(s) to check based on resource_type and view action.

        Returns a list; for update operations on workspace, both grant and revoke are required.
        """
        operation = self._get_operation(view)

        if resource_type == "tenant":
            if operation in ("create", "update"):
                return [self.TENANT_WRITE_RELATION]
            return [self.TENANT_READ_RELATION]

        # workspace and other resource types
        if operation == "create":
            return [self.ROLE_BINDING_GRANT_RELATION]
        if operation == "update":
            return [self.ROLE_BINDING_GRANT_RELATION, self.ROLE_BINDING_REVOKE_RELATION]
        # list/retrieve
        if FEATURE_FLAGS.is_use_role_binding_view_permission_enabled():
            return [self.ROLE_BINDING_VIEW_RELATION]
        return [self.VIEW_RELATION]

    def _get_resource_params(self, request, view) -> tuple[str, str]:
        """Extract resource_id and resource_type from request (query params or body)."""
        resource_id = request.query_params.get("resource_id", "").replace("\x00", "")
        resource_type = request.query_params.get("resource_type", "").replace("\x00", "").lower()

        # For batch_create, resource info is in request body
        if not resource_id and view.action == "batch_create":
            requests_data = request.data.get("requests") or []
            if requests_data:
                first_resource = requests_data[0].get("resource") or {}
                resource_id = str(first_resource.get("id", ""))
                resource_type = (first_resource.get("type") or "").lower()

        return resource_id, resource_type

    def has_permission(self, request, view):
        """
        Check if the user has permission to access role bindings for a resource.

        Args:
            request: The HTTP request object
            view: The view being accessed

        Returns:
            bool: True if the user has permission, False otherwise
        """
        resource_id, resource_type = self._get_resource_params(request, view)

        # If no resource_id or resource_type provided, let view validation handle it
        if not resource_id or not resource_type:
            return True

        # Validate resource_type against allowlist and fail closed on unknown types
        if resource_type not in self.ALLOWED_RESOURCE_TYPES:
            logger.debug("Denied access for unknown resource_type: %s", resource_type)
            return False

        # Get principal_id for Kessel API check using the reusable utility
        principal_id = get_kessel_principal_id(request)
        if not principal_id:
            return False

        # Use WorkspaceInventoryAccessChecker for the Kessel permission check
        relations = self._get_relations(resource_type, view)
        checker = WorkspaceInventoryAccessChecker()
        return all(
            checker.check_resource_access(
                resource_type=resource_type,
                resource_id=resource_id,
                principal_id=principal_id,
                relation=relation,
            )
            for relation in relations
        )
