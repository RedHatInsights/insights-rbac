#
# Copyright 2024 Red Hat, Inc.
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
"""Defines the Workspace Access Permissions class."""

from feature_flags import FEATURE_FLAGS
from management.workspace.utils import (
    is_user_allowed_v1,
    is_user_allowed_v2,
    operation_from_request,
    permission_from_request,
    workspace_from_request,
)
from rest_framework import permissions

# Custom message for target workspace access denial
TARGET_WORKSPACE_ACCESS_DENIED_MESSAGE = (
    "You do not have write access to the target workspace."
)


class WorkspaceAccessPermission(permissions.BasePermission):
    """
    Workspace access permission checker.

    This is the single entry point for workspace access control, handling
    the V1/V2 feature flag branching in one place.
    """

    def has_permission(self, request, view):
        """
        Check if the user has permission to access the workspace.

        Handles V1/V2 feature flag branching:
        - V2: Uses Inventory API with fine-grained permissions (view, create, edit, move, delete)
        - V1: Uses legacy role-based checks with read/write operations

        For move operations, this method checks both:
        - Source workspace: user needs 'move' permission (V2) or 'write' operation (V1)
        - Target workspace: user needs 'create' permission (V2) or 'write' operation (V1)

        Args:
            request: The HTTP request object
            view: The view being accessed

        Returns:
            bool: True if the user has permission, False otherwise
        """
        # Get the permission/operation and target workspace
        perm = permission_from_request(request, view)
        ws_id = workspace_from_request(request, view)

        # Branch based on feature flag - this is the ONLY place this check should occur
        if FEATURE_FLAGS.is_workspace_access_check_v2_enabled():
            # V2: Use Inventory API with fine-grained permissions
            # V2 relies solely on accessible workspaces from Inventory API
            if not is_user_allowed_v2(request, perm, ws_id):
                return False

            # For move operations, also check target workspace access
            if view.action == "move":
                return self._check_move_target_access_v2(request)

            return True

        # V1: Use legacy role-based checks with read/write operations
        # Admin users have full access, but for move operations they still need
        # the target workspace to exist within their tenant
        if request.user.admin:
            if view.action == "move":
                return self._check_move_target_exists_v1(request)
            return True

        op = operation_from_request(request)
        if not is_user_allowed_v1(request, op, ws_id):
            return False

        # For move operations, also check target workspace access (V1 non-admin only)
        if view.action == "move":
            return self._check_move_target_access_v1(request)

        return True

    def _get_target_workspace_id(self, request) -> str | None:
        """
        Get and validate the target workspace ID from request body.

        Aligns with the view's source of truth: only reads from request.data (POST body).
        The view's _parent_id_query_param_validation uses request.data.get("parent_id"),
        so we must use the same source to ensure consistent security enforcement.

        Args:
            request: The HTTP request object

        Returns:
            str: The valid UUID string, or None if missing/invalid (let validation handle it)
        """
        import uuid

        # Only check request.data (POST body) - aligns with view's source of truth
        target_workspace_id = request.data.get("parent_id")
        if not target_workspace_id:
            return None

        # Validate it's a valid UUID - if not, let the view's validation handle it
        try:
            uuid.UUID(str(target_workspace_id))
            return str(target_workspace_id)
        except (ValueError, AttributeError):
            return None

    def _check_move_target_access_v2(self, request) -> bool:
        """
        Check target workspace access for move operations in V2 mode.

        In V2, we use the Inventory API to check if the user has 'create' permission
        on the target workspace (from SpiceDB schema: create, view, edit, move, delete).

        Args:
            request: The HTTP request object

        Returns:
            bool: True if the user has 'create' permission on target workspace
        """
        target_workspace_id = self._get_target_workspace_id(request)
        if target_workspace_id is None:
            # Let validation handle missing/invalid parent_id
            return True

        # V2: Check 'create' permission on target workspace via Inventory API
        if not is_user_allowed_v2(request, "create", target_workspace_id):
            self.message = TARGET_WORKSPACE_ACCESS_DENIED_MESSAGE
            return False

        return True

    def _check_move_target_access_v1(self, request) -> bool:
        """
        Check target workspace access for move operations in V1 mode (non-admin users).

        In V1, we use legacy role-based checks with 'write' operation.

        Args:
            request: The HTTP request object

        Returns:
            bool: True if the user has 'write' access on target workspace
        """
        target_workspace_id = self._get_target_workspace_id(request)
        if target_workspace_id is None:
            # Let validation handle missing/invalid parent_id
            return True

        # V1: Check 'write' operation on target workspace
        if not is_user_allowed_v1(request, "write", target_workspace_id):
            self.message = TARGET_WORKSPACE_ACCESS_DENIED_MESSAGE
            return False

        return True

    def _check_move_target_exists_v1(self, request) -> bool:
        """
        Check that target workspace exists for V1 admin users.

        Admin users bypass permission checks but still need the target workspace
        to exist within their tenant for move operations.

        Args:
            request: The HTTP request object

        Returns:
            bool: True if target workspace exists, False otherwise
        """
        from management.workspace.model import Workspace

        target_workspace_id = self._get_target_workspace_id(request)
        if target_workspace_id is None:
            # Let validation handle missing/invalid parent_id
            return True

        if not Workspace.objects.filter(
            id=target_workspace_id, tenant=request.tenant
        ).exists():
            self.message = TARGET_WORKSPACE_ACCESS_DENIED_MESSAGE
            return False

        return True
