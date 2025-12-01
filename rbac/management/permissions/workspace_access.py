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
    "You do not have access to the target workspace."
)

# Permission/operation names for target workspace access checks
# V2 uses fine-grained permissions from SpiceDB schema (create, view, edit, move, delete)
# V1 uses legacy read/write operations
TARGET_WORKSPACE_PERMISSION_V2 = "create"  # V2: 'create' permission on target for move
TARGET_WORKSPACE_OPERATION_V1 = "write"  # V1: 'write' operation on target for move


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
                return self._check_target_workspace_access(request, v2=True)

            return True

        # V1: Use legacy role-based checks with read/write operations
        # Admin users always have full access in V1 mode
        if request.user.admin:
            return True

        op = operation_from_request(request)
        if not is_user_allowed_v1(request, op, ws_id):
            return False

        # For move operations, also check target workspace access (V1 non-admin only)
        if view.action == "move":
            target_workspace_id = self._get_valid_target_workspace_id(request)
            if target_workspace_id and not is_user_allowed_v1(
                request, TARGET_WORKSPACE_OPERATION_V1, target_workspace_id
            ):
                self.message = TARGET_WORKSPACE_ACCESS_DENIED_MESSAGE
                return False

        return True

    def _check_target_workspace_access(self, request, *, v2: bool) -> bool:
        """
        Check target workspace access for move operations in V2 mode.

        Args:
            request: The HTTP request object
            v2: Must be True (V2 mode only, V1 is handled inline in has_permission)

        Returns:
            bool: True if the user has 'create' permission on target workspace
        """
        target_workspace_id = self._get_valid_target_workspace_id(request)
        if target_workspace_id is None:
            # Let validation handle missing/invalid parent_id
            return True

        if not is_user_allowed_v2(
            request, TARGET_WORKSPACE_PERMISSION_V2, target_workspace_id
        ):
            self.message = TARGET_WORKSPACE_ACCESS_DENIED_MESSAGE
            return False

        return True

    def _get_valid_target_workspace_id(self, request) -> str | None:
        """
        Get and validate the target workspace ID from request.

        Checks both request.data and request.query_params for parent_id to ensure
        target workspace access is always enforced regardless of how the client
        sends the parameter.

        Args:
            request: The HTTP request object

        Returns:
            str: The valid UUID string, or None if missing/invalid (let validation handle it)
        """
        import uuid

        # Check both data (POST body) and query_params for parent_id
        target_workspace_id = request.data.get("parent_id") or request.query_params.get(
            "parent_id"
        )
        if not target_workspace_id:
            return None

        # Validate it's a valid UUID - if not, let the view's validation handle it
        try:
            uuid.UUID(str(target_workspace_id))
            return str(target_workspace_id)
        except (ValueError, AttributeError):
            return None
