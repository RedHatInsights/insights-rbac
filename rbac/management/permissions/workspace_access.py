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
"""Defines the Audit Log Access Permissions class."""

from feature_flags import FEATURE_FLAGS
from management.workspace.utils import (
    is_user_allowed_v1,
    is_user_allowed_v2,
    operation_from_request,
    permission_from_request,
    workspace_from_request,
)
from rest_framework import permissions


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
            return is_user_allowed_v2(request, perm, ws_id)

        # V1: Use legacy role-based checks with read/write operations
        # Admin users always have full access in V1 mode
        if request.user.admin:
            return True

        op = operation_from_request(request)
        return is_user_allowed_v1(request, op, ws_id)
