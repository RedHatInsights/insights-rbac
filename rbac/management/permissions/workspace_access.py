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
import logging
from typing import Optional

from feature_flags import FEATURE_FLAGS
from management.models import Workspace
from management.workspace.utils import is_user_allowed, is_user_allowed_v2
from rest_framework import permissions

logger = logging.getLogger(__name__)


class WorkspaceAccessPermission(permissions.BasePermission):
    """Determines if a user is an Account Admin."""

    @staticmethod
    def permission_from_request(request) -> str:
        """
        Determine the permission/relation from the HTTP request method.

        Maps HTTP methods to workspace permissions:
        - GET -> view
        - POST -> create
        - PUT/PATCH -> edit (or 'move' if moving workspace to different parent)
        - DELETE -> delete

        Note: The 'move' permission is a special case of 'edit' that occurs when
        changing a workspace's parent. To detect this, check if the request data
        contains a 'parent_id' or 'parent' field change.

        Args:
            request: The HTTP request object

        Returns:
            str: The permission/relation name (view, create, edit, move, delete)
        """
        method = request.method.upper()

        if method == "GET":
            return "view"
        elif method == "POST":
            return "create"
        elif method in ("PUT", "PATCH"):
            # Check if this is a move operation (changing parent)
            if hasattr(request, "data"):
                if "parent_id" in request.data or "parent" in request.data:
                    return "move"
            return "edit"
        elif method == "DELETE":
            return "delete"
        else:
            # Default to view for unknown methods
            logger.warning(f"Unknown HTTP method {method}, defaulting to 'view' permission")
            return "view"

    @staticmethod
    def workspace_from_request(request, view=None) -> Optional[str]:
        """
        Get workspace ID from request and fetch if exists or get default workspace.

        Determines the target workspace for permission checking:
        - For POST (create): checks parent_id in request.data, falls back to default workspace
        - For detail operations: uses pk from view.kwargs
        - For list operations (GET without pk): returns None (list all accessible)

        Args:
            request: The HTTP request object
            view: The view object (optional, contains kwargs with pk)

        Returns:
            Optional[str]: The workspace ID to check permissions against, or None for list operations
        """
        # For POST (create), check parent_id in request data
        if request.method == "POST" and (not view or view.kwargs.get("pk") is None):
            # Create operation: check permissions on the intended parent workspace
            if hasattr(request, "data") and (parent_id := request.data.get("parent_id")):
                return parent_id
            else:
                # Fall back to default workspace for create operations without parent_id
                try:
                    return str(Workspace.objects.default(tenant_id=request.tenant).id)
                except Exception:
                    # If default workspace doesn't exist, return None
                    return None

        # For list operations (GET without pk), return None to indicate list all accessible
        if request.method == "GET" and (not view or not view.kwargs.get("pk")):
            return None

        # For detail operations (update/delete/retrieve), use pk from URL
        if view and view.kwargs.get("pk"):
            return view.kwargs.get("pk")

        # Fallback to default workspace (shouldn't normally reach here)
        return str(Workspace.objects.default(tenant_id=request.tenant).id)

    def has_permission(self, request, view):
        """Check permission based on Account Admin property."""
        if FEATURE_FLAGS.is_workspace_access_check_v2_enabled():
            workspace_id = self.workspace_from_request(request, view)
            return is_user_allowed_v2(request, self.permission_from_request(request), workspace_id)

        if request.user.admin:
            return True

        # Determine the target workspace for permission checking
        workspace_id = self.workspace_from_request(request, view)

        # Determine required operation
        if request.method in permissions.SAFE_METHODS:
            required_operation = "read"
        else:
            required_operation = "write"

        return is_user_allowed(request, required_operation, workspace_id)
