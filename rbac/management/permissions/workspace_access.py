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
from rest_framework.exceptions import PermissionDenied

logger = logging.getLogger(__name__)

# Map HTTP methods to workspace permissions
PERM_MAP = {
    "GET": "view",
    "POST": "create",
    "PUT": "edit",
    "PATCH": "edit",
    "DELETE": "delete",
}


def _get_default_workspace_id(request) -> Optional[str]:
    """
    Get the default workspace ID for a tenant.

    Args:
        request: The HTTP request object containing tenant information

    Returns:
        Optional[str]: The default workspace ID, or None if it doesn't exist
    """
    try:
        return str(Workspace.objects.default(tenant_id=request.tenant).id)
    except Workspace.DoesNotExist:
        logger.warning(f"No default workspace for tenant {request.tenant}")
        return None


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

        Raises:
            PermissionDenied: If the HTTP method is not supported
        """
        method = request.method.upper()

        if method not in PERM_MAP:
            logger.error(f"Unsupported HTTP method: {method}")
            raise PermissionDenied(f"Unsupported HTTP method: {method}")

        perm = PERM_MAP[method]

        # Check if this is a move operation (changing parent)
        if (
            perm == "edit"
            and hasattr(request, "data")
            and (
                request.data.get("parent_id") is not None
                or request.data.get("parent") is not None
            )
        ):
            return "move"

        return perm

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
        # Get lookup key from view (defaults to "pk")
        lookup = getattr(view, "lookup_url_kwarg", "pk") if view else "pk"
        pk = getattr(view, "kwargs", {}).get(lookup) if view else None

        # For POST (create): prefer explicit parent_id, else default
        if request.method == "POST":
            parent_id = (
                request.data.get("parent_id") if hasattr(request, "data") else None
            )
            if parent_id:
                return parent_id
            default_id = _get_default_workspace_id(request)
            if default_id:
                logger.debug(
                    f"No parent_id provided for workspace creation, using default workspace: {default_id}"
                )
            return default_id

        # For GET: list (None) vs detail (pk)
        if request.method == "GET":
            return pk

        # All other methods (PUT/PATCH/DELETE) operate on existing pk
        return pk or _get_default_workspace_id(request)

    def has_permission(self, request, view):
        """Check permission based on Account Admin property."""
        # Admin users always have full access regardless of v2 flag
        if request.user.admin:
            return True

        if FEATURE_FLAGS.is_workspace_access_check_v2_enabled():
            workspace_id = self.workspace_from_request(request, view)
            return is_user_allowed_v2(
                request, self.permission_from_request(request), workspace_id
            )

        # Determine the target workspace for permission checking
        workspace_id = self.workspace_from_request(request, view)

        # Determine required operation
        if request.method in permissions.SAFE_METHODS:
            required_operation = "read"
        else:
            required_operation = "write"

        return is_user_allowed(request, required_operation, workspace_id)
