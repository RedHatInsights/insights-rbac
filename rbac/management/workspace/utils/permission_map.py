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
"""Permission mapping utilities for workspace operations."""
import logging

from rest_framework.exceptions import PermissionDenied

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

# Map HTTP methods to workspace permissions
PERM_MAP = {
    "GET": "view",
    "POST": "create",
    "PUT": "edit",
    "PATCH": "edit",
    "DELETE": "delete",
}


def permission_from_request(request, view=None) -> str:
    """
    Determine the permission/relation from the HTTP request method.

    Maps HTTP methods to workspace permissions:
    - GET -> view
    - POST -> create
    - PUT/PATCH -> edit (or 'move' if moving workspace to different parent)
    - DELETE -> delete

    Note: The 'move' permission is a special case of 'edit' that occurs when
    changing a workspace's parent. To detect this, we compare the new parent
    value with the existing one.

    Args:
        request: The HTTP request object
        view: The view object (optional, used to get the current workspace instance)

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
    return "move" if _is_move(request, view) else perm


def _is_move(request, view=None) -> bool:
    """
    Check if the request is a workspace move operation.

    Detects a move operation by checking if the parent is actually changing.
    Returns True only if the new parent differs from the current parent.

    Args:
        request: The HTTP request object
        view: The view object (optional, used to get the current workspace instance)

    Returns:
        bool: True if this is a move operation
    """
    # Only PUT/PATCH can be move operations
    if PERM_MAP.get(request.method.upper()) != "edit":
        return False

    if not hasattr(request, "data"):
        return False

    # Get the new parent from request data
    data = request.data
    new_parent_id = data.get("parent_id") or data.get("parent")

    # If no parent is being set, this is not a move
    if new_parent_id is None:
        return False

    # Try to get the current workspace instance to compare parents
    current_parent_id = None
    if view and hasattr(view, "get_object"):
        try:
            workspace = view.get_object()
            # Get current parent ID - handle both parent_id and parent attributes
            current_parent_id = getattr(workspace, "parent_id", None)
            if current_parent_id is None:
                parent = getattr(workspace, "parent", None)
                current_parent_id = getattr(parent, "id", None) if parent else None
        except Exception:
            # If we can't get the workspace, fall back to checking if parent is present
            # This is better than failing the request
            logger.debug("Could not get workspace instance for move detection")
            pass

    # If we couldn't get the current parent, assume it's a move if parent is being set
    # This maintains backward compatibility with the original behavior
    if current_parent_id is None:
        return True

    # Compare current and new parent IDs
    return str(new_parent_id) != str(current_parent_id)
