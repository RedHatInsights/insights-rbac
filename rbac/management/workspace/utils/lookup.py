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
"""Workspace lookup utilities."""
import logging
from typing import Optional

from management.models import Workspace

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def get_default_workspace_id(request) -> Optional[str]:
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
    # For POST (create): prefer explicit parent_id, else default
    if request.method == "POST":
        return _post_workspace(request)

    # For GET: list (None) vs detail (pk)
    if request.method == "GET":
        return _get_workspace(request, view)

    # All other methods (PUT/PATCH/DELETE) operate on existing pk
    return _other_workspace(request, view)


def _post_workspace(request) -> Optional[str]:
    """
    Get workspace ID for POST (create) operations.

    Args:
        request: The HTTP request object

    Returns:
        Optional[str]: The parent workspace ID or default workspace ID
    """
    parent_id = request.data.get("parent_id") if hasattr(request, "data") else None
    if parent_id:
        return parent_id

    default_id = get_default_workspace_id(request)
    if default_id:
        logger.debug(f"No parent_id provided for workspace creation, using default workspace: {default_id}")
    return default_id


def _get_workspace(request, view) -> Optional[str]:
    """
    Get workspace ID for GET operations.

    Args:
        request: The HTTP request object
        view: The view object (optional, contains kwargs with pk)

    Returns:
        Optional[str]: The workspace ID from view kwargs, or None for list operations
    """
    lookup = getattr(view, "lookup_url_kwarg", None) or "pk" if view else "pk"
    return getattr(view, "kwargs", {}).get(lookup) if view else None


def _other_workspace(request, view) -> Optional[str]:
    """
    Get workspace ID for PUT/PATCH/DELETE operations.

    Args:
        request: The HTTP request object
        view: The view object (optional, contains kwargs with pk)

    Returns:
        Optional[str]: The workspace ID from view kwargs or default workspace ID
    """
    pk = _get_workspace(request, view)
    return pk or get_default_workspace_id(request)
