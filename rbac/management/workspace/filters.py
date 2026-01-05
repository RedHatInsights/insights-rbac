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
"""Workspace access control via FilterBackend for v2 APIs."""

import logging
from typing import Optional, Set

from feature_flags import FEATURE_FLAGS
from management.permissions.system_user_utils import (
    SystemUserAccessResult,
    check_system_user_access,
)
from management.permissions.workspace_inventory_access import (
    WorkspaceInventoryAccessChecker,
)
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from management.utils import get_principal_from_request
from management.workspace.model import Workspace
from management.workspace.utils import permission_from_request
from management.workspace.utils.access import filter_top_level_workspaces, get_fallback_workspace_ids
from rest_framework import filters

logger = logging.getLogger(__name__)


class WorkspaceAccessFilterBackend(filters.BaseFilterBackend):
    """
    FilterBackend that enforces workspace visibility via Kessel Inventory API.

    This filter:
    - Applies ONLY to v2 workspace endpoints
    - Uses Kessel Inventory API (StreamedListObjects) to get accessible workspaces
    - Filters queryset to only include workspaces user can access
    - Returns 404 for inaccessible workspaces on detail views (no existence leak)

    Why FilterBackend over Permission class:
    - Permission classes are for coarse-grained endpoint access (can user call this endpoint?)
    - FilterBackends are for data filtering (what data can user see?)
    - This separation follows DRF best practices and single responsibility principle
    """

    def filter_queryset(self, request, queryset, view):
        """
        Filter workspaces to only those accessible by the current user.

        For list actions: Returns filtered queryset of accessible workspaces
        For detail actions: Also filters queryset so get_object() returns 404 for both
                           non-existing and inaccessible workspaces (prevents existence leakage)

        This ensures consistent 404 behavior:
        - If workspace doesn't exist: 404 (standard DRF behavior)
        - If workspace exists but user can't access: 404 (prevents existence leakage)

        The permission class only handles coarse-grained checks:
        - System user bypass
        - Move target validation
        """
        # Skip filtering if V2 access check is disabled (fall back to v1 behavior)
        if not FEATURE_FLAGS.is_workspace_access_check_v2_enabled():
            return self._filter_v1(request, queryset, view)

        # System user bypass check
        system_check = check_system_user_access(request.user, action=view.action)
        if system_check.result == SystemUserAccessResult.ALLOWED:
            return queryset
        if system_check.result == SystemUserAccessResult.DENIED:
            # Return empty queryset - permission class will handle 403
            return queryset.none()

        # Get accessible workspace IDs from Inventory API
        try:
            accessible_ids = self._get_accessible_workspace_ids(request, view)
        except Exception as e:
            logger.exception(
                "Exception while getting accessible workspaces from Inventory API: "
                "user=%s, org_id=%s, action=%s, method=%s, error=%s",
                getattr(request.user, "username", "unknown"),
                getattr(request.user, "org_id", "unknown"),
                getattr(view, "action", "unknown"),
                request.method,
                str(e),
            )
            return queryset.none()

        if accessible_ids is None:
            # Failed to get accessible workspaces - return empty for safety
            logger.warning("Failed to get accessible workspaces, returning empty queryset")
            return queryset.none()

        # Store for potential use by permission class (e.g., move target validation)
        request.accessible_workspace_ids = accessible_ids

        # Apply filter - this ensures 404 for both non-existing and inaccessible workspaces
        return queryset.filter(id__in=accessible_ids)

    def _filter_v1(self, request, queryset, view):
        """
        V1 filtering behavior - uses permission tuples set by is_user_allowed_v1.

        This maintains backward compatibility with V1 access control.
        """
        # For V1, the permission check in is_user_allowed_v1 sets request.permission_tuples
        # We need to filter based on those tuples
        if hasattr(request, "permission_tuples") and request.permission_tuples:
            permitted_ws_ids = [tuple[1] for tuple in request.permission_tuples]
            return queryset.filter(id__in=permitted_ws_ids)
        return queryset

    def _get_accessible_workspace_ids(self, request, view) -> Optional[Set[str]]:
        """
        Get set of workspace IDs accessible to the current user.

        Returns:
            set[str]: Accessible workspace IDs, or None on error
        """
        # Determine the relation/permission to check based on request method
        relation = permission_from_request(request, view)

        # Get principal ID for Inventory API
        principal_id = self._get_principal_id(request)
        if not principal_id:
            return None

        # Query Inventory API for accessible workspaces
        checker = WorkspaceInventoryAccessChecker()
        accessible_ids = checker.lookup_accessible_workspaces(
            principal_id=principal_id,
            relation=relation,
        )

        if accessible_ids:
            # Add ancestors for top-level workspaces (for ancestry display)
            accessible_ids = self._add_ancestors_for_top_level(accessible_ids, request.tenant)
        else:
            # Fallback: provide root, default, ungrouped workspaces
            accessible_ids = self._get_fallback_workspace_ids(request.tenant)

        return accessible_ids

    def _get_principal_id(self, request) -> Optional[str]:
        """Get the principal ID for Inventory API calls."""
        # Try to get user_id from principal
        principal = get_principal_from_request(request)
        if principal is not None and principal.user_id is not None:
            return Principal.user_id_to_principal_resource_id(principal.user_id)

        # Try from request.user
        user_id = getattr(request.user, "user_id", None)
        if user_id is not None:
            return Principal.user_id_to_principal_resource_id(user_id)

        # Fallback: query IT service via PrincipalProxy to get user_id
        username = getattr(request.user, "username", None)
        if not username:
            logger.warning("No username available from request.user for workspace filter")
            return None

        org_id = getattr(request.user, "org_id", None)
        if not org_id:
            logger.warning("No org_id available from request.user for workspace filter")
            return None

        proxy = PrincipalProxy()
        resp = proxy.request_filtered_principals([username], org_id=org_id, options={"return_id": True})

        if resp.get("status_code") != 200 or not resp.get("data"):
            logger.warning("Failed to retrieve user_id from IT service for username: %s", username)
            return None

        user_id = resp["data"][0].get("user_id")
        if not user_id:
            logger.warning("IT service response missing user_id for username: %s", username)
            return None

        logger.debug("Retrieved user_id from IT service via PrincipalProxy for workspace filter")
        return Principal.user_id_to_principal_resource_id(user_id)

    def _add_ancestors_for_top_level(self, accessible_ids: Set[str], tenant) -> Set[str]:
        """Add ancestor IDs for top-level accessible workspaces."""
        accessible_workspaces = Workspace.objects.filter(id__in=accessible_ids, tenant=tenant)
        top_level = filter_top_level_workspaces(accessible_workspaces)

        result = set(accessible_ids)
        for ws in top_level:
            for ancestor in ws.ancestors():
                result.add(str(ancestor.id))

        return result

    def _get_fallback_workspace_ids(self, tenant) -> Set[str]:
        """Get fallback workspace IDs (root, default, ungrouped)."""
        return get_fallback_workspace_ids(tenant)


class WorkspaceObjectAccessMixin:
    """
    Mixin that ensures 404 for inaccessible workspaces on detail views.

    Add this to viewsets to prevent object existence leakage.
    The get_object() method will raise 404 if the workspace is not
    in the filtered queryset (i.e., user doesn't have access).
    """

    def get_object(self):
        """
        Get object with access-aware 404 behavior.

        If the workspace exists but user doesn't have access,
        returns 404 (not 403) to prevent existence leakage.
        """
        # get_queryset() already filtered by WorkspaceAccessFilterBackend
        # If object not in filtered queryset, DRF raises 404
        return super().get_object()
