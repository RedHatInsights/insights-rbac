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

from feature_flags import FEATURE_FLAGS
from management.workspace.utils import permission_from_request
from management.workspace.utils.access import is_user_allowed_v2
from rest_framework import filters

logger = logging.getLogger(__name__)


class WorkspaceAccessFilterBackend(filters.BaseFilterBackend):
    """
    FilterBackend that enforces workspace visibility via Kessel Inventory API.

    This filter:
    - Applies ONLY to v2 workspace endpoints
    - For detail actions: just filters queryset to the specific workspace ID
      (access check is already done by WorkspaceAccessPermission)
    - For list actions: uses is_user_allowed_v2 with StreamedListObjects
      to determine accessible workspaces and filters queryset accordingly

    Why FilterBackend over Permission class:
    - Permission classes handle access decisions (can user access this resource? → 403)
    - FilterBackends handle data filtering (what data can user see? → queryset)
    - This separation follows DRF best practices and single responsibility principle
    """

    # Actions that operate on a single workspace
    DETAIL_ACTIONS = {"retrieve", "update", "partial_update", "destroy", "move"}

    def filter_queryset(self, request, queryset, view):
        """
        Filter workspaces to only those accessible by the current user.

        For detail actions: access is already checked by WorkspaceAccessPermission,
        so just filter to the specific workspace by ID.

        For list actions: uses is_user_allowed_v2 via StreamedListObjects to get
        accessible workspace IDs and filters the queryset accordingly.
        """
        # Skip filtering if V2 access check is disabled (fall back to v1 behavior)
        if not FEATURE_FLAGS.is_workspace_access_check_v2_enabled():
            return self._filter_v1(request, queryset, view)

        action = getattr(view, "action", None)

        # For detail actions, access was already checked by WorkspaceAccessPermission.
        # Just filter queryset to the specific workspace so DRF's get_object() can find it.
        if action in self.DETAIL_ACTIONS:
            workspace_id = view.kwargs.get("pk")
            if workspace_id:
                return queryset.filter(id=workspace_id)
            return queryset

        # For list actions, call is_user_allowed_v2 to get accessible workspaces
        relation = permission_from_request(request, view)
        try:
            has_access = is_user_allowed_v2(request, relation, None)
        except Exception as e:
            logger.exception(
                "Exception in is_user_allowed_v2: user=%s, org_id=%s, relation=%s, error=%s",
                getattr(request.user, "username", "unknown"),
                getattr(request.user, "org_id", "unknown"),
                relation,
                str(e),
            )
            return queryset.none()

        if not has_access:
            return queryset.none()

        # If permission_tuples is set, filter by those IDs
        if hasattr(request, "permission_tuples") and request.permission_tuples:
            accessible_ids = {ws_tuple[1] for ws_tuple in request.permission_tuples}
            return queryset.filter(id__in=accessible_ids)

        # has_access is True but no permission_tuples (system user bypass) - return all workspaces
        return queryset

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
