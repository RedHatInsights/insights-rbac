#
# Copyright 2026 Red Hat, Inc.
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
"""Permission classes for gating V1/V2 write operations by the v2_edit_api feature flag."""

from feature_flags import FEATURE_FLAGS
from rest_framework import permissions


class V1WriteBlockedWhenWorkspacesEnabled(permissions.BasePermission):
    """Deny V1 write operations when workspaces (v2 edit API) is enabled for the org.

    Add to V1 viewsets (RoleViewSet, GroupViewSet) to block write requests
    for orgs that have been migrated to workspaces.
    """

    message = "V1 write operations are not allowed for orgs using workspaces."

    def has_permission(self, request, view):
        """Allow reads always; deny writes when v2 edit API is enabled for this org."""
        if request.method in permissions.SAFE_METHODS:
            return True
        return not FEATURE_FLAGS.is_v2_edit_api_enabled(request.user.org_id)


class V2WriteRequiresWorkspacesEnabled(permissions.BasePermission):
    """Deny V2 write operations when workspaces (v2 edit API) is NOT enabled for the org.

    Add to V2 viewsets (RoleV2ViewSet, RoleBindingViewSet) to block write requests
    for orgs that have not been migrated to workspaces.
    """

    message = "V2 write operations require the workspaces feature to be enabled for this org."

    def has_permission(self, request, view):
        """Allow reads always; deny writes when v2 edit API is disabled for this org."""
        if request.method in permissions.SAFE_METHODS:
            return True
        return FEATURE_FLAGS.is_v2_edit_api_enabled(request.user.org_id)
