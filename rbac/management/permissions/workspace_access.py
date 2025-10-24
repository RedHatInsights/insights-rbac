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
    is_user_allowed,
    is_user_allowed_v2,
    permission_from_request,
    workspace_from_request,
)
from rest_framework import permissions


class WorkspaceAccessPermission(permissions.BasePermission):
    """Determines if a user is an Account Admin."""

    def has_permission(self, request, view):
        """Check permission based on Account Admin property."""
        # Admin users always have full access regardless of v2 flag
        if request.user.admin:
            return True

        perm = permission_from_request(request)
        ws_id = workspace_from_request(request, view)

        if FEATURE_FLAGS.is_workspace_access_check_v2_enabled():
            return is_user_allowed_v2(request, perm, ws_id)

        # Fallback to old read/write
        op = "read" if request.method in permissions.SAFE_METHODS else "write"
        return is_user_allowed(request, op, ws_id)
