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
from management.workspace.utils import is_user_allowed
from rest_framework import permissions


class WorkspaceAccessPermission(permissions.BasePermission):
    """Determines if a user is an Account Admin."""

    def has_permission(self, request, view):
        """Check permission based on Account Admin property."""
        # Would exist for update/delete/retrive workspace
        if request.user.admin:
            return True
        workspace_id = view.kwargs.get("pk")
        if request.method in permissions.SAFE_METHODS:
            required_operation = "read"
        else:
            required_operation = "write"

        return is_user_allowed(request, required_operation, workspace_id)
