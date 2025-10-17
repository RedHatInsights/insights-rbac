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
from management.models import Workspace
from management.workspace.utils import is_user_allowed
from rest_framework import permissions


class WorkspaceAccessPermission(permissions.BasePermission):
    """Determines if a user is an Account Admin."""

    def has_permission(self, request, view):
        """Check permission based on Account Admin property."""
        if request.user.admin:
            return True

        # Determine the target workspace for permission checking
        if request.method == "POST" and view.kwargs.get("pk") is None:
            # Create operation: check permissions on the intended parent workspace
            if parent_id := request.data.get("parent_id"):
                workspace_id = parent_id
            else:
                # Fall back to Default Workspace when parent_id is not provided
                workspace_id = str(Workspace.objects.default(tenant_id=request.tenant).id)
        else:
            # Update/delete/retrieve operations: use the workspace from URL
            workspace_id = view.kwargs.get("pk")

        # Determine required operation
        if request.method in permissions.SAFE_METHODS:
            required_operation = "read"
        else:
            required_operation = "write"

        return is_user_allowed(request, required_operation, workspace_id)
