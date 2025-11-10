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
"""View for role binding management."""
from management.base_viewsets import BaseV2ViewSet
from management.permissions.workspace_access import WorkspaceAccessPermission
from rest_framework.decorators import action
from rest_framework.response import Response

from .pagination import RoleBindingCursorPagination
from .serializer import RoleBindingBySubjectSerializer


class RoleBindingViewSet(BaseV2ViewSet):
    """Role Binding ViewSet.

    Provides read-only access to role bindings currently.
    """

    permission_classes = (WorkspaceAccessPermission,)
    serializer_class = RoleBindingBySubjectSerializer
    pagination_class = RoleBindingCursorPagination

    @action(detail=False, methods=["get"], url_path="by-subject")
    def by_subject(self, request, *args, **kwargs):
        """List role bindings grouped by subject - placeholder implementation."""
        return Response(
            {
                "meta": {"limit": 10},
                "links": {"next": None, "previous": None},
                "data": [],
            }
        )
