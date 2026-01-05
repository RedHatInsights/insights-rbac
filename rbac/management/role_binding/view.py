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
import logging

from management.base_viewsets import BaseV2ViewSet
from management.permissions.role_binding_access import (
    RoleBindingKesselAccessPermission,
    RoleBindingSystemUserAccessPermission,
)
from rest_framework.decorators import action

from api.common.pagination import V2CursorPagination
from .serializer import RoleBindingByGroupSerializer
from .service import RoleBindingService

logger = logging.getLogger(__name__)


class RoleBindingViewSet(BaseV2ViewSet):
    """Role Binding ViewSet.

    Provides read-only access to role bindings currently.

    Query Parameters (by-subject endpoint):
        Required:
            - resource_id: Filter by resource ID
            - resource_type: Filter by resource type

        Optional:
            - subject_type: Filter by subject type (e.g., 'group')
            - subject_id: Filter by subject ID
            - fields: Control which fields are included in the response
            - order_by: Sort by specified field(s), prefix with '-' for descending
    """

    serializer_class = RoleBindingByGroupSerializer
    permission_classes = (
        RoleBindingSystemUserAccessPermission,
        RoleBindingKesselAccessPermission,
    )
    pagination_class = V2CursorPagination

    @action(detail=False, methods=["get"], url_path="by-subject")
    def by_subject(self, request, *args, **kwargs):
        """List role bindings grouped by subject.

        Required query parameters:
            - resource_id: Filter by resource ID
            - resource_type: Filter by resource type

        Optional query parameters:
            - subject_type: Filter by subject type (e.g., 'group')
            - subject_id: Filter by subject ID (UUID)
            - fields: Control which fields are included in the response
            - order_by: Sort by specified field(s), prefix with '-' for descending
        """
        service = RoleBindingService(tenant=request.tenant)

        # Parse and validate query parameters
        params = service.parse_query_params(request.query_params)

        # Get role bindings queryset
        queryset = service.get_role_bindings_by_subject(params)

        # Build context for serializer
        context = {
            "request": request,
            **service.build_context(params),
        }

        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True, context=context)
        return self.get_paginated_response(serializer.data)
