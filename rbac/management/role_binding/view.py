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

from django.db.models import F
from management.base_viewsets import BaseV2ViewSet
from management.group.model import Group
from management.permissions.role_binding_access import (
    RoleBindingKesselAccessPermission,
    RoleBindingSystemUserAccessPermission,
)
from management.role.v2_model import RoleBinding
from rest_framework.decorators import action

from api.common.pagination import V2CursorPagination
from .serializer import (
    RoleBindingBySubjectInputSerializer,
    RoleBindingBySubjectOutputSerializer,
    RoleBindingListInputSerializer,
    RoleBindingListOutputSerializer,
)
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

    serializer_class = RoleBindingListOutputSerializer
    permission_classes = (
        RoleBindingSystemUserAccessPermission,
        RoleBindingKesselAccessPermission,
    )
    pagination_class = V2CursorPagination

    def get_queryset(self):
        """Build base queryset for listing role bindings.

        Filters by tenant and annotates role_created for cursor pagination ordering.

        For by_subject, returns an empty queryset since that action
        builds its own queryset via the service layer.
        """
        if self.action != "list":
            return Group.objects.none()

        # Explicit tenant filter because BaseV2ViewSet.get_queryset() adds
        # .order_by("name") which doesn't exist on RoleBinding.
        return (
            RoleBinding.objects.filter(tenant=self.request.tenant)
            .select_related("role")
            .prefetch_related("group_entries__group")
            .annotate(role_created=F("role__created"))
        )

    def get_serializer_class(self):
        """Get serializer class based on action."""
        if self.action == "by_subject":
            return RoleBindingBySubjectOutputSerializer
        return RoleBindingListOutputSerializer

    def list(self, request, *args, **kwargs):
        """Get a list of role bindings.

        Optional query parameters:
            - role_id: Filter by role ID (UUID)
            - fields: Control which fields are included in the response
            - order_by: Sort by specified field(s), prefix with '-' for descending
        """
        # Validate and parse query parameters using input serializer
        input_serializer = RoleBindingListInputSerializer(data=request.query_params)
        input_serializer.is_valid(raise_exception=True)
        validated_params = input_serializer.validated_data

        queryset = self.get_queryset()

        # Apply role_id filter using validated UUID
        role_id = validated_params.get("role_id")
        if role_id:
            queryset = queryset.filter(role__uuid=role_id)

        # Build context for output serializer
        context = {
            "request": request,
            "field_selection": validated_params.get("fields"),
        }

        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True, context=context)
        return self.get_paginated_response(serializer.data)

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
        # Validate and parse query parameters using input serializer
        input_serializer = RoleBindingBySubjectInputSerializer(data=request.query_params)
        input_serializer.is_valid(raise_exception=True)
        validated_params = input_serializer.validated_data

        service = RoleBindingService(tenant=request.tenant)

        # Get role bindings queryset using validated parameters
        queryset = service.get_role_bindings_by_subject(validated_params)

        # Build context for output serializer
        context = {
            "request": request,
            **service.build_context(validated_params),
        }

        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True, context=context)
        return self.get_paginated_response(serializer.data)
