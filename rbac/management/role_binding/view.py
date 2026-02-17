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
from management.models import Group
from management.permissions.role_binding_access import (
    RoleBindingKesselAccessPermission,
    RoleBindingSystemUserAccessPermission,
)
from management.v2_mixins import AtomicOperationsMixin
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from api.common.pagination import V2CursorPagination
from .serializer import (
    BatchCreateRoleBindingRequestSerializer,
    BatchCreateRoleBindingResponseItemSerializer,
    RoleBindingInputSerializer,
    RoleBindingOutputSerializer,
)
from .service import RoleBindingService

logger = logging.getLogger(__name__)


class RoleBindingViewSet(AtomicOperationsMixin, BaseV2ViewSet):
    """Role Binding ViewSet.

    Provides access to role bindings with support for listing and batch creation.

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

    serializer_class = RoleBindingOutputSerializer
    permission_classes = (
        RoleBindingSystemUserAccessPermission,
        RoleBindingKesselAccessPermission,
    )
    pagination_class = V2CursorPagination

    def get_queryset(self):
        """Return empty queryset - this ViewSet only exposes custom actions.

        Returns Group.objects.none() to satisfy DRF expectations while indicating no default queryset is used.
        """
        return Group.objects.none()

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
        input_serializer = RoleBindingInputSerializer(data=request.query_params)
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

    @action(detail=False, methods=["post"], url_path=":batchCreate")
    def batch_create(self, request, *args, **kwargs):
        """Grant access to a resource to a set of subjects with a set of roles."""
        return super().batch_create(request, *args, **kwargs)

    def perform_batch_create(self, request, *args, **kwargs):
        """Core batch create logic, called within an atomic transaction by the mixin."""
        serializer = BatchCreateRoleBindingRequestSerializer(
            data={**request.data, "fields": request.query_params.get("fields", "")}, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        created_bindings = serializer.save()

        field_selection = serializer.validated_data.get("fields")
        response_serializer = BatchCreateRoleBindingResponseItemSerializer(
            created_bindings, many=True, context={"field_selection": field_selection}
        )
        return Response({"role_bindings": response_serializer.data}, status=status.HTTP_201_CREATED)
