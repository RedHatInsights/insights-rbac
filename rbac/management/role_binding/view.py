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
from management.group.model import Group
from management.permissions.role_binding_access import (
    RoleBindingKesselAccessPermission,
    RoleBindingSystemUserAccessPermission,
)
from management.permissions.v2_edit_api_access import V2WriteRequiresWorkspacesEnabled
from management.v2_mixins import AtomicOperationsMixin
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from api.common.pagination import V2CursorPagination
from .serializer import (
    BatchCreateRoleBindingRequestSerializer,
    BatchCreateRoleBindingResponseItemSerializer,
    RoleBindingInputSerializer,
    RoleBindingListInputSerializer,
    RoleBindingListOutputSerializer,
    RoleBindingOutputSerializer,
    UpdateRoleBindingRequestSerializer,
    UpdateRoleBindingResponseSerializer,
)
from .service import RoleBindingService

logger = logging.getLogger(__name__)


class RoleBindingViewSet(AtomicOperationsMixin, BaseV2ViewSet):
    """Role Binding ViewSet.

    Provides access to role bindings with support for listing and updating.

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
        V2WriteRequiresWorkspacesEnabled,
    )
    pagination_class = V2CursorPagination

    def get_queryset(self):
        """Return an empty queryset to satisfy DRF's contract.

        The list and by_subject actions build their own querysets.
        """
        return Group.objects.none()

    def get_serializer_class(self):
        """Get serializer class based on action."""
        if self.action == "by_subject":
            return RoleBindingOutputSerializer
        return RoleBindingListOutputSerializer

    def list(self, request, *args, **kwargs):
        """Get a list of role bindings.

        Optional query parameters:
            - role_id: Filter by role ID (UUID)
            - resource_id: Filter by resource ID (must be used with resource_type for inherited bindings)
            - resource_type: Filter by resource type (must be used with resource_id for inherited bindings)
            - subject_type: Filter by subject type (e.g., 'group')
            - subject_id: Filter by subject ID (UUID)
            - granted_subject_type: Filter by effective grant subject type ('user' or 'group')
            - granted_subject_id: Filter by effective grant subject ID (principal UUID, user_id, or group UUID)
            - fields: Control which fields are included in the response
            - order_by: Sort by specified field(s), prefix with '-' for descending
            - exclude_sources: 'none' (default) shows all, 'indirect' hides inherited, 'direct' hides direct
        """
        input_serializer = RoleBindingListInputSerializer(data=request.query_params)
        input_serializer.is_valid(raise_exception=True)
        validated_params = input_serializer.validated_data

        service = RoleBindingService(tenant=request.tenant)
        queryset = service.get_role_bindings_for_list(validated_params)

        resource_id = validated_params.get("resource_id")
        resource_type = validated_params.get("resource_type")

        granted_subject_type = validated_params.get("granted_subject_type")
        granted_subject_id = validated_params.get("granted_subject_id")
        if granted_subject_type and granted_subject_id:
            queryset = queryset.for_granted_subject(granted_subject_type, granted_subject_id)

        field_selection = validated_params.get("fields")
        if field_selection is not None and "name" in field_selection.get_nested("resource"):
            queryset = queryset.with_resource_names()

        page = self.paginate_queryset(queryset)

        # Build context for output serializer
        context = {
            "request": request,
            "field_selection": field_selection,
            "queried_resource_id": str(resource_id) if resource_id else None,
            "queried_resource_type": resource_type,
            "service": service,
        }

        serializer = self.get_serializer(page, many=True, context=context)
        return self.get_paginated_response(serializer.data)

    def batch_create(self, request, *args, **kwargs):
        """Grant access to a resource to a set of subjects with a set of roles."""
        return self._atomic_action(self._perform_batch_create, "batch_create", request, *args, **kwargs)

    def _perform_batch_create(self, request, *args, **kwargs):
        """Core batch create logic."""
        data = {**request.data, "fields": request.query_params.get("fields", "")}
        serializer = BatchCreateRoleBindingRequestSerializer(data=data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        created_bindings = serializer.save()

        fields = serializer.validated_data.get("fields")
        response_serializer = BatchCreateRoleBindingResponseItemSerializer(
            created_bindings, many=True, context={"field_selection": fields}
        )
        return Response({"role_bindings": response_serializer.data}, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["get", "put"], url_path="by-subject")
    def by_subject(self, request, *args, **kwargs):
        """Handle role bindings by subject.

        GET: List role bindings grouped by subject.
        PUT: Update role bindings for a specific subject on a resource.
        """
        if request.method == "PUT":
            return self._update_by_subject(request)
        return self._list_by_subject(request)

    def _list_by_subject(self, request):
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

    def _update_by_subject(self, request):
        """Update role bindings for a specific subject on a resource."""
        return self._atomic_action(self._perform_update_by_subject, "update_by_subject", request)

    def _perform_update_by_subject(self, request):
        """Core update-by-subject logic."""
        data = {**request.query_params.dict(), **request.data}

        serializer = UpdateRoleBindingRequestSerializer(data=data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        result = serializer.save()

        response_context = {
            "request": request,
            "field_selection": serializer.validated_data.get("fields"),
        }
        response_serializer = UpdateRoleBindingResponseSerializer(result, context=response_context)
        return Response(response_serializer.data, status=status.HTTP_200_OK)
