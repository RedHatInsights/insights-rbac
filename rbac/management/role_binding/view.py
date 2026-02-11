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
from management.exceptions import InvalidFieldError
from management.permissions.role_binding_access import (
    RoleBindingKesselAccessPermission,
    RoleBindingSystemUserAccessPermission,
)
from management.role_binding.exceptions import (
    ResourceNotFoundError,
    SubjectNotFoundError,
    UnsupportedSubjectTypeError,
)
from management.subject import SubjectType
from management.v2_mixins import AtomicOperationsMixin
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from api.common.pagination import V2CursorPagination
from .serializer import (
    RoleBindingInputSerializer,
    RoleBindingOutputSerializer,
    UpdateRoleBindingSerializer,
)
from .service import RoleBindingService

logger = logging.getLogger(__name__)

# Mapping from domain exceptions to HTTP status codes and error fields
EXCEPTION_MAPPING = {
    UnsupportedSubjectTypeError: (status.HTTP_400_BAD_REQUEST, "subject_type"),
    SubjectNotFoundError: (status.HTTP_404_NOT_FOUND, "subject_id"),
    ResourceNotFoundError: (status.HTTP_404_NOT_FOUND, "resource_id"),
    InvalidFieldError: (status.HTTP_400_BAD_REQUEST, "field"),
}


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

    serializer_class = RoleBindingOutputSerializer
    permission_classes = (
        RoleBindingSystemUserAccessPermission,
        RoleBindingKesselAccessPermission,
    )
    pagination_class = V2CursorPagination

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
        data = {**request.query_params.dict(), **request.data}

        serializer = UpdateRoleBindingSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        role_ids = [str(role["id"]) for role in validated["roles"]]

        service = RoleBindingService(tenant=request.tenant)

        try:
            result = service.update_role_bindings_for_subject(
                resource_type=validated["resource_type"],
                resource_id=validated["resource_id"],
                subject_type=validated["subject_type"],
                subject_id=validated["subject_id"],
                role_ids=role_ids,
            )
        except tuple(EXCEPTION_MAPPING.keys()) as e:
            http_status, field = EXCEPTION_MAPPING[type(e)]
            return Response({field: str(e)}, status=http_status)

        resource_name = service.get_resource_name(validated["resource_id"], validated["resource_type"])
        last_modified = max((role.modified for role in result.roles), default=None) if result.roles else None

        if result.subject_type == SubjectType.GROUP and result.group:
            subject = {"id": result.group.uuid, "type": SubjectType.GROUP}
        elif result.subject_type == SubjectType.USER and result.principal:
            subject = {
                "id": result.principal.uuid,
                "type": SubjectType.USER,
                "user": {"username": result.principal.username},
            }
        else:
            subject = {"type": result.subject_type}

        response_data = {
            "subject": subject,
            "roles": [{"id": role.uuid, "name": role.name} for role in result.roles],
            "resource": {
                "id": validated["resource_id"],
                "type": validated["resource_type"],
                "name": resource_name,
            },
            "last_modified": last_modified,
        }

        return Response(response_data, status=status.HTTP_200_OK)
