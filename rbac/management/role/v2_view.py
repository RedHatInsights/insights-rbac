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
"""View for RoleV2 management."""

from management.atomic_transactions import atomic
from management.base_viewsets import BaseV2ViewSet
from management.permissions import RoleAccessPermission
from management.role.v2_exceptions import CustomRoleRequiredError, RoleNotFoundError
from management.role.v2_model import RoleV2
from management.role.v2_serializer import (
    RoleV2BulkDeleteRequestSerializer,
    RoleV2ListSerializer,
    RoleV2RequestSerializer,
    RoleV2ResponseSerializer,
)
from management.role.v2_service import RoleV2Service
from management.v2_mixins import AtomicOperationsMixin
from rest_framework import status
from rest_framework.response import Response

from api.common.pagination import V2CursorPagination


class RoleV2CursorPagination(V2CursorPagination):
    """Cursor pagination for roles."""

    ordering = "name"
    FIELD_MAPPING = {"name": "name", "last_modified": "modified"}


class RoleV2ViewSet(AtomicOperationsMixin, BaseV2ViewSet):
    """RoleV2 ViewSet."""

    permission_classes = (RoleAccessPermission,)
    queryset = RoleV2.objects.exclude(type=RoleV2.Types.PLATFORM)
    serializer_class = RoleV2ResponseSerializer
    pagination_class = RoleV2CursorPagination
    lookup_field = "uuid"
    http_method_names = ["get", "post", "head", "options"]

    def __init__(self, *args, **kwargs):
        """Initialize the ViewSet."""
        super().__init__(*args, **kwargs)
        self._service = RoleV2Service()

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == "create":
            return RoleV2RequestSerializer
        if self.action == "bulk_destroy":
            return RoleV2BulkDeleteRequestSerializer
        return RoleV2ResponseSerializer

    def list(self, request, *args, **kwargs):
        """Get a list of roles."""
        input_serializer = RoleV2ListSerializer(data=request.query_params, context={"request": request})
        input_serializer.is_valid(raise_exception=True)
        validated_params = input_serializer.validated_data

        service = RoleV2Service(tenant=request.tenant)
        queryset = service.list(validated_params)

        context = {
            "request": request,
            "fields": validated_params.get("fields"),
        }

        page = self.paginate_queryset(queryset)
        serializer = RoleV2ResponseSerializer(page, many=True, context=context)
        return self.get_paginated_response(serializer.data)

    def create(self, request, *args, **kwargs):
        """Create a role and return the full response representation."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = serializer.save()
        input_permissions = request.data.get("permissions", [])
        response_serializer = RoleV2ResponseSerializer(role, context={"input_permissions": input_permissions})
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    @atomic
    def bulk_destroy(self, request, *args, **kwargs):
        """Delete multiple roles atomically."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        ids = set(serializer.validated_data["ids"])

        try:
            self._service.bulk_delete(ids, from_tenant=self.request.tenant)
        except RoleNotFoundError as e:
            return Response({"title": "Resource was not found", "detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except CustomRoleRequiredError as e:
            # This should be impossible. We constrain deletions to be from the user's tenant. Non-custom roles should
            # only exist in the public tenant, and there shouldn't be any users in the public tenant. Thus,
            # we will never find any non-custom roles to try to delete.
            return Response({"title": "An internal error occurred.", "detail": str(e)})

        return Response(status=status.HTTP_204_NO_CONTENT)
