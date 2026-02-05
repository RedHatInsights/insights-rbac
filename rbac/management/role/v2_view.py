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

from management.base_viewsets import BaseV2ViewSet
from management.permissions import RoleAccessPermission
from management.role.v2_model import RoleV2
from management.role.v2_serializer import RoleV2InputSerializer, RoleV2RequestSerializer, RoleV2ResponseSerializer
from management.role.v2_service import RoleV2Service
from management.v2_mixins import AtomicOperationsMixin
from rest_framework import status
from rest_framework.response import Response

from api.common.pagination import V2CursorPagination


class RoleV2CursorPagination(V2CursorPagination):
    """Cursor pagination for roles."""

    ordering = "name"
    FIELD_MAPPING = {"name": "name", "last_modified": "modified"}

    def _convert_order_field(self, field: str) -> str | None:
        """Map API field names to model field names.

        Accepts direct field names.

        Args:
            field: The field name (name, last_modified)

        Returns:
            The Django ORM field name or None if invalid
        """
        descending = field.startswith("-")
        model_field = self.FIELD_MAPPING.get(field.lstrip("-"))
        if descending and model_field:
            return f"-{model_field}"
        return model_field


class RoleV2ViewSet(AtomicOperationsMixin, BaseV2ViewSet):
    """RoleV2 ViewSet."""

    permission_classes = (RoleAccessPermission,)
    queryset = RoleV2.objects.none()
    serializer_class = RoleV2ResponseSerializer
    pagination_class = RoleV2CursorPagination
    lookup_field = "uuid"
    http_method_names = ["get", "post", "head", "options"]

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == "create":
            return RoleV2RequestSerializer
        return RoleV2ResponseSerializer

    def list(self, request, *args, **kwargs):
        """Get a list of roles."""
        input_serializer = RoleV2InputSerializer(data=request.query_params)
        input_serializer.is_valid(raise_exception=True)
        params = input_serializer.validated_data

        service = RoleV2Service(tenant=request.tenant)
        queryset = service.list(params)

        # Build context for output serializer
        context = {
            "request": request,
            "fields": params.get("fields"),
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
