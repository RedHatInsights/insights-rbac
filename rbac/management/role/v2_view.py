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

from api.common.pagination import V2CursorPagination
from .v2_model import RoleV2
from .v2_serializer import RoleV2InputSerializer, RoleV2ResponseSerializer
from .v2_service import RoleV2Service


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


class RoleV2ViewSet(BaseV2ViewSet):
    """RoleV2 ViewSet."""

    queryset = RoleV2.objects.none()
    permission_classes = (RoleAccessPermission,)
    serializer_class = RoleV2ResponseSerializer
    pagination_class = RoleV2CursorPagination
    http_method_names = ["get"]

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
