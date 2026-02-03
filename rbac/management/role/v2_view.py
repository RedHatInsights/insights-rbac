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
"""View for V2 Role management."""

from django.db.models import Count
from management.base_viewsets import BaseV2ViewSet
from management.permissions import RoleAccessPermission
from rest_framework import serializers

from api.common.pagination import V2CursorPagination
from .v2_model import RoleV2
from .v2_serializer import RoleSerializer, parse_fields_param


class RoleV2CursorPagination(V2CursorPagination):
    """Cursor pagination for roles."""

    FIELD_MAPPING = {"name": "name", "last_modified": "modified"}

    def _convert_order_field(self, field: str) -> str | None:
        """Map API field names to model field names."""
        descending = field.startswith("-")
        model_field = self.FIELD_MAPPING.get(field.lstrip("-"))
        if descending and model_field:
            return f"-{model_field}"
        return model_field


class RoleV2ViewSet(BaseV2ViewSet):
    """V2 Role ViewSet."""

    queryset = RoleV2.objects.annotate(permissions_count_annotation=Count("permissions", distinct=True))
    serializer_class = RoleSerializer
    permission_classes = (RoleAccessPermission,)
    pagination_class = RoleV2CursorPagination

    def list(self, request, *args, **kwargs):
        """Get a list of roles."""
        queryset = self.get_queryset()

        # Handle name filter
        name = request.query_params.get("name")
        if name is not None:
            if not name.strip():
                name = None
            elif "\x00" in name:
                raise serializers.ValidationError({"name": "The 'name' query parameter contains invalid characters."})
        if name:
            queryset = queryset.filter(name__exact=name)

        # Prefetch permissions if requested
        requested_fields = parse_fields_param(request.query_params.get("fields"))
        if "permissions" in requested_fields:
            queryset = queryset.prefetch_related("permissions")

        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True)
        return self.get_paginated_response(serializer.data)
