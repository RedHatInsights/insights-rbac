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
import logging

from django.db.models import Count, Prefetch
from django_filters import rest_framework as filters
from management.base_viewsets import BaseV2ViewSet
from management.models import Permission
from management.permissions import RoleAccessPermission
from rest_framework.filters import OrderingFilter
from rest_framework.response import Response

from api.common.pagination import V2CursorPagination
from .v2_model import RoleV2
from .v2_serializer import RoleInputSerializer, RoleOutputSerializer

logger = logging.getLogger(__name__)


class RoleOrderingFilter(OrderingFilter):
    """Custom ordering filter that maps API field names to model field names."""

    # Mapping API field names to model field names
    FIELD_MAPPING = {
        "last_modified": "modified",
        "permissions_count": "permissions_count_annotation",
    }

    def get_ordering(self, request, queryset, view):
        """Override to map API field names to model field names."""
        ordering = super().get_ordering(request, queryset, view)
        if ordering:
            mapped = []
            for field in ordering:
                descending = field.startswith("-")
                field_name = field.lstrip("-")

                model_field = self.FIELD_MAPPING.get(field_name, field_name)

                # Add back prefix if descending
                mapped.append(f"-{model_field}" if descending else model_field)
            return mapped
        return ordering


class RoleV2CursorPagination(V2CursorPagination):
    """Cursor pagination for roles."""

    ORDERING_FIELD_MAPPING = {
        "last_modified": "modified",
        "permissions_count": "permissions_count_annotation",
    }

    def get_ordering(self, request, queryset, view):
        """Map API ordering fields to model fields."""
        order_by = request.query_params.get("order_by")
        if not order_by:
            return super().get_ordering(request, queryset, view)

        order_fields = []
        for f in order_by.split(","):
            stripped = f.strip()
            if stripped:
                order_fields.append(stripped)
        if not order_fields:
            return super().get_ordering(request, queryset, view)

        mapped_fields = []
        for field in order_fields:
            descending = field.startswith("-")
            field_name = field.lstrip("-")
            mapped = self.ORDERING_FIELD_MAPPING.get(field_name, field_name)
            mapped_fields.append(f"-{mapped}" if descending else mapped)

        try:
            ordered = queryset.order_by(*mapped_fields)
            str(ordered.query)
            return tuple(mapped_fields)
        except Exception:
            return super().get_ordering(request, queryset, view)


class RoleV2ViewSet(BaseV2ViewSet):
    """V2 Role ViewSet.

    Provides read-only access to roles with filtering, sorting, and field selection.

    Query Parameters:
        - limit: Number of results per page (default: 10)
        - cursor: Cursor for pagination
        - name: Filter by role name (case-sensitive exact match)
        - fields: Comma-separated list of optional fields to include (default: id, name, description)
        - order_by: Sort field(s), prefix with '-' for descending

    Example:
        GET
        /api/rbac/v2/roles/?name=admin&fields=name,description,permissions_count,last_modified&order_by=-last_modified
    """

    queryset = RoleV2.objects.annotate(permissions_count_annotation=Count("permissions", distinct=True))
    serializer_class = RoleOutputSerializer
    permission_classes = (RoleAccessPermission,)
    pagination_class = RoleV2CursorPagination
    filter_backends = (filters.DjangoFilterBackend, RoleOrderingFilter)
    # Allowed ordering fields
    ordering_fields = ("name", "description", "permissions_count", "last_modified")
    ordering = ("name", "-modified")
    ordering_param = "order_by"

    def get_queryset(self):
        """Get queryset filtered by tenant."""
        return super().get_queryset().filter(tenant=self.request.tenant)

    def list(self, request, *args, **kwargs):
        """Obtain the list of roles for the tenant.

        @api {get} /api/rbac/v2/roles/
        @apiName getRoles
        @apiGroup Role
        @apiVersion 2.0.0
        @apiDescription Obtain a list of roles

        @apiParam (Query) {String} name Filter by role name.
        @apiParam (Query) {String} fields Control which fields are included.
        @apiParam (Query) {String} order_by Sort by specified field(s), prefix with '-' for descending.

        @apiSuccess {Object} meta The metadata for pagination.
        @apiSuccess {Object} links  The object containing links of results.
        @apiSuccess {Object[]} data  The array of results.
        """
        # Validate and parse query parameters using input serializer
        input_serializer = RoleInputSerializer(data=request.query_params)
        input_serializer.is_valid(raise_exception=True)
        validated_data = input_serializer.validated_data

        queryset = self.filter_queryset(self.get_queryset())

        # Handle name filter
        name = validated_data.get("name")
        if name:
            queryset = queryset.filter(name__iexact=name)

        field_selection = validated_data.get("fields")

        # Speed up grabbing permissions if requested
        if field_selection and "permissions" in field_selection.selected_fields:
            queryset = queryset.prefetch_related(
                Prefetch("permissions", queryset=Permission.objects.all(), to_attr="prefetched_permissions")
            )

        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(
            page if page is not None else queryset,
            many=True,
            context={
                "request": request,
                "field_selection": field_selection,
            },
        )
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)
