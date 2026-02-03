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
from django_filters import rest_framework as filters
from management.base_viewsets import BaseV2ViewSet
from management.permissions import RoleAccessPermission
from management.role_binding.serializer import FieldSelectionValidationError
from rest_framework import serializers

from api.common.pagination import V2CursorPagination
from .v2_model import RoleV2
from .v2_serializer import RoleFieldSelection, RoleSerializer


class RoleV2CursorPagination(V2CursorPagination):
    """Cursor pagination for roles."""

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
    """V2 Role ViewSet."""

    queryset = RoleV2.objects.all()
    serializer_class = RoleSerializer
    permission_classes = (RoleAccessPermission,)
    pagination_class = RoleV2CursorPagination
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = {"name": ["exact"]}

    def get_queryset(self):
        """Return queryset based on requested fields."""
        queryset = super().get_queryset()

        try:
            field_selection = RoleFieldSelection.parse(self.request.query_params.get("fields"))
        except FieldSelectionValidationError as e:
            raise serializers.ValidationError(e.message)

        if field_selection:
            if "permissions_count" in field_selection.root_fields:
                queryset = queryset.annotate(permissions_count_annotation=Count("permissions", distinct=True))
            if "permissions" in field_selection.root_fields:
                queryset = queryset.prefetch_related("permissions")

        return queryset

    def list(self, request, *args, **kwargs):
        """Get a list of roles."""
        return super().list(request, *args, **kwargs)
