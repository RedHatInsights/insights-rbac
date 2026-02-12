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
    RoleFieldSelection,
    RoleV2BulkDeleteRequestSerializer,
    RoleV2ListSerializer,
    RoleV2RequestSerializer,
    RoleV2ResponseSerializer,
    _validate_fields_parameter,
)
from management.role.v2_service import RoleV2Service
from management.utils import FieldSelectionValidationError
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
    http_method_names = ["get", "post", "put", "head", "options"]

    # Default fields for create/update operations (per API spec)
    DEFAULT_CREATE_UPDATE_FIELDS = {"id", "name", "description", "permissions", "last_modified"}

    def get_queryset(self):
        """Get queryset with optimizations, excluding platform roles only for non-read actions."""
        base_qs = RoleV2.objects.filter(tenant=self.request.tenant).prefetch_related("permissions")

        if self.action in ("list", "retrieve"):
            return base_qs
        else:
            return base_qs.filter(type=RoleV2.Types.CUSTOM)

    def get_serializer_context(self):
        """Add validated fields parameter to serializer context."""
        context = super().get_serializer_context()
        if self.action == "retrieve":
            fields_param = self.request.query_params.get("fields", "").replace("\x00", "")
            context["fields"] = _validate_fields_parameter(fields_param, RoleV2Service.DEFAULT_RETRIEVE_FIELDS)
        return context

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action in ("create", "update"):
            return RoleV2RequestSerializer
        if self.action == "bulk_destroy":
            return RoleV2BulkDeleteRequestSerializer
        return RoleV2ResponseSerializer

    def _parse_fields_param(self, fields_str: str | None) -> set[str]:
        """
        Parse and validate the fields query parameter.

        Args:
            fields_str: Comma-separated list of field names from query params

        Returns:
            Set of validated field names

        Note:
            Invalid fields are silently ignored and filtered out.
            If all fields are invalid, returns default fields.
        """
        if not fields_str:
            return self.DEFAULT_CREATE_UPDATE_FIELDS

        try:
            field_selection = RoleFieldSelection.parse(fields_str)
        except FieldSelectionValidationError:
            # Invalid fields - return defaults and let the request proceed
            return self.DEFAULT_CREATE_UPDATE_FIELDS

        if not field_selection:
            return self.DEFAULT_CREATE_UPDATE_FIELDS

        # Resolve to actual response serializer fields (filters out invalid fields)
        resolved = field_selection.root_fields & set(RoleV2ResponseSerializer.Meta.fields)
        return resolved or self.DEFAULT_CREATE_UPDATE_FIELDS

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
        # Validate and parse fields query parameter
        fields = self._parse_fields_param(request.query_params.get("fields"))

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = serializer.save()

        # Build response with field selection and permission ordering
        input_permissions = request.data.get("permissions", [])
        response_serializer = RoleV2ResponseSerializer(
            role, context={"input_permissions": input_permissions, "fields": fields}
        )
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        """Update a role and return the full response representation."""
        # Validate and parse fields query parameter
        fields = self._parse_fields_param(request.query_params.get("fields"))

        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        role = serializer.save()

        # Build response with field selection and permission ordering
        input_permissions = request.data.get("permissions", [])
        response_serializer = RoleV2ResponseSerializer(
            role, context={"input_permissions": input_permissions, "fields": fields}
        )
        return Response(response_serializer.data, status=status.HTTP_200_OK)

    @atomic
    def bulk_destroy(self, request, *args, **kwargs):
        """Delete multiple roles atomically."""
        service = RoleV2Service(tenant=request.tenant)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        ids = set(serializer.validated_data["ids"])

        try:
            service.bulk_delete(ids, from_tenant=self.request.tenant)
        except RoleNotFoundError as e:
            return Response({"title": "Resource was not found", "detail": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except CustomRoleRequiredError as e:
            # This should be impossible. We constrain deletions to be from the user's tenant. Non-custom roles should
            # only exist in the public tenant, and there shouldn't be any users in the public tenant. Thus,
            # we will never find any non-custom roles to try to delete.
            return Response(
                {"title": "An internal error occurred.", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(status=status.HTTP_204_NO_CONTENT)
