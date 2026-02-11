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

from uuid import UUID

from django.http import Http404
from management.base_viewsets import BaseV2ViewSet
from management.permissions import RoleAccessPermission
from management.role.v2_exceptions import RoleNotFoundError
from management.role.v2_model import RoleV2
from management.role.v2_serializer import RoleV2ListSerializer, RoleV2RequestSerializer, RoleV2ResponseSerializer
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

    def get_queryset(self):
        """Get the queryset for roles filtered by tenant."""
        base_qs = (
            RoleV2.objects.filter(tenant=self.request.tenant)
            .prefetch_related("permissions")
            .order_by("name", "-modified")
        )

        if self.action in ("list", "retrieve"):
            return base_qs
        else:
            return base_qs.filter(type=RoleV2.Types.CUSTOM)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a single role by UUID."""
        # Step 1: Validate input using input serializer (always validate for consistency)
        input_serializer = RoleV2ListSerializer(
            data={"fields": request.query_params.get("fields", "")}, context={"request": request}
        )
        input_serializer.is_valid(raise_exception=True)
        validated_params = input_serializer.validated_data

        # Step 2: Use service layer for business logic (consistent with list)
        try:
            uuid_str = kwargs.get(self.lookup_field)
            uuid_obj = UUID(uuid_str)  # Convert string to UUID
            service = RoleV2Service(tenant=request.tenant)
            instance = service.get_role(uuid_obj)
        except (ValueError, RoleNotFoundError) as e:
            # ValueError: invalid UUID format
            # RoleNotFoundError: role not found for tenant
            raise Http404(str(e))

        # Step 3: Build context from validated_params (consistent with list)
        # For retrieve: use DEFAULT_RETRIEVE_FIELDS if no fields param provided
        if request.query_params.get("fields"):
            # User explicitly provided fields param - use validated value
            fields = validated_params.get("fields")
        else:
            # No fields param - use retrieve default (includes permissions)
            fields = RoleV2Service.DEFAULT_RETRIEVE_FIELDS
        context = {
            "request": request,
            "fields": fields,
        }

        # Step 4: Serialize and return
        serializer = RoleV2ResponseSerializer(instance, context=context)
        return Response(serializer.data)

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == "create":
            return RoleV2RequestSerializer
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
