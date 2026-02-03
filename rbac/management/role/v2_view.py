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
from management.role.v2_serializer import RoleV2ResponseSerializer
from management.role.v2_service import RoleV2Service
from management.v2_mixins import AtomicOperationsMixin
from rest_framework import serializers
from rest_framework.response import Response

# Default fields returned when no fields parameter is specified
DEFAULT_ROLE_FIELD_MASK = "id,name,description,permissions,last_modified"

# All valid fields that can be requested
VALID_ROLE_FIELDS = {
    "id",
    "name",
    "description",
    "permissions",
    "permissions_count",
    "last_modified",
}


class RoleV2ViewSet(AtomicOperationsMixin, BaseV2ViewSet):
    """RoleV2 ViewSet."""

    permission_classes = (RoleAccessPermission,)
    queryset = RoleV2.objects.all()
    serializer_class = RoleV2ResponseSerializer
    lookup_field = "uuid"
    http_method_names = ["get", "head", "options"]

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

    def get_serializer_context(self):
        """Add fields parameter to serializer context for retrieve/list operations."""
        context = super().get_serializer_context()

        # Only apply field filtering for retrieve and list actions
        if self.action in ("retrieve", "list"):
            # Parse and validate fields parameter
            fields_param = self.request.query_params.get("fields", DEFAULT_ROLE_FIELD_MASK)
            if fields_param:
                # Validate requested fields
                requested_fields = set(fields_param.split(","))
                invalid_fields = requested_fields - VALID_ROLE_FIELDS

                if invalid_fields:
                    raise serializers.ValidationError(
                        {
                            "fields": f"Invalid field(s): {', '.join(sorted(invalid_fields))}. "
                            f"Valid fields are: {', '.join(sorted(VALID_ROLE_FIELDS))}"
                        }
                    )

                context["fields"] = fields_param

        return context

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a single role by UUID."""
        uuid = kwargs.get("uuid")

        # Initialize service with tenant
        service = RoleV2Service(tenant=request.tenant)

        try:
            # Get role via service
            role = service.get_role(UUID(uuid))

            # Serialize with field filtering
            serializer = self.get_serializer(role)
            return Response(serializer.data)

        except RoleNotFoundError as e:
            raise Http404(str(e))
