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
from management.role.v2_serializer import RoleV2RequestSerializer, RoleV2ResponseSerializer
from management.v2_mixins import AtomicOperationsMixin
from rest_framework import status
from rest_framework.response import Response


class RoleV2ViewSet(AtomicOperationsMixin, BaseV2ViewSet):
    """RoleV2 ViewSet."""

    permission_classes = (RoleAccessPermission,)
    queryset = RoleV2.objects.none()
    serializer_class = RoleV2ResponseSerializer
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
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == "create":
            return RoleV2RequestSerializer
        return RoleV2ResponseSerializer

    def create(self, request, *args, **kwargs):
        """Create a role and return the full response representation."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = serializer.save()
        input_permissions = request.data.get("permissions", [])
        response_serializer = RoleV2ResponseSerializer(role, context={"input_permissions": input_permissions})
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)
