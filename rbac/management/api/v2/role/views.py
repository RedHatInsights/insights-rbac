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
"""View for Role management."""

from management.api.v2.role.serializers import RoleInputSerializer, RoleOutputSerializer
from management.base_viewsets import BaseV2ViewSet
from management.permissions import RoleAccessPermission
from management.role.model import RoleV2
from management.v2_mixins import AtomicOperationsMixin
from rest_framework import status
from rest_framework.response import Response


class RoleViewSet(AtomicOperationsMixin, BaseV2ViewSet):
    """Role ViewSet for V2 API."""

    permission_classes = (RoleAccessPermission,)
    queryset = RoleV2.objects.none()
    serializer_class = RoleOutputSerializer
    lookup_field = "uuid"
    http_method_names = ["post", "head", "options"]

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == "create":
            return RoleInputSerializer
        return RoleOutputSerializer

    def create(self, request, *args, **kwargs):
        """Create a role and return the full response representation."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = serializer.save()
        input_permissions = request.data.get("permissions", [])
        output_serializer = RoleOutputSerializer(role, context={"input_permissions": input_permissions})
        return Response(output_serializer.data, status=status.HTTP_201_CREATED)
