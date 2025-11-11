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
"""View for role binding management."""
import logging

from management.base_viewsets import BaseV2ViewSet
from management.permissions.workspace_access import WorkspaceAccessPermission
from management.querysets import get_role_binding_groups_queryset
from management.workspace.model import Workspace
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.response import Response

from .serializer import RoleBindingByGroupSerializer

logger = logging.getLogger(__name__)


class RoleBindingViewSet(BaseV2ViewSet):
    """Role Binding ViewSet.

    Provides read-only access to role bindings currently.
    """

    serializer_class = RoleBindingByGroupSerializer
    permission_classes = (WorkspaceAccessPermission,)

    @action(detail=False, methods=["get"], url_path="by-subject")
    def by_subject(self, request, *args, **kwargs):
        """List role bindings grouped by subject.

        Required query parameters:
            - resource_id: Filter by resource ID
            - resource_type: Filter by resource type
        """
        resource_id = request.query_params.get("resource_id")
        resource_type = request.query_params.get("resource_type")

        if not resource_id:
            raise serializers.ValidationError({"resource_id": "This query parameter is required."})
        if not resource_type:
            raise serializers.ValidationError({"resource_type": "This query parameter is required."})

        queryset = get_role_binding_groups_queryset(
            resource_id=resource_id,
            resource_type=resource_type,
            tenant=request.tenant,
        )

        context = {
            "request": request,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "resource_name": self._get_resource_name(resource_id, resource_type, request.tenant),
        }

        serializer = self.get_serializer(queryset, many=True, context=context)
        return Response(serializer.data)

    def _get_resource_name(self, resource_id, resource_type, tenant):
        """Get the name of the resource."""
        if resource_type == "workspace":
            try:
                workspace = Workspace.objects.get(id=resource_id, tenant=tenant)
                return workspace.name
            except Workspace.DoesNotExist:
                logger.warning(f"Workspace {resource_id} not found for tenant {tenant}")
                return None
        return None
