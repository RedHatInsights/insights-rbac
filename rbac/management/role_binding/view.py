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

from django.db.models import Count, Max, Prefetch, Q
from management.base_viewsets import BaseV2ViewSet
from management.models import Group
from management.permissions.workspace_access import WorkspaceAccessPermission
from management.principal.model import Principal
from management.role.v2_model import RoleBinding, RoleBindingGroup
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

        queryset = self._build_group_queryset(
            resource_id=resource_id,
            resource_type=resource_type,
            tenant=request.tenant,
        )

        request.resource_id = resource_id
        request.resource_type = resource_type
        request.resource_name = self._get_resource_name(resource_id, resource_type, request.tenant)

        serializer = self.get_serializer(queryset, many=True, context={"request": request})
        return Response(serializer.data)

    def _build_group_queryset(self, resource_id, resource_type, tenant):
        """Build a queryset of groups with their role bindings for the specified resource.

        Returns a queryset of Group objects annotated with:
        - principalCount: Count of user principals in the group
        - latest_modified: Latest modification timestamp from associated roles
        Each group will have prefetched role bindings filtered by resource.
        """
        # Start with groups that have bindings to the specified resource
        queryset = Group.objects.filter(
            tenant=tenant,
            role_binding_entries__binding__resource_type=resource_type,
            role_binding_entries__binding__resource_id=resource_id,
        ).distinct()

        # Annotate with principal count
        queryset = queryset.annotate(
            principalCount=Count("principals", filter=Q(principals__type=Principal.Types.USER), distinct=True)
        )

        # Prefetch the role bindings for this resource with their roles
        binding_queryset = RoleBinding.objects.filter(
            resource_type=resource_type, resource_id=resource_id
        ).select_related("role")

        # Prefetch the join table entries with the filtered bindings
        rolebinding_group_queryset = RoleBindingGroup.objects.filter(
            binding__resource_type=resource_type, binding__resource_id=resource_id
        ).prefetch_related(Prefetch("binding", queryset=binding_queryset))

        queryset = queryset.prefetch_related(
            Prefetch("role_binding_entries", queryset=rolebinding_group_queryset, to_attr="filtered_bindings")
        )

        # Annotate with latest modified timestamp from roles
        queryset = queryset.annotate(latest_modified=Max("role_binding_entries__binding__role__modified"))

        return queryset

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
