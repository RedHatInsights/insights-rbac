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

from .pagination import RoleBindingCursorPagination
from .serializer import RoleBindingBySubjectSerializer

logger = logging.getLogger(__name__)


class RoleBindingViewSet(BaseV2ViewSet):
    """Role Binding ViewSet.

    Provides read-only access to role bindings currently.
    """

    permission_classes = (WorkspaceAccessPermission,)
    serializer_class = RoleBindingBySubjectSerializer
    pagination_class = RoleBindingCursorPagination

    @action(detail=False, methods=["get"], url_path="by-subject")
    def by_subject(self, request, *args, **kwargs):
        """List role bindings grouped by subject.

        Required query parameters:
            - resource_id: Filter by resource ID
            - resource_type: Filter by resource type

        Optional query parameters:
            - subject_type: Filter by subject type (user/group)
            - subject_id: Filter by subject ID
            - fields: Control which fields are included in response
            - order_by: Sort by specified field(s)
            - limit: Number of results per page (default: 10)
            - cursor: Cursor for pagination
        """
        # Validate required parameters
        resource_id = request.query_params.get("resource_id")
        resource_type = request.query_params.get("resource_type")

        if not resource_id:
            raise serializers.ValidationError({"resource_id": "This query parameter is required."})
        if not resource_type:
            raise serializers.ValidationError({"resource_type": "This query parameter is required."})

        # Optional parameters
        subject_type = request.query_params.get("subject_type")
        subject_id = request.query_params.get("subject_id")
        fields = request.query_params.get("fields")
        order_by = request.query_params.get("order_by")

        # Build queryset based on subject type
        if subject_type == "user":
            queryset = self._build_principal_queryset(
                resource_id=resource_id,
                resource_type=resource_type,
                subject_id=subject_id,
                tenant=request.tenant,
            )
        else:
            # Default to groups (both when subject_type="group" or not specified)
            queryset = self._build_group_queryset(
                resource_id=resource_id,
                resource_type=resource_type,
                subject_type=subject_type,
                subject_id=subject_id,
                tenant=request.tenant,
            )

        # Apply ordering
        if order_by:
            queryset = self._apply_ordering(queryset, order_by)
        else:
            # Default ordering for cursor pagination
            queryset = queryset.order_by("-latest_modified")

        # Store resource info in request context for serializer
        request.resource_id = resource_id
        request.resource_type = resource_type
        request.resource_name = self._get_resource_name(resource_id, resource_type, request.tenant)

        # Paginate results
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True, fields=fields, context={"request": request})
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True, fields=fields, context={"request": request})
        return Response(serializer.data)

    def _build_group_queryset(self, resource_id, resource_type, subject_type, subject_id, tenant):
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

        # Apply subject filtering if specified
        if subject_type == "group" and subject_id:
            queryset = queryset.filter(uuid=subject_id)
        elif subject_id and not subject_type:
            # If subject_id is provided without type, try to match on group uuid
            queryset = queryset.filter(uuid=subject_id)

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

    def _build_principal_queryset(self, resource_id, resource_type, subject_id, tenant):
        """Build a queryset of principals (users) with their role bindings for the specified resource.

        Returns a queryset of Principal objects annotated with:
        - latest_modified: Latest modification timestamp from associated roles

        Each principal will have prefetched groups and their role bindings filtered by resource.
        """
        # Start with principals that belong to groups with bindings to the specified resource
        queryset = Principal.objects.filter(
            tenant=tenant,
            type=Principal.Types.USER,
            group__role_binding_entries__binding__resource_type=resource_type,
            group__role_binding_entries__binding__resource_id=resource_id,
        ).distinct()

        # Apply subject filtering if specified
        if subject_id:
            queryset = queryset.filter(uuid=subject_id)

        # Prefetch the role bindings through groups
        binding_queryset = RoleBinding.objects.filter(
            resource_type=resource_type, resource_id=resource_id
        ).select_related("role")

        # Prefetch the join table entries with the filtered bindings
        rolebinding_group_queryset = RoleBindingGroup.objects.filter(
            binding__resource_type=resource_type, binding__resource_id=resource_id
        ).prefetch_related(Prefetch("binding", queryset=binding_queryset))

        # Prefetch groups with their filtered bindings
        group_queryset = Group.objects.prefetch_related(
            Prefetch("role_binding_entries", queryset=rolebinding_group_queryset, to_attr="filtered_bindings")
        )

        queryset = queryset.prefetch_related(Prefetch("group", queryset=group_queryset, to_attr="filtered_groups"))

        # Annotate with latest modified timestamp from roles
        queryset = queryset.annotate(latest_modified=Max("group__role_binding_entries__binding__role__modified"))

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

    def _apply_ordering(self, queryset, order_by):
        """Apply ordering to queryset."""
        order_fields = [field.strip() for field in order_by.split(",")]
        return queryset.order_by(*order_fields)
