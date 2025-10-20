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

from django.db.models import Count, Prefetch, Q
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

        # Build queryset
        queryset = self._build_queryset(
            resource_id=resource_id,
            resource_type=resource_type,
            subject_type=subject_type,
            subject_id=subject_id,
            tenant=request.tenant,
        )

        # Apply ordering
        if order_by:
            queryset = self._apply_ordering(queryset, order_by)

        # Get resource details
        resource_name = self._get_resource_name(resource_id, resource_type, request.tenant)

        # Group by subject
        grouped_data = self._group_by_subject(queryset, resource_id, resource_name, resource_type, request.tenant)

        # Paginate results
        page = self.paginate_queryset(grouped_data)
        if page is not None:
            serializer = self.get_serializer(page, many=True, fields=fields)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(grouped_data, many=True, fields=fields)
        return Response(serializer.data)

    def _build_queryset(self, resource_id, resource_type, subject_type, subject_id, tenant):
        """Build the base queryset with filters."""
        queryset = RoleBinding.objects.filter(
            tenant=tenant, resource_type=resource_type, resource_id=resource_id
        ).select_related("role")

        # Create annotated Group queryset
        annotated_groups = Group.objects.annotate(
            principalCount=Count("principals", filter=Q(principals__type=Principal.Types.USER), distinct=True)
        )

        # Prefetch related groups with annotation
        group_queryset = RoleBindingGroup.objects.prefetch_related(
            Prefetch("group", queryset=annotated_groups)
        )

        # Apply subject filtering if specified
        if subject_type == "group" and subject_id:
            group_queryset = group_queryset.filter(group__uuid=subject_id)
        elif subject_type == "group":
            # If only type is specified, we just filter to groups (which is all we have in group_entries)
            pass
        elif subject_id and not subject_type:
            # If subject_id is provided without type, try to match on group uuid
            group_queryset = group_queryset.filter(group__uuid=subject_id)

        queryset = queryset.prefetch_related(Prefetch("group_entries", queryset=group_queryset))

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

    def _group_by_subject(self, queryset, resource_id, resource_name, resource_type, tenant):
        """Group role bindings by subject.

        Returns a list of dictionaries with subject, roles, resource, and metadata.
        """
        # Dictionary to hold grouped data: subject_key -> binding data
        grouped = {}

        for binding in queryset:
            # Get all groups for this binding
            for group_entry in binding.group_entries.all():
                group = group_entry.group
                subject_key = f"group_{group.uuid}"

                if subject_key not in grouped:
                    # Use the role's modified timestamp
                    modified_time = binding.role.modified if binding.role else None

                    grouped[subject_key] = {
                        "modified": modified_time,
                        "subject": {
                            "id": group.uuid,
                            "type": "group",
                            "group": {
                                "name": group.name,
                                "description": group.description,
                                "principalCount": group.principalCount,
                            },
                        },
                        "roles": [],
                        "resource": {
                            "id": resource_id,
                            "name": resource_name,
                            "type": resource_type,
                        },
                    }

                # Add role data
                role_data = {"uuid": binding.role.uuid, "name": binding.role.name}
                if role_data not in grouped[subject_key]["roles"]:
                    grouped[subject_key]["roles"].append(role_data)

                # Update modified timestamp to the latest role modified time
                if binding.role and binding.role.modified:
                    current_modified = grouped[subject_key].get("modified")
                    if not current_modified or binding.role.modified > current_modified:
                        grouped[subject_key]["modified"] = binding.role.modified

        return list(grouped.values())

    def _apply_ordering(self, queryset, order_by):
        """Apply ordering to queryset."""
        order_fields = [field.strip() for field in order_by.split(",")]
        return queryset.order_by(*order_fields)
