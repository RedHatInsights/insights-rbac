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
from management.permissions.role_binding_access import (
    RoleBindingKesselAccessPermission,
    RoleBindingSystemUserAccessPermission,
)
from rest_framework.decorators import action

from api.common.pagination import V2CursorPagination
from .serializer import RoleBindingInputSerializer, RoleBindingOutputSerializer
from .service import RoleBindingService

logger = logging.getLogger(__name__)


class RoleBindingViewSet(BaseV2ViewSet):
    """Role Binding ViewSet.

    Provides read-only access to role bindings currently.

    Query Parameters (by-subject endpoint):
        Required:
            - resource_id: Filter by resource ID
            - resource_type: Filter by resource type

        Optional:
            - subject_type: Filter by subject type (e.g., 'group')
            - subject_id: Filter by subject ID
            - fields: Control which fields are included in the response
            - order_by: Sort by specified field(s), prefix with '-' for descending
    """

    serializer_class = RoleBindingOutputSerializer
    permission_classes = (
        RoleBindingSystemUserAccessPermission,
        RoleBindingKesselAccessPermission,
    )
    pagination_class = V2CursorPagination

    @action(detail=False, methods=["get"], url_path="by-subject")
    def by_subject(self, request, *args, **kwargs):
        """List role bindings grouped by subject.

        Required query parameters:
            - resource_id: Filter by resource ID
            - resource_type: Filter by resource type

        Optional query parameters:
            - subject_type: Filter by subject type (e.g., 'group')
            - subject_id: Filter by subject ID (UUID)
            - fields: Control which fields are included in the response
            - order_by: Sort by specified field(s), prefix with '-' for descending
        """
        # Validate and parse query parameters using input serializer
        input_serializer = RoleBindingInputSerializer(data=request.query_params)
        input_serializer.is_valid(raise_exception=True)
        validated_params = input_serializer.validated_data

        service = RoleBindingService(tenant=request.tenant)

        # Get role bindings queryset using validated parameters
        queryset = service.get_role_bindings_by_subject(validated_params)

        # Get virtual bindings and attach them to groups
        virtual_groups_map = service.get_virtual_bindings(
            validated_params["resource_id"], validated_params["resource_type"]
        )

        # Build context for output serializer
        context = {
            "request": request,
            "virtual_groups_map": virtual_groups_map,
            **service.build_context(validated_params),
        }

        page = self.paginate_queryset(queryset)

        # Attach virtual bindings to groups in the paginated results
        if virtual_groups_map and page:
            for group in page:
                group_uuid = str(group.uuid)
                if group_uuid in virtual_groups_map:
                    # Ensure filtered_bindings exists
                    if not hasattr(group, "filtered_bindings"):
                        group.filtered_bindings = []

                    # Create synthetic RoleBindingGroup-like objects for virtual bindings
                    for binding_id, role in virtual_groups_map[group_uuid]:
                        mock_binding_group = type(
                            "MockRoleBindingGroup",
                            (),
                            {
                                "binding": type(
                                    "MockRoleBinding",
                                    (),
                                    {
                                        "uuid": binding_id,
                                        "role": role,
                                        "resource_type": validated_params["resource_type"],
                                        "resource_id": validated_params["resource_id"],
                                    },
                                )(),
                            },
                        )()
                        group.filtered_bindings.append(mock_binding_group)

                    # Update latest_modified if needed
                    virtual_role_dates = [
                        r.modified for _, r in virtual_groups_map[group_uuid] if hasattr(r, "modified")
                    ]
                    if virtual_role_dates:
                        current_latest = getattr(group, "latest_modified", None)
                        if current_latest is None or max(virtual_role_dates) > current_latest:
                            group.latest_modified = max(virtual_role_dates)

        serializer = self.get_serializer(page, many=True, context=context)
        return self.get_paginated_response(serializer.data)
