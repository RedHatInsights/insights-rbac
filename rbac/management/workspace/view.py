#
# Copyright 2019 Red Hat, Inc.
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
"""View for Workspace management."""
from django.core.exceptions import ValidationError as DjangoValidationError

# from django.db import transaction
from django_filters import rest_framework as filters
from rest_framework.filters import OrderingFilter
from management.base_viewsets import BaseV2ViewSet
from management.permissions import WorkspaceAccessPermission

# from management.relation_replicator.relation_replicator import ReplicationEventType
# from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspacepHandler
from rest_framework.exceptions import ValidationError
from management.utils import validate_and_get_key

from .model import Workspace
from .serializer import WorkspacePatchSerializer, WorkspaceSerializer, WorkspaceWithAncestrySerializer

INCLUDE_ANCESTRY_KEY = "include_ancestry"
VALID_BOOLEAN_VALUES = ["true", "false"]


class WorkspaceViewSet(BaseV2ViewSet):
    """Workspace View.

    A viewset that provides default `create()`, `destroy` and `retrieve()`.

    """

    permission_classes = (WorkspaceAccessPermission,)
    queryset = Workspace.objects.annotate()
    serializer_class = WorkspaceSerializer
    ordering_fields = ("name",)
    ordering = ("name",)
    filter_backends = (filters.DjangoFilterBackend, OrderingFilter)

    def get_serializer_class(self):
        """Get serializer class based on route."""
        if self.action == "partial_update":
            return WorkspacePatchSerializer
        if self.action == "retrieve":
            include_ancestry = validate_and_get_key(
                self.request.query_params, INCLUDE_ANCESTRY_KEY, VALID_BOOLEAN_VALUES, "false"
            )
            if include_ancestry == "true":
                return WorkspaceWithAncestrySerializer
        return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        """Create a Workspace."""
        return super().create(request=request, args=args, kwargs=kwargs)

    def perform_create(self, serializer):
        """Perform create operation."""
        try:
            return super().perform_create(serializer)
        except DjangoValidationError as e:
            # Use structured error checking by inspecting error codes
            message = e.message_dict
            if hasattr(e, "error_dict") and "__all__" in e.error_dict:
                for error in e.error_dict["__all__"]:
                    for msg in error.messages:
                        if "unique_workspace_name_per_parent" in msg:
                            message = "Can't create workspace with same name within same parent workspace"
                            break
            raise ValidationError(message)

    def retrieve(self, request, *args, **kwargs):
        """Get a workspace."""
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Get a list of workspaces."""
        all_types = "all"
        queryset = self.get_queryset()
        type_values = Workspace.Types.values + [all_types]
        type_field = validate_and_get_key(request.query_params, "type", type_values, all_types)
        name = request.query_params.get("name")

        if type_field != all_types:
            queryset = queryset.filter(type=type_field)
        if name:
            queryset = queryset.filter(name__iexact=name.lower())

        serializer = self.get_serializer(queryset, many=True)
        page = self.paginate_queryset(serializer.data)
        return self.get_paginated_response(page)

    def destroy(self, request, *args, **kwargs):
        """Delete a workspace."""
        pass
        # instance = self.get_object()
        # if instance.type != Workspace.Types.STANDARD:
        #     message = f"Unable to delete {instance.type} workspace"
        #     error = {"workspace": [_(message)]}
        #     raise serializers.ValidationError(error)
        # if Workspace.objects.filter(parent=instance, tenant=instance.tenant).exists():
        #     message = "Unable to delete due to workspace dependencies"
        #     error = {"workspace": [_(message)]}
        #     raise serializers.ValidationError(error)
        # with transaction.atomic():
        #     instance = Workspace.objects.select_for_update().filter(id=instance.id).get()
        #     response = super().destroy(request=request, args=args, kwargs=kwargs)
        #   dual_write_handler = RelationApiDualWriteWorkspacepHandler(
        #                           instance,
        #                           ReplicationEventType.DELETE_WORKSPACE
        #                       )
        #     dual_write_handler.replicate_deleted_workspace()
        # return response

        # NEED TO VALIDATE DELETE HERE
        return super().destroy(request=request, args=args, kwargs=kwargs)

    def update(self, request, *args, **kwargs):
        """Update a workspace."""
        return super().update(request=request, args=args, kwargs=kwargs)

    def partial_update(self, request, *args, **kwargs):
        """Patch a workspace."""
        return super().update(request=request, args=args, kwargs=kwargs)
