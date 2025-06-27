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
import uuid

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django_filters import rest_framework as filters
from management.base_viewsets import BaseV2ViewSet
from management.permissions.workspace_access import WorkspaceAccessPermission
from management.utils import validate_and_get_key
from management.workspace.service import WorkspaceService
from management.workspace.utils import is_user_allowed
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter
from rest_framework.permissions import SAFE_METHODS
from rest_framework.request import Request

from .model import Workspace
from .serializer import WorkspaceSerializer, WorkspaceWithAncestrySerializer
from ..utils import validate_uuid

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

    def __init__(self, **kwargs):
        """Init viewset."""
        super().__init__(**kwargs)
        self._service = WorkspaceService()

    def get_serializer_class(self):
        """Get serializer class based on route."""
        if self.action == "retrieve":
            include_ancestry = validate_and_get_key(
                self.request.query_params, INCLUDE_ANCESTRY_KEY, VALID_BOOLEAN_VALUES, "false"
            )
            if include_ancestry == "true":
                return WorkspaceWithAncestrySerializer
        return super().get_serializer_class()

    def get_queryset(self):
        """Get queryset override."""
        if self.request.method not in SAFE_METHODS:
            return super().get_queryset().select_for_update()
        return super().get_queryset()

    def create(self, request, *args, **kwargs):
        """Create a Workspace."""
        tenant = request.tenant
        parent_id = request.data.get("parent_id")

        if parent_id and tenant:
            if not Workspace.objects.filter(id=parent_id, tenant=tenant).exists():
                raise serializers.ValidationError(
                    {"parent_id": f"Parent workspace '{parent_id}' doesn't exist in tenant"}
                )
        return super().create(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a workspace."""
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Get a list of workspaces."""
        all_types = "all"
        queryset = self.get_queryset()
        if getattr(request, "permission_tuples", None):
            permitted_wss = [tuple[1] for tuple in request.permission_tuples]
            queryset = queryset.filter(id__in=permitted_wss)
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

    @transaction.atomic()
    def destroy(self, request, *args, **kwargs):
        """
        Destroy the instance.

        Overridden only to add transaction.
        """
        return super().destroy(request, *args, **kwargs)

    def perform_destroy(self, instance):
        """Delegate to service for destroy logic."""
        self._service.destroy(instance)

    @transaction.atomic()
    def update(self, request, *args, **kwargs):
        """Update a workspace."""
        return super().update(request, *args, **kwargs)

    @action(detail=True, methods=["post"], url_path="move")
    @transaction.atomic()
    def move(self, request, *args, **kwargs):
        """Move a workspace under new parent."""
        new_parent_id = self._parent_id_query_param_validation(request)
        self._check_target_workspace_write_access(request, new_parent_id)
        return self._service.move(self.get_object(), new_parent_id)

    def _check_target_workspace_write_access(self, request, target_workspace_id: uuid.UUID) -> None:
        """Check if user has write access to the target workspace."""
        # Admin users bypass all access checks
        if request.user.admin:
            return

        if not is_user_allowed(request, "write", str(target_workspace_id)):
            raise PermissionDenied("You do not have write access to the target workspace.")

    @staticmethod
    def _parent_id_query_param_validation(request: Request) -> uuid.UUID:
        """Validate the parent_id query parameter."""
        new_parent_id = request.data.get("parent_id")
        if not new_parent_id:
            raise serializers.ValidationError({"parent_id": "The 'parent_id' field is required."})
        validate_uuid(new_parent_id)
        return uuid.UUID(new_parent_id)
