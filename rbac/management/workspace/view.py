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
import json

from django.utils.translation import gettext as _
from django_filters import rest_framework as filters
from management.base_viewsets import BaseV2ViewSet
from management.permissions import WorkspaceAccessPermission
from management.utils import validate_and_get_key, validate_uuid
from rest_framework import serializers
from rest_framework.filters import OrderingFilter

from .model import Workspace
from .serializer import WorkspaceSerializer, WorkspaceWithAncestrySerializer

VALID_PATCH_FIELDS = ["name", "description", "parent_id"]
REQUIRED_PUT_FIELDS = ["name", "description", "parent_id"]
REQUIRED_CREATE_FIELDS = ["name"]
INCLUDE_ANCESTRY_KEY = "include_ancestry"
VALID_BOOLEAN_VALUES = ["true", "false"]


class WorkspaceViewSet(BaseV2ViewSet):
    """Workspace View.

    A viewset that provides default `create()`, `destroy` and `retrieve()`.

    """

    permission_classes = (WorkspaceAccessPermission,)
    queryset = Workspace.objects.annotate()
    lookup_field = "uuid"
    serializer_class = WorkspaceSerializer
    ordering_fields = ("name",)
    ordering = ("name",)
    filter_backends = (filters.DjangoFilterBackend, OrderingFilter)

    def get_serializer_class(self):
        """Get serializer class based on route."""
        if self.action == "retrieve":
            include_ancestry = validate_and_get_key(
                self.request.query_params, INCLUDE_ANCESTRY_KEY, VALID_BOOLEAN_VALUES, "false"
            )
            if include_ancestry == "true":
                return WorkspaceWithAncestrySerializer
        return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        """Create a Workspace."""
        self.validate_workspace(request)
        return super().create(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a workspace."""
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Get a list of workspaces."""
        all_types = "all"
        queryset = self.get_queryset()
        type_values = Workspace.Types.values + [all_types]
        type_field = validate_and_get_key(request.query_params, "type", type_values, all_types)

        if type_field != all_types:
            queryset = queryset.filter(type=type_field)

        serializer = self.get_serializer(queryset, many=True)
        page = self.paginate_queryset(serializer.data)
        return self.get_paginated_response(page)

    def destroy(self, request, *args, **kwargs):
        """Delete a workspace."""
        instance = self.get_object()
        if Workspace.objects.filter(parent=instance, tenant=instance.tenant).exists():
            message = "Unable to delete due to workspace dependencies"
            error = {"workspace": [_(message)]}
            raise serializers.ValidationError(error)
        return super().destroy(request=request, args=args, kwargs=kwargs)

    def update(self, request, *args, **kwargs):
        """Update a workspace."""
        self.validate_workspace(request, "put")
        self.update_validation(request)
        return super().update(request=request, args=args, kwargs=kwargs)

    def partial_update(self, request, *args, **kwargs):
        """Patch a workspace."""
        payload = json.loads(request.body or "{}")
        for field in payload:
            if field not in VALID_PATCH_FIELDS:
                message = f"Field '{field}' is not supported. Please use one or more of: {VALID_PATCH_FIELDS}."
                error = {"workspace": [_(message)]}
                raise serializers.ValidationError(error)

        self.update_validation(request)

        return super().update(request=request, args=args, kwargs=kwargs)

    def update_validation(self, request):
        """Validate a workspace for update."""
        instance = self.get_object()
        parent_id = request.data.get("parent_id")
        if str(instance.uuid) == parent_id:
            message = "Parent ID and UUID can't be same"
            error = {"workspace": [_(message)]}
            raise serializers.ValidationError(error)

    def validate_required_fields(self, request, required_fields):
        """Validate required fields for workspace."""
        for field in required_fields:
            if field not in request.data:
                message = f"Field '{field}' is required."
                error = {"workspace": [_(message)]}
                raise serializers.ValidationError(error)

    def validate_workspace(self, request, action="create"):
        """Validate a workspace."""
        parent_id = request.data.get("parent_id")
        tenant = request.tenant
        if action == "create":
            self.validate_required_fields(request, REQUIRED_CREATE_FIELDS)
        else:
            self.validate_required_fields(request, REQUIRED_PUT_FIELDS)
            if parent_id is None:
                message = "Field 'parent_id' can't be null."
                error = {"workspace": [_(message)]}
                raise serializers.ValidationError(error)
        if parent_id:
            validate_uuid(parent_id)
            if not Workspace.objects.filter(uuid=parent_id, tenant=tenant).exists():
                message = f"Parent workspace '{parent_id}' doesn't exist in tenant"
                error = {"workspace": [message]}
                raise serializers.ValidationError(error)
