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
from management.permissions import WorkspaceAccessPermission
from management.utils import validate_uuid
from rest_framework import mixins, serializers, viewsets
from rest_framework.filters import OrderingFilter

from .model import Workspace
from .serializer import WorkspaceSerializer

VALID_PATCH_FIELDS = ["name", "description", "parent"]
REQUIRED_PUT_FIELDS = ["name", "description", "parent"]
REQUIRED_CREATE_FIELDS = ["name"]
DEPTH_KEY = "depth"


class WorkspaceViewSet(
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
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

    def create(self, request, *args, **kwargs):
        """Create a Workspace."""
        self.validate_workspace(request)
        return super().create(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a workspace."""
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def get_queryset_for_depth(self, queryset, current_depth, max_depth):
        """Get queryset for depth recursively."""
        if current_depth >= max_depth:
            return queryset
        descendents = Workspace.objects.filter(parent__in=queryset)
        if not descendents.exists():
            return queryset
        queryset = descendents | queryset
        return self.get_queryset_for_depth(queryset, current_depth + 1, max_depth)

    def list(self, request, *args, **kwargs):
        """Return workspaces."""
        depth = self.validate_depth(request)
        queryset = self.get_queryset()
        if depth != -1:
            queryset = queryset.filter(parent__isnull=True)
            queryset = self.get_queryset_for_depth(queryset, current_depth=1, max_depth=depth)

        serializer = self.get_serializer(queryset, many=True)
        page = self.paginate_queryset(serializer.data)
        return self.get_paginated_response(page)

    def validate_depth(self, request):
        """Validate the depth param."""
        depth = request.query_params.get(DEPTH_KEY)
        if depth:
            err_message = f"{depth} is not a valid depth value. Use -1 for all, or specify a positive integer value."
            try:
                depth_int = int(depth)
                if depth_int > 0 or depth_int == -1:
                    return depth_int
                else:
                    raise serializers.ValidationError({"depth": _(err_message)})
            except ValueError:
                raise serializers.ValidationError({"depth": _(err_message)})

        return -1

    def destroy(self, request, *args, **kwargs):
        """Delete a workspace."""
        instance = self.get_object()
        if Workspace.objects.filter(parent=instance.uuid, tenant=instance.tenant).exists():
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
        parent = request.data.get("parent")
        if str(instance.uuid) == parent:
            message = "Parent and UUID can't be same"
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
        parent = request.data.get("parent")
        tenant = request.tenant
        if action == "create":
            self.validate_required_fields(request, REQUIRED_CREATE_FIELDS)
        else:
            self.validate_required_fields(request, REQUIRED_PUT_FIELDS)
            if parent is None:
                message = "Field 'parent' can't be null."
                error = {"workspace": [_(message)]}
                raise serializers.ValidationError(error)
            validate_uuid(parent)
            if not Workspace.objects.filter(uuid=parent, tenant=tenant).exists():
                message = f"Parent workspace '{parent}' doesn't exist in tenant"
                error = {"workspace": [message]}
                raise serializers.ValidationError(error)
