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
from rest_framework import mixins, serializers, viewsets
from rest_framework.filters import OrderingFilter

from .model import Workspace
from .serializer import WorkspaceSerializer

VALID_PATCH_FIELDS = ["name", "description"]
REQUIRED_PATCH_FIELDS = ["name", "description"]


class WorkspaceViewSet(
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
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

    def destroy(self, request, *args, **kwargs):
        """Delete a workspace."""
        return super().destroy(request=request, args=args, kwargs=kwargs)

    def update(self, request, *args, **kwargs):
        """Update a workspace."""
        self.validate_workspace(request)
        return super().update(request=request, args=args, kwargs=kwargs)

    def partial_update(self, request, *args, **kwargs):
        """Patch a workspace."""
        kwargs["partial"] = True

        payload = json.loads(request.body or "{}")
        for field in payload:
            if field not in VALID_PATCH_FIELDS:
                message = f"Field '{field}' is not supported. Please use one or more of: {VALID_PATCH_FIELDS}."
                error = {"workspace": [_(message)]}
                raise serializers.ValidationError(error)
        return super().update(request=request, args=args, kwargs=kwargs)

    def validate_workspace(self, request):
        """Validate a workspace."""
        for field in REQUIRED_PATCH_FIELDS:
            if request.data.get(field) is None:
                message = f"Field '{field}' is required."
                error = {"workspace": [_(message)]}
                raise serializers.ValidationError(error)

        name = request.data.get("name")
        if name is None:
            return

        description = request.data.get("description")
        if description is None:
            message = "Field 'description' is required"
            error = {"workspace": [message]}
            raise serializers.ValidationError(error)

        tenant = request.tenant

        if Workspace.objects.filter(name=name, tenant=tenant).exists():
            message = "Workspace already exist in tenant"
            error = {"workspace": [message]}
            raise serializers.ValidationError(error)
