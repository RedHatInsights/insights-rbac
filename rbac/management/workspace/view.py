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
from django.utils.translation import gettext as _
from management.permissions import WorkspaceAccessPermission
from rest_framework import mixins, serializers, viewsets

from .model import Workspace
from .serializer import WorkspaceSerializer


class WorkspaceViewSet(
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Workspace View.

    A viewset that provides default `create()`, `destroy`, `retrieve()`,
    and `list()` actions.

    """

    permission_classes = (WorkspaceAccessPermission,)
    queryset = Workspace.objects.all()
    lookup_field = "uuid"
    serializer_class = WorkspaceSerializer

    def create(self, request, *args, **kwargs):
        """Create a Workspace."""
        self.validate_workspace(request)

        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of workspace for the tenant."""
        return super().list(request=request, args=args, kwargs=kwargs)

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

    def validate_workspace(self, request):
        """Validate a workspace."""
        name = request.data["name"]
        tenant = request.tenant

        if Workspace.objects.filter(name=name, tenant=tenant).exists():
            key = "workspace"
            message = "Workspace already exist in tenant"
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
