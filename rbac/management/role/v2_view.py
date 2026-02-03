#
# Copyright 2026 Red Hat, Inc.
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
"""View for RoleV2 management."""

from management.base_viewsets import BaseV2ViewSet
from management.permissions import RoleAccessPermission
from management.role.v2_model import RoleV2
from management.role.v2_serializer import RoleV2RequestSerializer, RoleV2ResponseSerializer
from management.v2_mixins import AtomicOperationsMixin


class RoleV2ViewSet(AtomicOperationsMixin, BaseV2ViewSet):
    """RoleV2 ViewSet."""

    permission_classes = (RoleAccessPermission,)
    queryset = RoleV2.objects.all()
    serializer_class = RoleV2ResponseSerializer
    lookup_field = "uuid"
    # Explicitly exclude PATCH - API only supports full replacement via PUT.
    # Without this, UpdateModelMixin exposes partial_update() which would silently
    # accept PATCH requests but do nothing (response serializer has read-only fields).
    http_method_names = ["get", "post", "put", "delete", "head", "options"]

    def get_serializer_class(self):
        if self.action in ("create", "update"):
            return RoleV2RequestSerializer
        return RoleV2ResponseSerializer

    def get_queryset(self):
        """
        Return different querysets based on action.

        - list/retrieve: All roles (custom, seeded, system) for the tenant
        - create/update/destroy: Only custom roles (users can only modify custom roles)
        """
        base_qs = (
            RoleV2.objects.filter(tenant=self.request.tenant)
            .prefetch_related("permissions")
            .order_by("name", "-modified")
        )

        if self.action in ("list", "retrieve"):
            return base_qs
        else:
            return base_qs.filter(type=RoleV2.Types.CUSTOM)
