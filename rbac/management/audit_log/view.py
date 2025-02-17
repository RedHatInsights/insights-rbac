#
# Copyright 2024 Red Hat, Inc.
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

"""View for Audit Logs."""
from management.models import AuditLog
from management.permissions import AuditLogAccessPermission
from management.serializers import AuditLogSerializer
from management.utils import filter_queryset_by_tenant
from rest_framework import mixins, viewsets


class AuditLogViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """Audit Logs View.

    A viewset that provides default `list()` actions.
    """

    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = (AuditLogAccessPermission,)

    def order_by_id(self, queryset):
        """Order queryset by id."""
        return queryset.order_by("-id").values()

    def list(self, request, *args, **kwargs):
        """List all of the audit logs within database by tenant."""
        self.queryset = filter_queryset_by_tenant(AuditLog.objects.all(), request.tenant)
        if request.query_params.get("order_by") is not None:
            self.queryset = self.order_by_id(self.queryset)
        return super().list(request=request, args=args, kwargs=kwargs)
