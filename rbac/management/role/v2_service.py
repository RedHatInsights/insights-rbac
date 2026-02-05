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
"""Service layer for RoleV2 management."""

import logging

from django.db.models import Count, QuerySet

from api.models import Tenant
from .v2_model import RoleV2

logger = logging.getLogger(__name__)


class RoleV2Service:
    """Service for RoleV2 queries and operations."""

    def __init__(self, tenant: Tenant):
        """Initialize the service with a tenant."""
        self.tenant = tenant

    def list(self, params: dict) -> QuerySet:
        """Get a list of roles for the tenant."""
        queryset = RoleV2.objects.filter(tenant=self.tenant)

        name = params.get("name")
        if name:
            queryset = queryset.filter(name__exact=name)

        field_selection = params.get("fields")
        if field_selection:
            if "permissions_count" in field_selection.root_fields:
                queryset = queryset.annotate(permissions_count_annotation=Count("permissions", distinct=True))
            if "permissions" in field_selection.root_fields:
                queryset = queryset.prefetch_related("permissions")

        return queryset
