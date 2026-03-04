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
"""QuerySet for RoleV2 lookups."""

from django.db import models
from django.db.models import Count, Q


class RoleV2QuerySet(models.QuerySet):
    """Custom QuerySet for RoleV2 with domain-aware query methods."""

    def assignable(self):
        """Filter to roles that can be assigned to bindings.

        Only custom and seeded roles can be directly assigned.
        Platform roles are internal aggregations and cannot be assigned directly.
        """
        # Import here to avoid circular import (RoleV2 -> queryset -> RoleV2).
        from management.role.v2_model import RoleV2

        return self.exclude(type=RoleV2.Types.PLATFORM)

    def for_tenant(self, tenant, fields=None):
        """Return assignable roles visible to the given tenant with field-driven eager loading.

        Includes the tenant's own roles and roles from the public tenant
        (e.g. seeded roles). Excludes platform roles. When fields is provided,
        drives select_related, prefetch_related, and annotations so the
        serializer never triggers lazy loads.

        Args:
            tenant: The tenant to filter by.
            fields: Optional set of response field names; drives select_related,
                    prefetch_related, and annotations so the serializer never
                    triggers lazy loads.
        """
        from api.models import Tenant

        qs = self.filter(Q(tenant=tenant) | Q(tenant__tenant_name=Tenant.PUBLIC_TENANT_NAME)).assignable()
        if not fields:
            return qs
        if "org_id" in fields:
            qs = qs.select_related("tenant")
        if "permissions_count" in fields:
            qs = qs.annotate(permissions_count_annotation=Count("permissions", distinct=True))
        if "permissions" in fields:
            qs = qs.prefetch_related("permissions")
        return qs

    def named(self, name):
        """Filter to roles matching an exact name."""
        return self.filter(name__exact=name)
