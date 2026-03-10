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
from django.db.models import Q


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

    def for_tenant(self, tenant):
        """Return roles visible to the given tenant.

        Includes the tenant's own roles and roles from the public tenant
        (e.g. seeded roles). Does not filter by role type — callers are
        responsible for excluding platform roles where needed.
        """
        from api.models import Tenant

        return self.filter(Q(tenant=tenant) | Q(tenant__tenant_name=Tenant.PUBLIC_TENANT_NAME))
