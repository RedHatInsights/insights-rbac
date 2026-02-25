#
# Copyright 2025 Red Hat, Inc.
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
"""QuerySet for RoleBinding lookups."""

from django.db.models import F, QuerySet


class RoleBindingQuerySet(QuerySet):
    """Custom QuerySet for RoleBinding lookups."""

    def for_tenant(self, tenant, role_id=None):
        """Return role bindings for a tenant with related data eagerly loaded.

        Args:
            tenant: The tenant to filter by.
            role_id: Optional role UUID to filter by.
        """
        qs = (
            self.filter(tenant=tenant)
            .select_related("role")
            .prefetch_related("group_entries__group")
            .annotate(role_created=F("role__created"))
        )
        if role_id:
            qs = qs.filter(role__uuid=role_id)
        return qs
