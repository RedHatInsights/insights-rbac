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

from django.db.models import Count, F, QuerySet
from management.subject import SubjectType


class RoleBindingQuerySet(QuerySet):
    """Custom QuerySet for RoleBinding with domain-aware query methods."""

    def for_tenant(
        self, tenant, role_id=None, resource_id=None, resource_type=None, subject_type=None, subject_id=None
    ):
        """Return role bindings for a tenant with related data eagerly loaded.

        Args:
            tenant: The tenant to filter by.
            role_id: Optional role UUID to filter by.
            resource_id: Optional resource ID to filter by (must pair with resource_type).
            resource_type: Optional resource type to filter by (must pair with resource_id).
            subject_type: Optional subject type filter. Only 'group' is supported;
                unsupported types return an empty queryset.
            subject_id: Optional subject (group) UUID to filter by.
        """
        qs = (
            self.filter(tenant=tenant)
            .select_related("role")
            .prefetch_related("group_entries__group")
            .annotate(role_created=F("role__created"))
        )
        if role_id:
            qs = qs.filter(role__uuid=role_id)
        if resource_id and resource_type:
            qs = qs.filter(resource_id=resource_id, resource_type=resource_type)
        if subject_type and subject_type != SubjectType.GROUP:
            return qs.none()
        if subject_id:
            qs = qs.filter(group_entries__group__uuid=subject_id)
        return qs

    def for_resource(self, resource_type, resource_id, tenant):
        """Filter to bindings on a specific resource for a tenant."""
        return self.filter(resource_type=resource_type, resource_id=resource_id, tenant=tenant)

    def orphaned(self):
        """Filter to bindings that have no subjects (groups or principals) attached."""
        return self.annotate(
            group_count=Count("group_entries"),
            principal_count=Count("principal_entries"),
        ).filter(group_count=0, principal_count=0)
