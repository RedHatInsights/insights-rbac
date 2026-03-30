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

from django.db.models import Count, F, OuterRef, Q, QuerySet, Subquery
from django.db.models.fields import UUIDField
from django.db.models.functions import Cast
from management.subject import SubjectType


class RoleBindingQuerySet(QuerySet):
    """Custom QuerySet for RoleBinding with domain-aware query methods."""

    def for_tenant(self, tenant):
        """Return role bindings for a tenant with related data eagerly loaded.

        Annotates cross-relation fields so they are available as attributes
        on each RoleBinding instance.  This is required by DRF's
        CursorPagination which uses ``getattr(instance, field)`` to build
        cursor positions — plain ORM lookups (``role__name``) only work in
        ``.order_by()`` but not in ``getattr``.
        """
        return (
            self.filter(tenant=tenant)
            .select_related("role")
            .prefetch_related("group_entries__group", "principal_entries__principal")
            .annotate(
                role_created=F("role__created"),
                role_name=F("role__name"),
                role_uuid=F("role__uuid"),
                role_modified=F("role__modified"),
            )
        )

    def for_role(self, role_id):
        """Filter by role UUID."""
        return self.filter(role__uuid=role_id)

    def for_resource_filter(self, resource_type=None, resource_id=None):
        """Apply optional resource_type and resource_id filters."""
        qs = self
        if resource_id:
            qs = qs.filter(resource_id=resource_id)
        if resource_type:
            qs = qs.filter(resource_type=resource_type)
        return qs

    def for_subject(self, subject_type=None, subject_id=None):
        """Filter by subject type and/or subject ID.

        When subject_type is 'group', filters by group; when 'user', by principal.
        An unsupported subject_type returns an empty queryset.
        When subject_id is provided without subject_type, searches both groups and principals.
        """
        if subject_type == SubjectType.GROUP:
            if subject_id:
                return self.filter(group_entries__group__uuid=subject_id)
            return self.filter(group_entries__isnull=False).distinct()
        elif subject_type == SubjectType.USER:
            if subject_id:
                return self.filter(principal_entries__principal__uuid=subject_id)
            return self.filter(principal_entries__isnull=False).distinct()
        elif subject_type:
            return self.none()
        elif subject_id:
            return self.filter(
                Q(group_entries__group__uuid=subject_id) | Q(principal_entries__principal__uuid=subject_id)
            ).distinct()
        return self

    def with_resource_names(self):
        """Annotate each binding with its resource's display name.

        Resolves workspace names via a correlated subquery so the name is
        available as ``obj.resource_name`` without per-row queries.
        Non-workspace resource types will get ``None``.
        """
        from management.workspace.model import Workspace

        return self.annotate(
            resource_name=Subquery(
                Workspace.objects.filter(
                    id=Cast(OuterRef("resource_id"), UUIDField()),
                    tenant=OuterRef("tenant"),
                ).values("name")[:1]
            )
        )

    def for_resource(self, resource_type, resource_id, tenant):
        """Filter to bindings on a specific resource for a tenant."""
        return self.filter(resource_type=resource_type, resource_id=resource_id, tenant=tenant)

    def orphaned(self):
        """Filter to bindings that have no subjects (groups or principals) attached."""
        return self.annotate(
            group_count=Count("group_entries"),
            principal_count=Count("principal_entries"),
        ).filter(group_count=0, principal_count=0)
