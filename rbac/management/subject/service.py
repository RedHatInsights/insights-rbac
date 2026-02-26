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
"""Service layer for subject operations."""

from management.group.model import Group
from management.principal.model import Principal


class SubjectService:
    """Service for subject-related operations."""

    def resolve_groups(self, group_uuids: set[str]) -> dict[str, Group]:
        """Resolve group UUIDs to Group objects in bulk."""
        if not group_uuids:
            return {}
        return {str(g.uuid): g for g in Group.objects.filter(uuid__in=group_uuids)}

    def resolve_users(self, user_uuids: set[str]) -> dict[str, Principal]:
        """Resolve user UUIDs to Principal objects in bulk."""
        if not user_uuids:
            return {}
        return {str(p.uuid): p for p in Principal.objects.filter(uuid__in=user_uuids)}
