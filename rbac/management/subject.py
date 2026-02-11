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
"""Domain types and services for subjects in the RBAC system.

A "subject" is an entity that can be granted permissions via role bindings.
Currently supported subjects are:
- Groups (collections of users)
- Users (individual principals)
"""

from enum import StrEnum

from management.group.model import Group
from management.principal.model import Principal
from management.tenant_mapping.model import Tenant


class SubjectType(StrEnum):
    """Valid subject types for role bindings.

    This is a domain enum representing the types of subjects that can be
    assigned roles via role bindings.
    """

    GROUP = "group"
    USER = "user"

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Check if a value is a valid subject type."""
        return value in cls._value2member_map_

    @classmethod
    def values(cls) -> list[str]:
        """Return list of all valid subject type values."""
        return list(cls._value2member_map_.keys())


class SubjectService:
    """Service for subject-related operations.

    This service provides methods for retrieving and validating subjects
    (groups and users/principals) in the RBAC system.
    """

    def __init__(self, tenant: Tenant):
        """Initialize the service with a tenant context.

        Args:
            tenant: The tenant context for subject lookups
        """
        self.tenant = tenant

    def resolve_groups(self, group_uuids: set[str]) -> dict[str, Group]:
        """Resolve group UUIDs to Group objects in bulk.

        Args:
            group_uuids: Set of group UUID strings to look up.

        Returns:
            Dict mapping UUID string to Group object for each found group.
        """
        if not group_uuids:
            return {}
        return {str(g.uuid): g for g in Group.objects.filter(uuid__in=group_uuids)}

    def resolve_users(self, user_uuids: set[str]) -> dict[str, Principal]:
        """Resolve user UUIDs to Principal objects in bulk.

        Args:
            user_uuids: Set of user UUID strings to look up.

        Returns:
            Dict mapping UUID string to Principal object for each found principal.
        """
        if not user_uuids:
            return {}
        return {str(p.uuid): p for p in Principal.objects.filter(uuid__in=user_uuids)}
