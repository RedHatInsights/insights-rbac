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
"""Application service for Permission operations."""

from management.permission.model import Permission, PermissionValue
from management.role.v2_exceptions import EmptyPermissionsError, PermissionsNotFoundError


class PermissionService:
    """Application service for Permission operations."""

    def resolve(self, permission_data: list[dict]) -> list[Permission]:
        """Resolve permission dicts to Permission objects."""
        if not permission_data:
            raise EmptyPermissionsError()

        permission_strings = [
            PermissionValue.with_operation_as_verb(perm_dict).v1_string() for perm_dict in permission_data
        ]

        found_permissions = Permission.objects.filter(permission__in=permission_strings)
        found_map = {p.permission: p for p in found_permissions}

        permissions = []
        not_found = []
        for perm in permission_strings:
            if perm in found_map:
                permissions.append(found_map[perm])
            else:
                not_found.append(perm)

        if not_found:
            raise PermissionsNotFoundError(not_found)

        return permissions
