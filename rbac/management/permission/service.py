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

from management.permission.model import Permission, PermissionValue
from management.role.v2_exceptions import EmptyPermissionsError, PermissionsNotFoundError


class PermissionService:
    """Application service for Permission operations."""

    def resolve(self, permission_data: list[dict]) -> list[Permission]:
        """

        Raises:
            EmptyPermissionsError: If no permissions are provided
            PermissionsNotFoundError: If any permission cannot be found
        """
        if not permission_data:
            raise EmptyPermissionsError()

        permissions = []
        not_found = []

        for perm_dict in permission_data:
            perm_value = PermissionValue(
                application=perm_dict.get("application"),
                resource_type=perm_dict.get("resource_type"),
                verb=perm_dict.get("operation") or perm_dict.get("verb"),
            )
            permission_string = perm_value.v1_string()

            try:
                permission = Permission.objects.get(permission=permission_string)
                permissions.append(permission)
            except Permission.DoesNotExist:
                not_found.append(permission_string)

        if not_found:
            raise PermissionsNotFoundError(not_found)

        return permissions
