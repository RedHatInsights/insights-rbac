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
"""Domain exceptions for RoleV2 operations."""


class RoleV2Error(Exception):
    """Base exception for RoleV2 domain errors."""

    pass


class RoleNotFoundError(RoleV2Error):
    """Raised when a role cannot be found."""

    def __init__(self, uuid):
        """Initialize RoleNotFoundError with UUID."""
        self.uuid = uuid
        super().__init__(f"Role with UUID '{uuid}' not found.")


class RoleAlreadyExistsError(RoleV2Error):
    """Raised when attempting to create a role with a name that already exists for the tenant."""

    def __init__(self, name: str):
        """Initialize with the duplicate role name."""
        self.name = name
        super().__init__(f"A role with name '{name}' already exists for this tenant.")


class PermissionsNotFoundError(RoleV2Error):
    """Raised when one or more permissions cannot be found."""

    def __init__(self, missing_permissions: list[str]):
        """Initialize with the list of missing permission strings."""
        self.missing_permissions = missing_permissions
        super().__init__(f"The following permissions do not exist: {', '.join(missing_permissions)}")


class RoleDatabaseError(RoleV2Error):
    """Raised when an unexpected database error occurs."""

    def __init__(self, message: str = "An unexpected database error occurred."):
        """Initialize with optional custom message."""
        super().__init__(message)


class InvalidRolePermissionsError(RoleV2Error):
    """Raised when permission data for a role is malformed or invalid."""

    def __init__(self, message: str):
        """Initialize with the validation error message."""
        super().__init__(message)
