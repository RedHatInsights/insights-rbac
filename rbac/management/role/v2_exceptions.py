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


class RoleAlreadyExistsError(RoleV2Error):
    """Raised when attempting to create a role with a name that already exists for the tenant."""

    def __init__(self, name: str):
        self.name = name
        super().__init__(f"A role with name '{name}' already exists for this tenant.")


class PermissionsNotFoundError(RoleV2Error):
    """Raised when one or more permissions cannot be found."""

    def __init__(self, missing_permissions: list[str]):
        self.missing_permissions = missing_permissions
        super().__init__(f"The following permissions do not exist: {', '.join(missing_permissions)}")


class EmptyPermissionsError(RoleV2Error):
    """Raised when no permissions are provided for a role."""

    def __init__(self):
        super().__init__("At least one permission is required.")


class EmptyDescriptionError(RoleV2Error):
    """Raised when description is empty or missing."""

    def __init__(self):
        super().__init__("Description is required and cannot be empty.")


class RoleDatabaseError(RoleV2Error):
    """Raised when an unexpected database error occurs."""

    def __init__(self, message: str = "An unexpected database error occurred."):
        super().__init__(message)
