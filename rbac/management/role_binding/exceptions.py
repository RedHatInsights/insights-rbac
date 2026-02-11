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
"""Domain exceptions for RoleBinding operations."""

# Re-export subject exceptions for backward compatibility
from management.subject import SubjectNotFoundError, UnsupportedSubjectTypeError

# Expose in __all__ for explicit re-export
__all__ = [
    "SubjectNotFoundError",
    "UnsupportedSubjectTypeError",
    "RoleBindingError",
    "RolesNotFoundError",
    "ResourceNotFoundError",
]


class RoleBindingError(Exception):
    """Base exception for RoleBinding domain errors."""

    pass


class RolesNotFoundError(RoleBindingError):
    """Raised when one or more roles cannot be found."""

    def __init__(self, missing_role_ids: list[str]):
        """Initialize with the list of missing role IDs."""
        self.missing_role_ids = missing_role_ids
        super().__init__(f"The following roles do not exist: {', '.join(missing_role_ids)}")


class ResourceNotFoundError(RoleBindingError):
    """Raised when the specified resource cannot be found."""

    def __init__(self, resource_type: str, resource_id: str):
        """Initialize with the resource details."""
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(f"Resource not found: {resource_type} with id '{resource_id}'")
