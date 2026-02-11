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

__all__ = [
    "RoleBindingError",
    "RolesNotFoundError",
    "SubjectsNotFoundError",
    "DuplicateBindingError",
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


class SubjectsNotFoundError(RoleBindingError):
    """Raised when one or more referenced subjects cannot be found."""

    def __init__(self, subject_type: str, missing_uuids: list[str]):
        """Initialize with subject type and missing UUIDs."""
        self.subject_type = subject_type
        self.missing_uuids = missing_uuids
        super().__init__(f"The following {subject_type} subjects were not found: {', '.join(missing_uuids)}")


class DuplicateBindingError(RoleBindingError):
    """Raised when a role binding already exists for the given role/resource/tenant."""

    def __init__(self, role_id: str, resource_type: str, resource_id: str):
        """Initialize with the duplicate binding details."""
        self.role_id = role_id
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(
            f"A role binding already exists for role '{role_id}' " f"on resource {resource_type}/{resource_id}."
        )
