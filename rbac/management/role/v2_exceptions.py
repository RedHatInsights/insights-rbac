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
