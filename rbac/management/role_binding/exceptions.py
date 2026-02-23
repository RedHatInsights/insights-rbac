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
from management.subject import UnsupportedSubjectTypeError

# Expose in __all__ for explicit re-export
__all__ = [
    "UnsupportedSubjectTypeError",
    "RoleBindingError",
]


class RoleBindingError(Exception):
    """Base exception for RoleBinding domain errors."""

    pass
