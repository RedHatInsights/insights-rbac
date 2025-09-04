#
# Copyright 2025 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Helper for determining workspace/tenant binding levels for permissions."""
from enum import IntEnum


class Scope(IntEnum):
    """
    Permission scope levels, ordered from lowest to highest.

    This represents the possible default scopes for a permission:
    * DEFAULT, for the default workspace of a tenant.
    * ROOT, for the root workspace of a tenant.
    * TENANT, for the tenant itself.

    Later scopes are said to be "higher" than earlier scopes, as they encompass
    more resources.
    """

    DEFAULT = 1
    ROOT = 2
    TENANT = 3
