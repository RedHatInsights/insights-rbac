"""
Copyright 2019 Red Hat, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

# Algorithms provide implementations of the following functions:

# Type of v1 to v2 mapping function:
# V1role => Set[V2rolebinding]
from typing import Callable, FrozenSet

from migration_tool.models import V1role, V2rolebinding


v1_to_v2_mapping_fn = Callable[[V1role], FrozenSet[V2rolebinding]]


class Migrator:
    """Migrator class."""

    def __init__(
        self,
        v1_to_v2_mapping: v1_to_v2_mapping_fn,
    ):
        """Initialize the migrator."""
        self.v1_to_v2_mapping = v1_to_v2_mapping

    def migrate_v1_roles(self, v1_role: V1role) -> FrozenSet[V2rolebinding]:
        """Migrate a v1 role to a set of v2 role bindings."""
        return self.v1_to_v2_mapping(v1_role)
