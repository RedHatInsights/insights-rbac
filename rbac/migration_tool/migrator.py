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

from dataclasses import dataclass
from typing import Callable, FrozenSet


@dataclass(frozen=True)
class V1group:
    """V1 group definition."""

    id: str
    users: frozenset[str]


@dataclass(frozen=True)
class V1resourcedef:
    """V1 resource definition."""

    resource_type: str
    op: str
    resource_id: str


@dataclass(frozen=True)
class V1permission:
    """V1 permission definition."""

    app: str
    resource: str
    perm: str
    resourceDefs: frozenset[V1resourcedef]


@dataclass(frozen=True)
class V1role:
    """V1 role definition."""

    id: str
    permissions: frozenset[V1permission]
    groups: frozenset[V1group]


@dataclass(frozen=True)
class V2group:
    """V2 group definition."""

    id: str
    users: frozenset[str]


@dataclass(frozen=True)
class V2boundresource:
    """V2 bound resource definition."""

    resource_type: str
    resourceId: str


@dataclass(frozen=True)
class V2role:
    """V2 role definition."""

    id: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class V2rolebinding:
    """V2 role binding definition."""

    id: str
    role: V2role
    resources: frozenset[V2boundresource]
    groups: frozenset[V2group]


# Algorithms provide implementations of the following functions:

# Type of v1 to v2 mapping function:
# V1role => Set[V2rolebinding]
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
