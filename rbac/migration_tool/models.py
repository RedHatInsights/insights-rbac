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
from typing import Tuple


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

    def matches(self, v2perm: str):
        """Check if the V1 permission matches the V2 permission."""
        app, resource, perm = split_v2_perm(v2perm)
        if self.app != "*" and cleanNameForV2SchemaCompatibility(self.app) != app:
            return False
        if self.resource != "*" and cleanNameForV2SchemaCompatibility(self.resource) != resource:
            return False
        if self.perm != "*" and cleanNameForV2SchemaCompatibility(self.perm) != perm:
            return False

        return True


@dataclass(frozen=True)
class V2boundresource:
    """V2 bound resource definition."""

    resource_type: Tuple[str, str]
    resource_id: str


@dataclass(frozen=True)
class V2role:
    """V2 role definition."""

    id: str
    is_system: bool
    permissions: frozenset[str]

    def as_dict(self) -> dict:
        """Convert the V2 role to a dictionary."""
        return {
            "id": self.id,
            "is_system": self.is_system,
            "permissions": list(self.permissions),
        }


@dataclass(frozen=True)
class V2rolebinding:
    """V2 role binding definition."""

    id: str
    role: V2role
    resource: V2boundresource
    groups: frozenset[str]

    def as_minimal_dict(self) -> dict:
        """Convert the V2 role binding to a dictionary, excluding resource, original role, and users."""
        return {
            "id": self.id,
            "role": self.role.as_dict(),
            "groups": [g for g in self.groups],
        }


def split_v2_perm(perm: str):
    """Split V2 permission into app, resource and permission."""
    first_delimiter = perm.find("_")
    last_delimiter = perm.rfind("_")

    # Handle inventory groups rewrite
    if perm == "read":
        return "inventory", "groups", "read"
    if perm == "write":
        return "inventory", "groups", "write"

    if first_delimiter == -1 or last_delimiter == -1 or first_delimiter == last_delimiter:
        raise ValueError("Invalid V2 permission: " + perm)

    return (
        perm[:first_delimiter],
        perm[(first_delimiter + 1) : last_delimiter],  # noqa: E203
        perm[(last_delimiter + 1) :],  # noqa: E203
    )


# Translated from: https://gitlab.corp.redhat.com/ciam-authz/loadtesting-spicedb/-/blob/main/spicedb/
# prbac-schema-generator/main.go?ref_type=heads#L286
def cleanNameForV2SchemaCompatibility(name: str):
    """Clean a name for compatibility with the v2 schema."""
    return name.lower().replace("-", "_").replace(".", "_").replace(":", "_").replace(" ", "_").replace("*", "all")
