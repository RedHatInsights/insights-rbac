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
import dataclasses
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


@dataclasses.dataclass(frozen=True)
class _PermissionDescriptor:
    """
    Represents the value of a single permission.

    A permission consists of an app name, a resource type name, and a verb.

    The resource type and verb may either be normal strings or the wildcard '*'.
    If either component contains a wildcard, it must be the entire component.
    (That is, 'foo*' is not a glob.) The app name may not be a wildcard.

    No component may contain a colon in order to ensure the string representation
    remains unambiguous.
    """

    app: str
    resource: str
    verb: str

    @staticmethod
    def _check_valid_component(name: str, value: str):
        """
        Check that the component is valid in a permission.

        Name is used for producing error messages.
        """
        if value is None:
            raise ValueError(f"{name} cannot be None")

        if ":" in value:
            raise ValueError(f"Portions of a permission cannot contain colons, but got {name}: {value}")

        if (value != "*") and ("*" in value):
            raise ValueError(f"Wildcard portions of a permission must be only an asterisk, but got {name}: {value}")

    def __post_init__(self):
        """Verify that this permission is valid."""
        if "*" in self.app:
            raise ValueError("Wildcards are not permitted in the app portion of permissions.")

        self._check_valid_component("app", self.app)
        self._check_valid_component("resource", self.resource)
        self._check_valid_component("action", self.verb)

    @classmethod
    def parse_v1(cls, permission_str: str) -> "_PermissionDescriptor":
        """Parse a V1 permission string, e.g. app:resource:verb."""
        parts = permission_str.split(":")

        if len(parts) != 3:
            raise ValueError(f"Permission string must contain three colon-separated parts: {permission_str}")

        return cls(app=parts[0], resource=parts[1], verb=parts[2])


class ImplicitResourceService:
    """Classifies permissions based on their default scope."""

    _permissions_map: dict[_PermissionDescriptor, Scope]

    def __init__(self, root_scope_permissions: list[str], tenant_scope_permissions: list[str]):
        """
        Create an ImplicitResourceService with specific root and tenant scope permissions.

        root_scope_permissions is a set of permissions assigned to the root workspace scope.
        tenant_scope_permissions is a set of permissions assigned to tenant scope.

        Both sets of permissions are represented as V1 permission strings (valid for
        _PermissionDescriptor.parse_v1). Both sets may contain wildcards.
        """
        self._permissions_map = {}

        def add_permission(permission: _PermissionDescriptor, scope: Scope):
            previous_scope = self._permissions_map.get(permission, None)

            if previous_scope is not None and previous_scope != scope:
                raise ValueError(f"Permission is in multiple scopes: {previous_scope} and {scope}")

            self._permissions_map[permission] = scope

        for permission_str in root_scope_permissions:
            add_permission(_PermissionDescriptor.parse_v1(permission_str), Scope.ROOT)

        for permission_str in tenant_scope_permissions:
            add_permission(_PermissionDescriptor.parse_v1(permission_str), Scope.TENANT)
