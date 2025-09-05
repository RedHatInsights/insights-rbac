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
from typing import Iterable

from django.conf import settings
from migration_tool.models import V2boundresource


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

    def with_unconstrained_resource(self) -> "_PermissionDescriptor":
        """Return a new permission with a wildcard resource."""
        return _PermissionDescriptor(
            app=self.app,
            resource="*",
            verb=self.verb,
        )

    def with_unconstrained_verb(self) -> "_PermissionDescriptor":
        """Return a new permission with a wildcard verb."""
        return _PermissionDescriptor(
            app=self.app,
            resource=self.resource,
            verb="*",
        )

    def with_app_only(self) -> "_PermissionDescriptor":
        """Return a new permission with a wildcard resource and verb."""
        return _PermissionDescriptor(
            app=self.app,
            resource="*",
            verb="*",
        )

    def v1_string(self) -> str:
        """Return the V1 representation of this permission: app:resource:verb."""
        return f"{self.app}:{self.resource}:{self.verb}"


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
            previous_scope = self._permissions_map.get(permission)

            if previous_scope is not None and previous_scope != scope:
                raise ValueError(
                    f"Duplicate permission found: {permission.v1_string()} is in multiple scopes: "
                    f"{previous_scope} and {scope}"
                )

            self._permissions_map[permission] = scope

        for permission_str in root_scope_permissions:
            add_permission(_PermissionDescriptor.parse_v1(permission_str), Scope.ROOT)

        for permission_str in tenant_scope_permissions:
            add_permission(_PermissionDescriptor.parse_v1(permission_str), Scope.TENANT)

    @classmethod
    def from_settings(cls) -> "ImplicitResourceService":
        """
        Create an ImplicitResourceService from the configuration in settings.

        Root workspace permissions are determined from the ROOT_SCOPE_PERMISSIONS setting.
        Tenant permissions are determined from the TENANT_SCOPE_PERMISSIONS setting.

        Each setting must be a comma-separated list of V1 permissions strings (as if for
        _PermissionDescriptor.parse_v1); spaces are trimmed from the start and each of
        each permission. An empty (or blank) string is acceptable and will be parsed to
        the empty list.
        """

        def parse_setting(value: str) -> list[str]:
            if value.strip() == "":
                return []

            return [p.strip() for p in value.split(",")]

        return cls(
            root_scope_permissions=parse_setting(settings.ROOT_SCOPE_PERMISSIONS),
            tenant_scope_permissions=parse_setting(settings.TENANT_SCOPE_PERMISSIONS),
        )

    def scope_for_permission(self, permission: str) -> Scope:
        """
        Return the scope that a permission binds to using this object's configured permissions.

        The argument shall be a V1 permission string (as if for _PermissionDescriptor.parse_v1).
        The permission may be a wildcard.

        Matching precedence (highest to lowest):
        1. Exact app:resource_type:verb match.
        2. Wildcard app:resource_type:* match.
        3. Wildcard app:*:verb match.
        4. Wildcard app:*:* match.
        5. Finally, if no match exists, the DEFAULT scope.

        Note that, if the permission is a wildcard, some of these steps will be redundant.
        For instance, if the permission is app:*:verb, there are only two possible matches:
        app:*:verb and app:*:*.
        """
        parsed = _PermissionDescriptor.parse_v1(permission)

        # If we are passed a wildcard, some wildcard checks will be redundant.
        candidates = [parsed] + [
            wildcard
            for wildcard in [
                parsed.with_unconstrained_verb(),
                parsed.with_unconstrained_resource(),
                parsed.with_app_only(),
            ]
            if wildcard != parsed
        ]

        for candidate in candidates:
            scope = self._permissions_map.get(candidate)

            if scope is not None:
                return scope

        return Scope.DEFAULT

    def highest_scope_for_permissions(self, permissions: Iterable[str]) -> Scope:
        """
        Return the highest scope to which any permission in permissions is assigned.

        Permission scopes are determined as if by using scope_for_permission.
        """
        return max(
            (self.scope_for_permission(permission) for permission in permissions),
            default=Scope.DEFAULT,
        )

    def v2_bound_resource_for_permission(
        self,
        permissions: Iterable[str],
        tenant_org_id: str,
        root_workspace_id: str,
        default_workspace_id: str,
    ) -> V2boundresource:
        """
        Return a V2boundresource corresponding the highest scope for any permission in permissions.

        The appropriate scope is determined as if by highest_scope_for_permissions. A
        V2boundresource is then returned, bound to the appropriate provided resource.
        """
        scope = self.highest_scope_for_permissions(permissions)

        if scope == Scope.TENANT:
            tenant_resource_id = f"{settings.PRINCIPAL_USER_DOMAIN}/{tenant_org_id}"
            return V2boundresource(resource_type=("rbac", "tenant"), resource_id=tenant_resource_id)
        elif scope == Scope.ROOT:
            return V2boundresource(resource_type=("rbac", "workspace"), resource_id=root_workspace_id)
        elif scope == Scope.DEFAULT:
            return V2boundresource(resource_type=("rbac", "workspace"), resource_id=default_workspace_id)
        else:
            raise AssertionError(f"Unexpected scope: {scope}")


"""
A global ImplicitResourceService configured using Django Settings.

See ImplicitResourceService.from_settings for details on how this is configured.
"""
default_implicit_resource_service = ImplicitResourceService.from_settings()
