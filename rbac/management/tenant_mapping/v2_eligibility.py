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
"""Contains utilities for determining whether a tenant is eligible to opt into V2."""

import dataclasses
import functools
from typing import Optional

from django.conf import settings
from django.db.models import Prefetch
from management.atomic_transactions import atomic
from management.group.model import Group
from management.policy.model import Policy
from management.role.model import Role
from management.tenant_mapping.model import try_lock_mapping_for_share

from api.models import Tenant


@dataclasses.dataclass(frozen=True)
class OptInIneligibleRole:
    """Information on a role making a tenant ineligible for opting into V2."""

    role: Role
    ineligible_applications: frozenset[str]

    def __post_init__(self):
        """Establish invariants."""
        if not isinstance(self.role, Role):
            raise TypeError(f"Expected role to be a Role, but got: {self.role!r}")

        if not (
            isinstance(self.ineligible_applications, frozenset)
            and all(isinstance(app, str) for app in self.ineligible_applications)
        ):
            raise TypeError(
                f"Expected ineligible_applications to be a frozenset of str, but got: "
                f"{self.ineligible_applications!r}"
            )

        if len(self.ineligible_applications) == 0:
            raise ValueError("Expected ineligible_applications not to be empty")


@dataclasses.dataclass(frozen=True)
class OptInIneligibleGroup:
    """Information on a group making a tenant ineligible for opting into V2."""

    group: Group
    ineligible_system_roles: tuple[OptInIneligibleRole, ...]

    def __post_init__(self):
        """Establish invariants."""
        if not isinstance(self.group, Group):
            raise TypeError(f"Expected group to be a Group, but got: {self.group!r}")

        if not (
            isinstance(self.ineligible_system_roles, tuple)
            and all(isinstance(r, OptInIneligibleRole) for r in self.ineligible_system_roles)
        ):
            raise TypeError(
                f"Expected ineligible_system_roles to be a tuple of OptInIneligibleRole, but got: "
                f"{self.ineligible_system_roles!r}"
            )

        if len(self.ineligible_system_roles) == 0:
            raise ValueError("Expected ineligible_system_roles not to be empty")


@dataclasses.dataclass(frozen=True)
class OptInIneligibleState:
    """Information on why a tenant is ineligible to opt into V2."""

    bootstrapped: bool
    ineligible_groups: tuple[OptInIneligibleGroup, ...]
    ineligible_custom_roles: tuple[OptInIneligibleRole, ...]

    def __post_init__(self):
        """Establish invariants."""
        if not isinstance(self.bootstrapped, bool):
            raise TypeError(f"Expected bootstrapped to be a bool, but got: {self.bootstrapped!r}")

        if not (
            isinstance(self.ineligible_groups, tuple)
            and all(isinstance(g, OptInIneligibleGroup) for g in self.ineligible_groups)
        ):
            raise TypeError(
                f"Expected ineligible_groups to be a tuple of OptInIneligibleGroup, but got: "
                f"{self.ineligible_groups!r}"
            )

        if not (
            isinstance(self.ineligible_custom_roles, tuple)
            and all(isinstance(r, OptInIneligibleRole) for r in self.ineligible_custom_roles)
        ):
            raise TypeError(
                f"Expected ineligible_custom_roles to be a tuple of OptInIneligibleRole, but got: "
                f"{self.ineligible_custom_roles!r}"
            )

        if self.bootstrapped and (not self.ineligible_groups) and (not self.ineligible_custom_roles):
            raise ValueError("Found no reason for tenant to be ineligible")


@dataclasses.dataclass(frozen=True)
class OptInEligibleState:
    """Indicates that a tenant is eligible to opt into V2."""

    pass


def _ineligibility_for_role(role: Role, ineligible_apps: frozenset[str]) -> Optional[OptInIneligibleRole]:
    permission_apps = {access.permission.application for access in role.access.all()}
    found_ineligible = permission_apps.intersection(ineligible_apps)

    return (
        OptInIneligibleRole(role=role, ineligible_applications=frozenset(found_ineligible))
        if found_ineligible
        else None
    )


def _ineligible_groups_for(tenant: Tenant, ineligible_apps: frozenset[str]) -> list[OptInIneligibleGroup]:
    # The same system role may be assigned many times, and OptInIneligibleRole is immutable, so we want to avoid
    # having to create a new instance every time.
    @functools.cache
    def cached_ineligibility_for(role: Role) -> Optional[OptInIneligibleRole]:
        return _ineligibility_for_role(role=role, ineligible_apps=ineligible_apps)

    group_query = (
        Group.objects.filter(tenant=tenant, platform_default=False, admin_default=False, policies__roles__system=True)
        .prefetch_related(
            Prefetch(
                "policies",
                Policy.objects.prefetch_related(
                    Prefetch(
                        "roles",
                        Role.objects.filter(system=True)
                        .filter(access__permission__application__in=ineligible_apps)
                        .prefetch_related("access", "access__permission")
                        .distinct(),
                        to_attr="ineligible_system_roles",
                    )
                ),
            )
        )
        .distinct()
    )

    ineligible_groups = []

    for group in group_query.iterator(chunk_size=100):
        ineligible_roles: set[OptInIneligibleRole] = {
            role_result
            for role_result in (
                cached_ineligibility_for(role)
                for policy in group.policies.all()
                for role in policy.ineligible_system_roles
            )
            if role_result is not None
        }

        if not ineligible_roles:
            continue

        ineligible_groups.append(
            OptInIneligibleGroup(
                group=group,
                ineligible_system_roles=tuple(ineligible_roles),
            )
        )

    return ineligible_groups


def _ineligible_custom_roles_for(tenant: Tenant, ineligible_apps: frozenset[str]) -> list[OptInIneligibleRole]:
    role_query = (
        Role.objects.filter(tenant=tenant, access__permission__application__in=ineligible_apps)
        .prefetch_related("access", "access__permission")
        .distinct()
    )

    return [
        result
        for result in (
            _ineligibility_for_role(role, ineligible_apps=ineligible_apps)
            for role in role_query.iterator(chunk_size=100)
        )
        if result is not None
    ]


@atomic
def check_v2_eligibility(tenant: Tenant) -> OptInEligibleState | OptInIneligibleState:
    """
    Determine whether the provided tenant is eligible to opt into V2.

    Returns an OptInEligibleState if the tenant is eligible, or an OptInIneligibleState otherwise.
    """
    mapping = try_lock_mapping_for_share(tenant)

    # Opting in is idempotent, so a tenant that has already opted in can always do so again.
    if mapping is not None and mapping.v2_opted_in_at is not None:
        return OptInEligibleState()

    ineligible_apps = frozenset(settings.V2_MIGRATION_APP_EXCLUDE_LIST)

    bootstrapped = mapping is not None
    ineligible_groups = _ineligible_groups_for(tenant, ineligible_apps=ineligible_apps)
    ineligible_custom_roles = _ineligible_custom_roles_for(tenant, ineligible_apps=ineligible_apps)

    if (not bootstrapped) or ineligible_groups or ineligible_custom_roles:
        return OptInIneligibleState(
            bootstrapped=bootstrapped,
            ineligible_groups=tuple(ineligible_groups),
            ineligible_custom_roles=tuple(ineligible_custom_roles),
        )

    return OptInEligibleState()
