#
# Copyright 2025 Red Hat, Inc.
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
"""Contains utilities for handling platform roles."""

from typing import Callable
from uuid import UUID

from django.conf import settings
from management.group.platform import GlobalPolicyIdService
from management.permission.scope_service import Scope
from management.tenant_mapping.model import DefaultAccessType

_uuid_fns: dict[DefaultAccessType, dict[Scope, Callable[[GlobalPolicyIdService], UUID]]] = {
    DefaultAccessType.USER: {
        Scope.DEFAULT: lambda ps: ps.platform_default_policy_uuid(),
        Scope.ROOT: lambda _: UUID(settings.SYSTEM_DEFAULT_ROOT_WORKSPACE_ROLE_UUID),
        Scope.TENANT: lambda _: UUID(settings.SYSTEM_DEFAULT_TENANT_ROLE_UUID),
    },
    DefaultAccessType.ADMIN: {
        Scope.DEFAULT: lambda ps: ps.admin_default_policy_uuid(),
        Scope.ROOT: lambda _: UUID(settings.SYSTEM_ADMIN_ROOT_WORKSPACE_ROLE_UUID),
        Scope.TENANT: lambda _: UUID(settings.SYSTEM_ADMIN_TENANT_ROLE_UUID),
    },
}


def platform_v2_role_uuid_for(
    access_type: DefaultAccessType, scope: Scope, policy_service: GlobalPolicyIdService
) -> UUID:
    """
    Get the UUID for the platform default role for the provided access type and scope.

    This UUID is intended for use with Relations (e.g. as a parent role for platform default roles).
    """
    return _uuid_fns[access_type][scope](policy_service)
