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
"""Provide common helpers for V2 tenant relationships."""
import enum
import logging
from typing import Optional

from kessel.relations.v1beta1.common_pb2 import Relationship

from management.models import Group
from management.tenant_mapping.model import TenantMapping
from migration_tool.utils import create_relationship

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class DefaultGroupNotAvailableError(Exception):
    """Indicates that a request for a platform or admin default group could not be fulfilled."""

    pass


class GlobalPolicyIdCache:
    """Caches the platofrm and admin default policy UUIDs (used as default role IDs in V2)."""

    def __init__(self):
        """Initialize an empty GlobalPolicyIdCache."""
        self._platform_default_uuid = None
        self._admin_default_uuid = None

    def platform_default_policy_uuid(self) -> str:
        """
        Return the policy UUID of the global platform default group.

        Raises DefaultGroupNotAvailableError if no such group exists.
        """
        try:
            if self._platform_default_uuid is None:
                policy = Group.objects.public_tenant_only().get(platform_default=True).policies.get()
                self._platform_default_uuid = str(policy.uuid)
            return self._platform_default_uuid
        except Group.DoesNotExist as e:
            raise DefaultGroupNotAvailableError() from e

    def admin_default_policy_uuid(self) -> str:
        """
        Return the policy UUID of the global admin default group.

        Raises DefaultGroupNotAvailableError if no such group exists.
        """
        try:
            if self._admin_default_uuid is None:
                policy = Group.objects.public_tenant_only().get(admin_default=True).policies.get()
                self._admin_default_uuid = str(policy.uuid)
            return self._admin_default_uuid
        except Group.DoesNotExist as e:
            raise DefaultGroupNotAvailableError() from e


class DefaultRoleBindingType(enum.StrEnum):
    USER = "user"
    ADMIN = "admin"


def default_role_binding_tuples(
    tenant_mapping: TenantMapping,
    target_workspace_uuid: str,
    role_type: DefaultRoleBindingType,
    resource_binding_only: bool = False,
    policy_cache: Optional[GlobalPolicyIdCache] = None,
) -> list[Relationship]:
    """
    Create the tuples used to bootstrap default access for a Workspace.

    If resource_binding_only is true, only return the relationship that binds the role binding to the target resource.
    This might be used when removing default access from a resource (while still leaving the role binding itself
    around, if it already exists).

    The optional policy_cache argument can be used to prevent redundant policy UUID lookups across calls.
    """
    if policy_cache is None:
        policy_cache = GlobalPolicyIdCache()

    if role_type == DefaultRoleBindingType.USER:
        role_binding_uuid = str(tenant_mapping.default_role_binding_uuid)
        default_group_uuid = str(tenant_mapping.default_group_uuid)
        default_role_uuid = policy_cache.platform_default_policy_uuid()

        if default_role_uuid is None:
            logger.warning("No platform default role found for public tenant. Default access will not be set up.")
    elif role_type == DefaultRoleBindingType.ADMIN:
        role_binding_uuid = str(tenant_mapping.default_admin_role_binding_uuid)
        default_group_uuid = str(tenant_mapping.default_admin_group_uuid)
        default_role_uuid = policy_cache.admin_default_policy_uuid()

        if default_role_uuid is None:
            logger.warning("No admin default role found for public tenant. Default access will not be set up.")
    else:
        raise ValueError(f"Unexpected role type: {role_type}")

    # Always add the relationship from the role binding to the target resource.
    relationships = [
        create_relationship(
            ("rbac", "workspace"),
            target_workspace_uuid,
            ("rbac", "role_binding"),
            role_binding_uuid,
            "binding",
        )
    ]

    if not resource_binding_only:
        relationships.extend(
            [
                create_relationship(
                    ("rbac", "role_binding"),
                    role_binding_uuid,
                    ("rbac", "role"),
                    default_role_uuid,
                    "role",
                ),
                create_relationship(
                    ("rbac", "role_binding"),
                    role_binding_uuid,
                    ("rbac", "group"),
                    default_group_uuid,
                    "subject",
                    "member",
                ),
            ]
        )

    return relationships
