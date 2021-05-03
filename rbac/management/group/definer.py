#
# Copyright 2019 Red Hat, Inc.
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

"""Handler for system defined group."""
import logging

from django.db import transaction
from django.db.models.query import QuerySet
from management.group.model import Group
from management.policy.model import Policy
from management.role.model import Role
from tenant_schemas.utils import tenant_context

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def seed_group(tenant):
    """For a tenant create or update default group."""
    with tenant_context(tenant):
        with transaction.atomic():
            name = "Default access"
            group_description = (
                "This group contains the roles that all users inherit by default. "
                "Adding or removing roles in this group will affect permissions for all users in your organization."
            )

            group, group_created = Group.objects.get_or_create(
                platform_default=True, defaults={"description": group_description, "name": name, "system": True}
            )

            # NOTE: after we ensure/enforce all object have a tenant_id FK, we can add tenant=tenant
            # to the get_or_create. We cannot currently, because records without would fail the GET
            # and would create duplicate records. This ensures we temporarily do an update if
            # obj.tenant_id is NULL
            if not group.tenant:
                group.tenant = tenant
                group.save()

            if group.system:
                platform_roles = Role.objects.filter(platform_default=True)
                add_roles(group, platform_roles, tenant, replace=True)
                logger.info("Finished seeding default group %s for tenant %s.", name, tenant.schema_name)
            else:
                logger.info("Default group %s is managed by tenant %s.", name, tenant.schema_name)
    return tenant


def set_system_flag_post_update(group):
    """Update system flag on default groups."""
    if group.system:
        group.name = "Custom default access"
    group.system = False
    group.save()


def add_roles(group, roles_or_role_ids, tenant, replace=False):
    """Process list of roles and add them to the group."""
    system_policy_name = "System Policy for Group {}".format(group.uuid)
    system_policy, system_policy_created = Policy.objects.get_or_create(
        system=True, group=group, name=system_policy_name
    )

    # NOTE: after we ensure/enforce all object have a tenant_id FK, we can add tenant=tenant
    # to the get_or_create. We cannot currently, because records without would fail the GET
    # and would create duplicate records. This ensures we temporarily do an update if
    # obj.tenant_id is NULL
    if not system_policy.tenant:
        system_policy.tenant = tenant
        system_policy.save()

    if system_policy_created:
        logger.info("Created new system policy for tenant.")
    else:
        if replace:
            system_policy.roles.clear()

    if not isinstance(roles_or_role_ids, QuerySet):
        # If given an iterable of UUIDs, get the corresponding objects
        roles = Role.objects.filter(uuid__in=roles_or_role_ids)
    else:
        roles = roles_or_role_ids

    for role in roles:
        system_policy.roles.add(role)

    system_policy.save()


def remove_roles(group, role_ids):
    """Process list of roles and remove them from the group."""
    roles = Role.objects.filter(uuid__in=role_ids)

    for policy in group.policies.all():
        policy.roles.remove(*roles)
