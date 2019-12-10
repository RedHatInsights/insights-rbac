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

from django.core.exceptions import ValidationError
from management.group.model import Group
from management.policy.model import Policy
from management.role.model import Role
from tenant_schemas.utils import tenant_context

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def seed_group(tenant):
    """For a tenant create or update default group."""
    with tenant_context(tenant):
        name = 'Platform group'
        group_description = 'Default group that contains default permissions for new users.'

        group, group_created = Group.objects.get_or_create(
            platform_default=True,
            defaults={
                'description': group_description,
                'name': name,
                'system': True
            }
        )

        if group.system:
            platform_roles = Role.objects.filter(platform_default=True).values_list('uuid', flat=True)
            add_roles(group, platform_roles, replace=True)
            logger.info('Finished seeding default group %s for tenant %s.', name, tenant.schema_name)
        else:
            logger.info('Default group %s is managed by tenant %s.', name, tenant.schema_name)
    return tenant


def set_system_flag_post_update(group):
    """Update system flag on default groups."""
    group.system = False
    group.save()


def add_roles(group, roles, replace=False):
    """Process list of roles and add them to the group."""
    system_policy_name = 'System Policy for Group {}'.format(group.uuid)
    system_policy, system_policy_created = Policy.objects.get_or_create(system=True,
                                                                        group=group,
                                                                        name=system_policy_name)
    if system_policy_created:
        logger.info('Created new system policy for tenant.')
    else:
        if replace:
            system_policy.roles.clear()

    for role_id in roles:
        try:
            role = Role.objects.get(uuid=role_id)
            system_policy.roles.add(role)
        except (Role.DoesNotExist, ValidationError):
            logger.info('No role with id %s to save to group.', role_id)

    system_policy.save()


def remove_roles(group, role_ids):
    """Process list of roles and remove them from the group."""
    roles = []
    for role_id in role_ids:
        try:
            role = Role.objects.get(uuid=role_id)
            roles.append(role)
        except (Role.DoesNotExist, ValidationError):
            logger.info('No role with id %s to delete from group.', role_id)

    for policy in group.policies.all():
        policy.roles.remove(*roles)
        policy.save()
