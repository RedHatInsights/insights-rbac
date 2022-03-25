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
from uuid import uuid4

from django.db import transaction
from django.db.models import Q
from django.db.models.query import QuerySet
from django.utils.translation import gettext as _
from management.group.model import Group
from management.notifications.notification_hanlders import (
    group_flag_change_notification_handler,
    group_role_change_notification_handler,
)
from management.policy.model import Policy
from management.role.model import Role
from management.utils import clear_pk
from rest_framework import serializers

from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def seed_group():
    """Create or update default group."""
    public_tenant = Tenant.objects.get(tenant_name="public")
    with transaction.atomic():
        name = "Default access"
        group_description = (
            "This group contains the roles that all users inherit by default. "
            "Adding or removing roles in this group will affect permissions for all users in your organization."
        )

        group, group_created = Group.objects.get_or_create(
            platform_default=True,
            defaults={"description": group_description, "name": name, "system": True},
            tenant=public_tenant,
        )

        platform_roles = Role.objects.filter(platform_default=True)
        add_roles(group, platform_roles, public_tenant)
        logger.info("Finished seeding default group %s.", name)

        # Default admin group
        admin_name = "Default admin access"
        admin_group_description = (
            "This group contains the roles that all org admin users inherit by default. "
            "Adding or removing roles in this group will affect permissions for all org admin users in your org."
        )
        admin_group, admin_group_created = Group.objects.get_or_create(
            admin_default=True,
            defaults={"description": admin_group_description, "name": admin_name, "system": True},
            tenant=public_tenant,
        )
        platform_roles = Role.objects.filter(admin_default=True)
        add_roles(admin_group, platform_roles, public_tenant)
        logger.info("Finished seeding default org admin group %s.", name)


def set_system_flag_before_update(group, tenant, user):
    """Update system flag on default groups."""
    if group.system:
        group = clone_default_group_in_public_schema(group, tenant)
        group_flag_change_notification_handler(user, group)
    return group


def clone_default_group_in_public_schema(group, tenant):
    """Clone the default group for a tenant into the public schema."""
    tenant_default_policy = group.policies.get(system=True)
    group.name = "Custom default access"
    group.system = False
    group.tenant = tenant
    group.uuid = uuid4()
    clear_pk(group)
    clear_pk(tenant_default_policy)
    tenant_default_policy.uuid = uuid4()
    tenant_default_policy.name = "System Policy for Group {}".format(group.uuid)
    tenant_default_policy.tenant = tenant
    if Group.objects.filter(name=group.name, platform_default=group.platform_default, tenant=tenant):
        return
    public_default_roles = Role.objects.filter(platform_default=True)

    group.save()
    tenant_default_policy.group = group
    tenant_default_policy.save()
    tenant_default_policy.roles.set(public_default_roles)
    return group


def add_roles(group, roles_or_role_ids, tenant, user=None):
    """Process list of roles and add them to the group."""
    if not isinstance(roles_or_role_ids, QuerySet):
        # If given an iterable of UUIDs, get the corresponding objects
        roles = Role.objects.filter(uuid__in=roles_or_role_ids)
    else:
        roles = roles_or_role_ids
    group_name = group.name
    role_names = list(roles.values_list("name", flat=True))

    group, created = Group.objects.get_or_create(name=group_name, tenant=tenant)
    system_policy_name = "System Policy for Group {}".format(group.uuid)
    system_policy, system_policy_created = Policy.objects.update_or_create(
        system=True, group=group, name=system_policy_name, defaults={"tenant": tenant}
    )

    if system_policy_created:
        logger.info(f"Created new system policy for tenant {tenant.tenant_name}.")

    roles = Role.objects.filter(
        Q(tenant=tenant) | Q(tenant=Tenant.objects.get(tenant_name="public")), name__in=role_names
    )
    for role in roles:
        accesses = role.access.all()
        for access in accesses:
            if access.permission_application() == "rbac" and user and not user.admin:
                key = "add-roles"
                message = f"Non-admin users cannot add RBAC role {role.display_name} to groups."
                raise serializers.ValidationError({key: _(message)})
        # Only add the role if it was not attached
        if not system_policy.roles.filter(pk=role.pk).exists():
            system_policy.roles.add(role)

            # Send notifications
            group_role_change_notification_handler(user, group, role, "added")


def remove_roles(group, role_ids, tenant, user):
    """Process list of roles and remove them from the group."""
    roles = Role.objects.filter(uuid__in=role_ids)
    role_names = list(roles.values_list("name", flat=True))

    group = Group.objects.get(name=group.name, tenant=tenant)
    roles = group.roles().filter(name__in=role_names)
    for policy in group.policies.all():
        # Only remove the role if it was attached
        for role in roles:
            if policy.roles.filter(pk=role.pk).exists():
                policy.roles.remove(role)

                # Send notifications
                group_role_change_notification_handler(user, group, role, "remove")
