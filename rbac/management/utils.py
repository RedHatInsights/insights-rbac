#
# Copyright 2019 Red Hat, Inc.
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
"""Helper utilities for management module."""
from django.core.exceptions import PermissionDenied
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext as _
from management.models import Principal
from rest_framework import serializers

USERNAME_KEY = 'username'
APPLICATION_KEY = 'application'


def get_principal_from_request(request):
    """Obtain principal from the request object."""
    current_user = request.user.username
    username = request.query_params.get(USERNAME_KEY)

    if username and not request.user.admin:
        raise PermissionDenied()
    if not username:
        username = current_user

    try:
        principal = Principal.objects.get(username__iexact=username)
    except Principal.DoesNotExist:
        key = 'detail'
        message = 'No data found for principal with username {}.'.format(username)
        raise serializers.ValidationError({key: _(message)})
    return principal


def policies_for_groups(groups):
    """Gathers all policies for the given groups."""
    policies = []
    for group in set(groups):
        group_policies = set(group.policies.all())
        policies += group_policies
    return policies


def roles_for_policies(policies):
    """Gathers all roles for the given policies."""
    roles = []
    for policy in set(policies):
        policy_roles = set(policy.roles.all())
        roles += policy_roles
    return roles


def access_for_roles(roles, application):
    """Gathers all access for the given roles and application."""
    access = []
    for role in set(roles):
        role_access = set(role.access.all())
        for access_item in role_access:
            if application in access_item.permission:
                access.append(access_item)
    return access


def groups_for_principal(principal, **kwargs):
    """Gathers all groups for a principal."""
    return set(principal.group.all())


def policies_for_principal(principal, **kwargs):
    """Gathers all policies for a principal."""
    groups = groups_for_principal(principal)
    return policies_for_groups(groups)


def roles_for_principal(principal, **kwargs):
    """Gathers all roles for a principal."""
    policies = policies_for_principal(principal)
    return roles_for_policies(policies)


def access_for_principal(principal, **kwargs):
    """Gathers all access for a principal for an application."""
    application = kwargs.get(APPLICATION_KEY)
    roles = roles_for_principal(principal)
    access = access_for_roles(roles, application)
    return access


def queryset_by_id(objects, clazz):
    """Return a queryset of from the class ordered by id."""
    wanted_ids = [obj.id for obj in objects]
    return clazz.objects.filter(id__in=wanted_ids).order_by('id')


class AutoDateTimeField(models.DateTimeField):
    """Class that defines is pre_save value."""

    def pre_save(self, model_instance, add):
        """Save its time as now."""
        return timezone.now()
