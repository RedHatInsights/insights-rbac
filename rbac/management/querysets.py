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
"""Queryset helpers for management module."""
from django.db.models.aggregates import Count
from management.group.model import Group
from management.policy.model import Policy
from management.role.model import Role


def get_group_queryset(request):
    """Obtain the queryset for groups."""
    if request.user.admin:
        return Group.objects.annotate(principalCount=Count('principals'),
                                      policyCount=Count('policies'))

    username = request.query_params.get('username')
    if username:
        decoded = request.user.identity_header.get('decoded', {})
        identity_username = decoded.get('identity', {}).get('user', {}).get('username')
        if username != identity_username:
            return Group.objects.none()
        else:
            return Group.objects.filter(principals__username=username)
    access = request.user.access
    access_op = 'read'
    if request.method in ('POST', 'PUT'):
        access_op = 'write'
    res_list = access.get('group', {}).get(access_op, [])
    if not res_list:
        return Group.objects.none()
    if '*' in res_list:
        return Group.objects.annotate(principalCount=Count('principals'),
                                      policyCount=Count('policies'))
    return Group.objects.filter(uuid__in=res_list).annotate(principalCount=Count('principals'),
                                                            policyCount=Count('policies'))


def get_role_queryset(request):
    """Obtain the queryset for roles."""
    if request.user.admin:
        return Role.objects.annotate(policyCount=Count('policies'))
    access = request.user.access
    access_op = 'read'
    if request.method in ('POST', 'PUT'):
        access_op = 'write'
    res_list = access.get('role', {}).get(access_op, [])
    if not res_list:
        return Role.objects.none()
    if '*' in res_list:
        return Role.objects.annotate(policyCount=Count('policies'))
    return Role.objects.filter(uuid__in=res_list).annotate(policyCount=Count('policies'))


def get_policy_queryset(request):
    """Obtain the queryset for policies."""
    if request.user.admin:
        return Policy.objects.all()
    access = request.user.access
    access_op = 'read'
    if request.method in ('POST', 'PUT'):
        access_op = 'write'
    res_list = access.get('policy', {}).get(access_op, [])
    if not res_list:
        return Policy.objects.none()
    if '*' in res_list:
        return Policy.objects.all()
    return Policy.objects.filter(uuid__in=res_list)
