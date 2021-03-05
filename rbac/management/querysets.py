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
from django.urls import reverse
from django.utils.translation import gettext as _
from management.group.model import Group
from management.policy.model import Policy
from management.role.model import Access, Role
from management.utils import (
    APPLICATION_KEY,
    access_for_principal,
    get_principal,
    get_principal_from_request,
    groups_for_principal,
    policies_for_principal,
    queryset_by_id,
    roles_for_principal,
)
from rest_framework import permissions, serializers

from rbac.env import ENVIRONMENT

SCOPE_KEY = "scope"
ACCOUNT_SCOPE = "account"
PRINCIPAL_SCOPE = "principal"
VALID_SCOPES = [ACCOUNT_SCOPE, PRINCIPAL_SCOPE]
PRINCIPAL_QUERYSET_MAP = {
    Access.__name__: access_for_principal,
    Group.__name__: groups_for_principal,
    Policy.__name__: policies_for_principal,
    Role.__name__: roles_for_principal,
}


def get_annotated_groups():
    """Return an annotated set of groups for the tenant."""
    return Group.objects.annotate(
        principalCount=Count("principals", distinct=True), policyCount=Count("policies", distinct=True)
    )


def has_group_all_access(request):
    """Quick check to determine if a request should have access to all groups on a tenant."""
    return (
        ENVIRONMENT.get_value("ALLOW_ANY", default=False, cast=bool)
        or request.user.admin
        or (request.path == reverse("group-list") and request.method == "GET")
    )


def get_group_queryset(request):
    """Obtain the queryset for groups."""
    scope = request.query_params.get(SCOPE_KEY, ACCOUNT_SCOPE)
    if scope != ACCOUNT_SCOPE:
        return get_object_principal_queryset(request, scope, Group)

    username = request.query_params.get("username")
    if username:
        principal = get_principal(username, request.user.account)
        if principal.cross_account:
            return Group.objects.none()
        return Group.objects.filter(principals__username__iexact=username) | Group.platform_default_set()

    if has_group_all_access(request):
        return get_annotated_groups() | Group.platform_default_set()

    return Group.objects.none()


def annotate_roles_with_counts(queryset):
    """Annotate the queryset for roles with counts."""
    return queryset.annotate(policyCount=Count("policies", distinct=True), accessCount=Count("access", distinct=True))


def get_role_queryset(request):
    """Obtain the queryset for roles."""
    scope = request.query_params.get(SCOPE_KEY, ACCOUNT_SCOPE)
    base_query = annotate_roles_with_counts(Role.objects.prefetch_related("access"))

    if scope != ACCOUNT_SCOPE:
        queryset = get_object_principal_queryset(
            request,
            scope,
            Role,
            **{"prefetch_lookups_for_ids": "access", "prefetch_lookups_for_groups": "policies__roles"},
        )
        return annotate_roles_with_counts(queryset)

    username = request.query_params.get("username")
    if username:
        if username != request.user.username and not request.user.admin:
            return Role.objects.none()
        else:
            queryset = get_object_principal_queryset(
                request,
                PRINCIPAL_SCOPE,
                Role,
                **{"prefetch_lookups_for_ids": "access", "prefetch_lookups_for_groups": "policies__roles"},
            )

            return annotate_roles_with_counts(queryset)

    if ENVIRONMENT.get_value("ALLOW_ANY", default=False, cast=bool):
        return base_query
    if request.user.admin:
        return base_query
    access = request.user.access
    access_op = "read"
    if request.method in ("POST", "PUT"):
        access_op = "write"
    res_list = access.get("role", {}).get(access_op, [])
    if not res_list:
        return Role.objects.none()
    if "*" in res_list:
        return base_query
    return base_query.filter(uuid__in=res_list)


def get_policy_queryset(request):
    """Obtain the queryset for policies."""
    scope = request.query_params.get(SCOPE_KEY, ACCOUNT_SCOPE)
    if scope != ACCOUNT_SCOPE:
        return get_object_principal_queryset(request, scope, Policy)

    if ENVIRONMENT.get_value("ALLOW_ANY", default=False, cast=bool):
        return Policy.objects.all()
    if request.user.admin:
        return Policy.objects.all()
    access = request.user.access
    access_op = "read"
    if request.method in ("POST", "PUT"):
        access_op = "write"
    res_list = access.get("policy", {}).get(access_op, [])
    if not res_list:
        return Policy.objects.none()
    if "*" in res_list:
        return Policy.objects.all()
    return Policy.objects.filter(uuid__in=res_list)


def get_access_queryset(request):
    """Obtain the queryset for policies."""
    required_parameters = [APPLICATION_KEY]
    have_parameters = all(param in request.query_params for param in required_parameters)

    if not have_parameters:
        key = "detail"
        message = "Query parameters [{}] are required.".format(", ".join(required_parameters))
        raise serializers.ValidationError({key: _(message)})

    app = request.query_params.get(APPLICATION_KEY)
    return get_object_principal_queryset(
        request,
        PRINCIPAL_SCOPE,
        Access,
        **{
            APPLICATION_KEY: app,
            "prefetch_lookups_for_ids": "resourceDefinitions",
            "prefetch_lookups_for_groups": "policies__roles__access",
        },
    )


def get_object_principal_queryset(request, scope, clazz, **kwargs):
    """Get the query set for the specific object for principal scope."""
    if scope not in VALID_SCOPES:
        key = "detail"
        message = "{} query parameter value {} is invalid. [{}] are valid inputs.".format(
            SCOPE_KEY, scope, ", ".join(VALID_SCOPES)
        )
        raise serializers.ValidationError({key: _(message)})

    if request.method not in permissions.SAFE_METHODS:
        return clazz.objects.none()

    object_principal_func = PRINCIPAL_QUERYSET_MAP.get(clazz.__name__)
    principal = get_principal_from_request(request)
    objects = object_principal_func(principal, **kwargs)
    return queryset_by_id(objects, clazz, **kwargs)
