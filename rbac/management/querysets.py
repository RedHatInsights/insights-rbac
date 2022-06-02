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
from django.conf import settings
from django.db.models.aggregates import Count
from django.urls import reverse
from django.utils.translation import gettext as _
from management.group.model import Group
from management.permissions.role_access import RoleAccessPermission
from management.policy.model import Policy
from management.role.model import Access, Role
from management.utils import (
    APPLICATION_KEY,
    access_for_principal,
    filter_queryset_by_tenant,
    get_admin_from_proxy,
    get_principal,
    get_principal_from_request,
    groups_for_principal,
    policies_for_principal,
    queryset_by_id,
    roles_for_principal,
)
from rest_framework import permissions, serializers

from api.models import Tenant
from rbac.env import ENVIRONMENT


SCOPE_KEY = "scope"
ACCOUNT_SCOPE = "account"
ORG_ID_SCOPE = "org_id"
PRINCIPAL_SCOPE = "principal"
VALID_SCOPES = [ACCOUNT_SCOPE, ORG_ID_SCOPE, PRINCIPAL_SCOPE]
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


def user_has_perm(request, resource):
    """Check to determine if user has RBAC access perms."""
    access = request.user.access
    access_op = "read"
    if request.method in ("POST", "PUT"):
        access_op = "write"
    res_list = access.get(resource, {}).get(access_op, [])
    if not res_list:
        return "None"
    if "*" in res_list:
        return "All"
    return res_list


def has_group_all_access(request):
    """Quick check to determine if a request should have access to all groups on a tenant."""
    return (
        ENVIRONMENT.get_value("ALLOW_ANY", default=False, cast=bool)
        or request.user.admin
        or (request.path == reverse("group-list") and request.method == "GET")
    )


def get_group_queryset(request):
    """Obtain the queryset for groups."""
    return _filter_admin_default(request, _gather_group_querysets(request))


def _gather_group_querysets(request):
    """Decide which groups to provide for request."""
    if settings.AUTHENTICATE_WITH_ORG_ID:
        scope = request.query_params.get(SCOPE_KEY, ORG_ID_SCOPE)
        if scope != ORG_ID_SCOPE:
            return get_object_principal_queryset(request, scope, Group)
    else:
        scope = request.query_params.get(SCOPE_KEY, ACCOUNT_SCOPE)
        if scope != ACCOUNT_SCOPE:
            return get_object_principal_queryset(request, scope, Group)

    public_tenant = Tenant.objects.get(tenant_name="public")
    default_group_set = Group.platform_default_set().filter(
        tenant=request.tenant
    ) or Group.platform_default_set().filter(tenant=public_tenant)

    username = request.query_params.get("username")
    if username:
        principal = get_principal(username, request)
        if principal.cross_account:
            return Group.objects.none()
        return (
            filter_queryset_by_tenant(Group.objects.filter(principals__username__iexact=username), request.tenant)
            | default_group_set
        )

    if has_group_all_access(request):
        return filter_queryset_by_tenant(get_annotated_groups(), request.tenant) | default_group_set

    access = user_has_perm(request, "group")

    if access == "All":
        return filter_queryset_by_tenant(get_annotated_groups(), request.tenant) | default_group_set
    if access == "None":
        return Group.objects.none()

    return filter_queryset_by_tenant(Group.objects.filter(uuid__in=access), request.tenant) | default_group_set


def annotate_roles_with_counts(queryset):
    """Annotate the queryset for roles with counts."""
    return queryset.annotate(policyCount=Count("policies", distinct=True), accessCount=Count("access", distinct=True))


def get_role_queryset(request):
    """Obtain the queryset for roles."""
    scope = request.query_params.get(SCOPE_KEY, ACCOUNT_SCOPE)
    public_tenant = Tenant.objects.get(tenant_name="public")
    base_query = annotate_roles_with_counts(Role.objects.prefetch_related("access")).filter(
        tenant__in=[request.tenant, public_tenant]
    )

    if scope != (ACCOUNT_SCOPE or ORG_ID_SCOPE):
        queryset = get_object_principal_queryset(
            request,
            scope,
            Role,
            **{
                "prefetch_lookups_for_ids": "access",
                "prefetch_lookups_for_groups": "policies__roles",
                "is_org_admin": request.user.admin,
            },
        )
        return annotate_roles_with_counts(queryset)

    username = request.query_params.get("username")
    if username:
        role_permission = RoleAccessPermission()

        if username != request.user.username and not role_permission.has_permission(request=request, view=None):
            return Role.objects.none()
        else:
            if settings.BYPASS_BOP_VERIFICATION:
                is_org_admin = request.user.admin
            else:
                is_org_admin = get_admin_from_proxy(username, request)

            queryset = get_object_principal_queryset(
                request,
                PRINCIPAL_SCOPE,
                Role,
                **{
                    "prefetch_lookups_for_ids": "access",
                    "prefetch_lookups_for_groups": "policies__roles",
                    "is_org_admin": is_org_admin,
                },
            )
            return annotate_roles_with_counts(queryset)

    if ENVIRONMENT.get_value("ALLOW_ANY", default=False, cast=bool):
        return base_query
    if request.user.admin:
        return base_query
    access = user_has_perm(request, "role")
    if access == "All":
        return base_query
    if access == "None":
        return Role.objects.none()
    return annotate_roles_with_counts(filter_queryset_by_tenant(Role.objects.filter(uuid__in=access), request.tenant))


def get_policy_queryset(request):
    """Obtain the queryset for policies."""
    if settings.AUTHENTICATE_WITH_ORG_ID:
        scope = request.query_params.get(SCOPE_KEY, ORG_ID_SCOPE)
        if scope != ORG_ID_SCOPE:
            return get_object_principal_queryset(request, scope, Policy)
    else:
        scope = request.query_params.get(SCOPE_KEY, ACCOUNT_SCOPE)
        if scope != ACCOUNT_SCOPE:
            return get_object_principal_queryset(request, scope, Policy)

    if ENVIRONMENT.get_value("ALLOW_ANY", default=False, cast=bool):
        return filter_queryset_by_tenant(Policy.objects.all(), request.tenant)
    if request.user.admin:
        return filter_queryset_by_tenant(Policy.objects.all(), request.tenant)
    access = user_has_perm(request, "policy")

    if access == "All":
        return filter_queryset_by_tenant(Policy.objects.all(), request.tenant)
    if access == "None":
        return Policy.objects.none()
    return filter_queryset_by_tenant(Policy.objects.filter(uuid__in=access), request.tenant)


def get_access_queryset(request):
    """Obtain the queryset for policies."""
    required_parameters = [APPLICATION_KEY]
    have_parameters = all(param in request.query_params for param in required_parameters)

    if not have_parameters:
        key = "detail"
        message = "Query parameters [{}] are required.".format(", ".join(required_parameters))
        raise serializers.ValidationError({key: _(message)})

    app = request.query_params.get(APPLICATION_KEY)
    # If we are querying on a username we need to check if the username is an org_admin
    # not the user making the request
    username = request.query_params.get("username")
    if not username or settings.BYPASS_BOP_VERIFICATION:
        is_org_admin = request.user.admin
    else:
        is_org_admin = get_admin_from_proxy(username, request)

    return get_object_principal_queryset(
        request,
        PRINCIPAL_SCOPE,
        Access,
        **{
            APPLICATION_KEY: app,
            "prefetch_lookups_for_ids": "resourceDefinitions",
            "prefetch_lookups_for_groups": "policies__roles__access",
            "is_org_admin": is_org_admin,
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
    objects = object_principal_func(principal, request.tenant, **kwargs)
    return queryset_by_id(objects, clazz, **kwargs)


def _filter_admin_default(request, queryset):
    """Filter out admin default groups unless the principal is an org admin."""
    # If the principal is an org admin, make sure they get any and all admin_default groups
    if request.user.admin:
        public_tenant = Tenant.objects.get(tenant_name="public")
        admin_default_group_set = Group.admin_default_set().filter(
            tenant=request.tenant
        ) or Group.admin_default_set().filter(tenant=public_tenant)

        return queryset | admin_default_group_set

    return queryset
