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
import json
import os
from uuid import UUID

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.utils.translation import gettext as _
from management.models import Access, Group, Policy, Principal, Role
from management.permissions.principal_access import PrincipalAccessPermission
from management.principal.proxy import PrincipalProxy
from rest_framework import serializers, status

from api.models import CrossAccountRequest, Tenant


USERNAME_KEY = "username"
APPLICATION_KEY = "application"
PRINCIPAL_PERMISSION_INSTANCE = PrincipalAccessPermission()


def validate_psk(psk, client_id):
    """Validate the PSK for the client."""
    psks = json.loads(os.environ.get("SERVICE_PSKS", "{}"))
    client_config = psks.get(client_id, {})
    primary_key = client_config.get("secret")
    alt_key = client_config.get("alt-secret")

    if psks:
        return psk == primary_key or psk == alt_key

    return False


def get_principal_from_request(request):
    """Obtain principal from the request object."""
    current_user = request.user.username
    qs_user = request.query_params.get(USERNAME_KEY)
    username = current_user
    from_query = False
    if qs_user and not PRINCIPAL_PERMISSION_INSTANCE.has_permission(request=request, view=None):
        raise PermissionDenied()

    if qs_user:
        username = qs_user
        from_query = True

    return get_principal(username, request, verify_principal=bool(qs_user), from_query=from_query)


def get_principal(username, request, verify_principal=True, from_query=False):
    """Get principals from username."""
    # First check if principal exist on our side,
    # if not call BOP to check if user exist in the account.
    tenant = request.tenant
    try:
        # If the username was provided through a query we must verify if it is an org admin from the BOP
        if from_query:
            verify_principal_with_proxy(username, request, verify_principal=verify_principal)
        principal = Principal.objects.get(username__iexact=username, tenant=tenant)
    except Principal.DoesNotExist:
        verify_principal_with_proxy(username, request, verify_principal=verify_principal)

        # Avoid possible race condition if the user was created while checking BOP
        principal, created = Principal.objects.get_or_create(
            username=username, tenant=tenant
        )  # pylint: disable=unused-variable

    return principal


def verify_principal_with_proxy(username, request, verify_principal=True):
    """Verify username through the BOP."""
    account = request.user.account
    org_id = request.user.org_id
    proxy = PrincipalProxy()
    if verify_principal:
        if settings.AUTHENTICATE_WITH_ORG_ID:
            resp = proxy.request_filtered_principals([username], org_id=org_id)
        else:
            resp = proxy.request_filtered_principals([username], account)

        if isinstance(resp, dict) and "errors" in resp:
            raise Exception("Dependency error: request to get users from dependent service failed.")

        if not resp.get("data"):
            key = "detail"
            message = "No data found for principal with username '{}'.".format(username)
            raise serializers.ValidationError({key: _(message)})

        return resp


def policies_for_groups(groups):
    """Gathers all policies for the given groups."""
    policies = Policy.objects.filter(group__in=set(groups))
    return set(policies)


def roles_for_policies(policies):
    """Gathers all roles for the given policies."""
    roles = Role.objects.filter(policies__in=set(policies))
    return set(roles)


def access_for_roles(roles, param_applications):
    """Gathers all access for the given roles and application(s)."""
    if param_applications:
        param_applications_list = param_applications.split(",")
        access = Access.objects.filter(role__in=roles).filter(permission__application__in=param_applications_list)
    else:
        access = Access.objects.filter(role__in=roles)
    return set(access)


def groups_for_principal(principal, tenant, **kwargs):
    """Gathers all groups for a principal, including the default."""
    if principal.cross_account:
        return set()
    assigned_group_set = principal.group.all()
    public_tenant = Tenant.objects.get(tenant_name="public")
    platform_default_group_set = Group.platform_default_set().filter(
        tenant=tenant
    ) or Group.platform_default_set().filter(tenant=public_tenant)

    admin_default_group_set = Group.admin_default_set().filter(tenant=tenant) or Group.admin_default_set().filter(
        tenant=public_tenant
    )
    prefetch_lookups = kwargs.get("prefetch_lookups_for_groups")

    if prefetch_lookups:
        assigned_group_set = assigned_group_set.prefetch_related(prefetch_lookups)
        platform_default_group_set = platform_default_group_set.prefetch_related(prefetch_lookups)

    if kwargs.get("is_org_admin"):
        return set(assigned_group_set | platform_default_group_set | admin_default_group_set)

    return set(assigned_group_set | platform_default_group_set)


def policies_for_principal(principal, tenant, **kwargs):
    """Gathers all policies for a principal."""
    groups = groups_for_principal(principal, tenant, **kwargs)
    return policies_for_groups(groups)


def roles_for_principal(principal, tenant, **kwargs):
    """Gathers all roles for a principal."""
    if principal.cross_account:
        return roles_for_cross_account_principal(principal)
    policies = policies_for_principal(principal, tenant, **kwargs)
    return roles_for_policies(policies)


def access_for_principal(principal, tenant, **kwargs):
    """Gathers all access for a principal for an application."""
    application = kwargs.get(APPLICATION_KEY)
    roles = roles_for_principal(principal, tenant, **kwargs)
    access = access_for_roles(roles, application)
    return access


def queryset_by_id(objects, clazz, **kwargs):
    """Return a queryset of from the class ordered by id."""
    wanted_ids = [obj.id for obj in objects]
    prefetch_lookups = kwargs.get("prefetch_lookups_for_ids")
    query = clazz.objects.filter(id__in=wanted_ids).order_by("id")
    if prefetch_lookups:
        query = query.prefetch_related(prefetch_lookups)

    return query


def filter_queryset_by_tenant(queryset, tenant):
    """Limit queryset by appropriate tenant when serving from public schema."""
    return queryset.filter(tenant=tenant)


def deduplicate_access_queryset(queryset):
    """
    Deduplicate the access queryset.

    Takes a queryset on the Access model, and returns a list of the minimal
    permissions described in the original queryset.  These deduplications are
    performed:

    1: two exactly matching permissions are combined - e.g. 'app:*:read' and
       'app:*:read' - including joining together their resourceDefinitions.
    2: '*' implies all other verbs.  Therefore 'app:*:read' will be ignored
       in favour of 'app:*:*'.  Ignored permissions have their
       resourceDefinitions thrown away, because they are superseded.
    """
    # Since the ordering does not matter, we record these in a dict by the
    # permission, for ease of access.
    deduplicated_access = dict()

    def matching_perms(this_access, sought_access):
        """Find all access objects that match the app and resource given."""
        tap = this_access.permission
        sap = sought_access.permission
        return tap.app == sap.app and tap.resource_type == sap.resource_type

    for access in queryset:
        if not access.permission:
            # Cannot emit an access permission if it doesn't have one
            continue
        if access.permission.permission not in deduplicated_access:
            if access.verb == '*':
                # Rule 2 (reverse): does this permission supersede any access
                # objects we have already?
                matching_access_objs = list(filter(
                    lambda a: matching_perms(a, access),
                    deduplicated_access.values()
                ))
                # have to listify it because we're going to possibly edit the
                # dict, and doing that while a filter is running is... sketchy
                for superseded in matching_access_objs:
                    del deduplicated_access[superseded.permission.permission]
            else:
                # Rule 2 (forward): is this included in a '*' permission on
                # the same app and resource?
                if f"{access.permission.app}:{access.permission.resource_type}:*" in deduplicated_access:
                    # we can throw this one away then, it's superseded.
                    continue
        else:
            # Combine this access object's resource definitions into that
            # already stored.  Note that at this stage we DO NOT attempt to
            # merge attributeFilter structures.
            deduplicated_access[access.permission.permission].resourceDefinitions.extend(
                access.resourceDefinitions
            )
    # Return access object list in order by permission for testing consistency
    return (deduplicated_access[perm] for perm in sorted(deduplicated_access.keys()))


def validate_and_get_key(params, query_key, valid_values, default_value=None, required=True):
    """Validate the key."""
    value = params.get(query_key, default_value)
    if not value:
        if required:
            key = "detail"
            message = "Query parameter '{}' is required.".format(query_key)
            raise serializers.ValidationError({key: _(message)})
        return None

    elif value.lower() not in valid_values:
        key = "detail"
        message = "{} query parameter value '{}' is invalid. {} are valid inputs.".format(
            query_key, value, valid_values
        )
        raise serializers.ValidationError({key: _(message)})
    return value.lower()


def validate_uuid(uuid, key="UUID Validation"):
    """Verify UUID provided is valid."""
    try:
        UUID(uuid)
    except ValueError:
        key = key
        message = f"{uuid} is not a valid UUID."
        raise serializers.ValidationError({key: _(message)})


def validate_group_name(name):
    """Verify name provided is valid."""
    if name and name.lower() in ["custom default access", "default access"]:
        key = "Group name Validation"
        message = f"{name} is reserved, please use another name."
        raise serializers.ValidationError({key: _(message)})


def validate_limit_and_offset(query_params):
    """Limit and offset should not be negative number."""
    if (int(query_params.get("limit", 10)) < 0) | (int(query_params.get("offset", 0)) < 0):
        error = {
            "detail": "Values for limit and offset must be positive numbers.",
            "source": "CrossAccountRequest",
            "status": str(status.HTTP_400_BAD_REQUEST),
        }
        return {"errors": [error]}


def roles_for_cross_account_principal(principal):
    """Return roles for cross account principals."""
    target_account, user_id = principal.username.split("-")
    target_org = principal.tenant.org_id
    if settings.AUTHENTICATE_WITH_ORG_ID:
        role_names = (
            CrossAccountRequest.objects.filter(target_org=target_org, user_id=user_id, status="approved")
            .values_list("roles__name", flat=True)
            .distinct()
        )
    else:
        role_names = (
            CrossAccountRequest.objects.filter(target_account=target_account, user_id=user_id, status="approved")
            .values_list("roles__name", flat=True)
            .distinct()
        )
    role_names_list = list(role_names)
    return Role.objects.filter(name__in=role_names_list)


def clear_pk(entry):
    """Clear the ID and PK values for provided postgres entry."""
    entry.id = None
    entry.pk = None


def account_id_for_tenant(tenant):
    """Return the account id from a tenant's name."""
    return tenant.tenant_name.replace("acct", "")


def get_admin_from_proxy(username, request):
    """Return org_admin status of a username from the proxy."""
    bop_resp = verify_principal_with_proxy(username, request, verify_principal=True)

    if bop_resp.get("data") == []:
        key = "detail"
        message = "No data found for principal with username '{}'.".format(username)
        raise serializers.ValidationError({key: _(message)})

    index = next(
        (i for i, x in enumerate(bop_resp.get("data")) if x["username"].casefold() == username.casefold()), None
    )

    if index is None:
        key = "detail"
        message = "No data found for principal with username '{}'.".format(username)
        raise serializers.ValidationError({key: _(message)})

    is_org_admin = bop_resp.get("data")[index]["is_org_admin"]
    return is_org_admin
