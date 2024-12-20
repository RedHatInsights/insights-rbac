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
import uuid
from uuid import UUID

from django.core.exceptions import PermissionDenied
from django.utils.translation import gettext as _
from management.models import Access, Group, Policy, Principal, Role
from management.permissions.principal_access import PrincipalAccessPermission
from management.principal.it_service import ITService
from management.principal.proxy import PrincipalProxy
from rest_framework import serializers
from rest_framework.request import Request

from api.models import CrossAccountRequest, Tenant

USERNAME_KEY = "username"
APPLICATION_KEY = "application"
PRINCIPAL_PERMISSION_INSTANCE = PrincipalAccessPermission()
SERVICE_ACCOUNT_KEY = "service-account"


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


def get_principal(
    username: str, request: Request, verify_principal: bool = True, from_query: bool = False
) -> Principal:
    """Get principals from username.

    The service account usernames are not being validated for now because that would require for the clients to send
    tokens with the "api.iam.service_accounts" scope. That conflicts with the following two use cases:

    - A user sends a request to the /access/?username=service-account-<uuid> endpoint.
    - A service account makes a request to /access.

    In these two cases, due to how "get_principal_from_request" works, we would need to validate the service account
    against IT, but the only way to do it is by using a bearer token that we can only obtain from the incoming request.

    Until RBAC is given some other means to validate the service accounts, we are skipping that validation. Also, this
    does not affect the other endpoints where we need to validate service accounts —listed below just in case—, because
    there the bearer token with that claim is a must to be able to manage the service accounts. The endpoints that are
    fine are:

    - GET /principals/?type=service-account
    - GET /groups/{uuid}/principals/?principal_type=service-account
    - POST /groups/{uuid}/principals/ with a service account payload
    - DELETE /groups/{uuid}/principals/?service-account=<uuid>.
    """
    # First check if principal exist on our side, if not call BOP to check if user exist in the account.
    tenant: Tenant = request.tenant
    is_username_service_account = ITService.is_username_service_account(username)

    try:
        # If the username was provided through a query we must verify if it exists in the corresponding services first.
        if from_query and not is_username_service_account:
            verify_principal_with_proxy(username=username, request=request, verify_principal=verify_principal)

        principal = Principal.objects.get(username__iexact=username, tenant=tenant)
    except Principal.DoesNotExist:
        # If the "from query" parameter was specified, the username was validated above, so there is no need to
        # validate it again.
        if not from_query and not is_username_service_account:
            verify_principal_with_proxy(username=username, request=request, verify_principal=verify_principal)

        if is_username_service_account:
            client_id: uuid.UUID = ITService.extract_client_id_service_account_username(username)

            principal, _ = Principal.objects.get_or_create(
                username=username, tenant=tenant, type=SERVICE_ACCOUNT_KEY, service_account_id=client_id
            )
        else:
            # Avoid possible race condition if the user was created while checking BOP
            principal, _ = Principal.objects.get_or_create(username=username, tenant=tenant)

    return principal


def verify_principal_with_proxy(username, request, verify_principal=True):
    """Verify username through the BOP."""
    org_id = request.user.org_id
    proxy = PrincipalProxy()
    if verify_principal:
        resp = proxy.request_filtered_principals([username], org_id=org_id, options=request.query_params)

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


def groups_for_principal(principal: Principal, tenant, **kwargs):
    """Gathers all groups for a principal, including the default."""
    if principal.cross_account:
        return set()
    assigned_group_set = principal.group.all()

    # Only user principals should be able to get permissions from the default groups. For service accounts, customers
    # need to explicitly add the service accounts to a group.
    if principal.type == "user":
        admin_default_group_set = (
            Group.admin_default_set().filter(tenant=tenant) or Group.admin_default_set().public_tenant_only()
        )
        platform_default_group_set = (
            Group.platform_default_set().filter(tenant=tenant) or Group.platform_default_set().public_tenant_only()
        )
    else:
        admin_default_group_set = Group.objects.none()
        platform_default_group_set = Group.objects.none()

    prefetch_lookups = kwargs.get("prefetch_lookups_for_groups")

    if prefetch_lookups:
        assigned_group_set = assigned_group_set.prefetch_related(prefetch_lookups)

        if principal.type == "user":
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


def validate_and_get_key(params, query_key, valid_values, default_value=None, required=True):
    """Validate and return the key."""
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


def validate_key(params, query_key, valid_values, default_value=None, required=True):
    """Validate a key and do not return the value."""
    value = params.get(query_key, default_value)
    if value.lower() not in valid_values:
        key = "detail"
        message = "{} query parameter value '{}' is invalid. {} are valid inputs.".format(
            query_key, value, valid_values
        )
        raise serializers.ValidationError({key: _(message)})


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


def roles_for_cross_account_principal(principal):
    """Return roles for cross account principals."""
    _, user_id = principal.username.split("-")
    target_org = principal.tenant.org_id
    role_names = (
        CrossAccountRequest.objects.filter(target_org=target_org, user_id=user_id, status="approved")
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

    if not bop_resp.get("data"):
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


def api_path_prefix():
    """Get api path prefix."""
    path_prefix = os.getenv("API_PATH_PREFIX", "api/")
    if path_prefix != "":
        if path_prefix.startswith("/"):
            path_prefix = path_prefix[1:]
        if not path_prefix.endswith("/"):
            path_prefix = path_prefix + "/"
    return path_prefix


def v2response_error_from_errors(errors, exc=None, context=None):
    """Convert v1 error format to v2."""
    detail = ""
    status_code = 0
    if errors and any(isinstance(error, dict) and "detail" in error for error in errors):
        detail = str(errors[0]["detail"])
        status_code = int(errors[0]["status"])

    response = {
        "status": status_code,
        "detail": detail,
    }

    if context.get("request").method in ["PUT", "PATCH", "DELETE"]:
        response["instance"] = context.get("request").path

    return response
