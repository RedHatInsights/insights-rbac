#
# Copyright 2020 Red Hat, Inc.
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

"""View for internal tenant management."""
import json
import logging
import uuid
from contextlib import contextmanager

import grpc
import requests
from core.utils import destructive_ok
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.db import connection, transaction
from django.db.migrations.recorder import MigrationRecorder
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.html import escape
from django.views.decorators.http import require_http_methods
from feature_flags import FEATURE_FLAGS
from google.protobuf import json_format
from grpc import RpcError
from internal.errors import SentryDiagnosticError, UserNotFoundError
from internal.jwt_utils import JWTManager, JWTProvider
from internal.utils import (
    delete_bindings,
    get_or_create_ungrouped_workspace,
    validate_inventory_input,
    validate_relations_input,
)
from kessel.inventory.v1beta2 import (
    check_request_pb2,
    reporter_reference_pb2,
    resource_reference_pb2,
    subject_reference_pb2,
)
from kessel.inventory.v1beta2 import inventory_service_pb2_grpc
from kessel.relations.v1beta1 import check_pb2, lookup_pb2, relation_tuples_pb2
from kessel.relations.v1beta1 import check_pb2_grpc, lookup_pb2_grpc, relation_tuples_pb2_grpc
from kessel.relations.v1beta1 import common_pb2
from management.cache import JWTCache, TenantCache
from management.models import BindingMapping, Group, Permission, Principal, ResourceDefinition, Role
from management.principal.proxy import (
    API_TOKEN_HEADER,
    CLIENT_ID_HEADER,
    USER_ENV_HEADER,
)
from management.principal.proxy import PrincipalProxy
from management.principal.proxy import (
    bop_request_status_count,
    bop_request_time_tracking,
)
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType
from management.role.definer import delete_permission
from management.role.model import Access
from management.role.serializer import BindingMappingSerializer
from management.tasks import (
    migrate_data_in_worker,
    run_migrations_in_worker,
    run_ocm_performance_in_worker,
    run_seeds_in_worker,
    run_sync_schemas_in_worker,
)
from management.tenant_service.v2 import V2TenantBootstrapService
from management.utils import (
    get_principal,
    groups_for_principal,
)
from management.workspace.model import Workspace
from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspaceHandler
from management.workspace.serializer import WorkspaceSerializer
from rest_framework import status

from api.common.pagination import StandardResultsSetPagination, WSGIRequestResultsSetPagination
from api.cross_access.model import CrossAccountRequest, RequestsRoles
from api.models import Tenant, User
from api.tasks import (
    cross_account_cleanup,
    populate_tenant_account_id_in_worker,
    run_migration_resource_deletion,
    run_reset_imported_tenants,
)
from api.utils import RESOURCE_MODEL_MAPPING, get_resources

logger = logging.getLogger(__name__)
TENANTS = TenantCache()
PROXY = PrincipalProxy()
jwt_cache = JWTCache()
jwt_provider = JWTProvider()
jwt_manager = JWTManager(jwt_provider, jwt_cache)


@contextmanager
def create_client_channel(addr):
    """Create secure channel for grpc requests."""
    secure_channel = grpc.insecure_channel(addr)
    yield secure_channel


def tenant_is_modified(tenant_name=None, org_id=None):
    """Determine whether or not the tenant is modified."""
    # we need to check if the schema exists because if we don't, and it doesn't exist,
    # the search_path on the query will fall back to using the public schema, in
    # which case there will be custom groups/roles, and we won't be able to properly
    # prune the tenant which has been created without a valid schema
    tenant = get_object_or_404(Tenant, org_id=org_id)

    return (Role.objects.filter(system=False, tenant=tenant).count() != 0) or (
        Group.objects.filter(system=False, tenant=tenant).count() != 0
    )


def tenant_is_unmodified(tenant_name=None, org_id=None):
    """Determine whether or not the tenant is unmodified."""
    return not tenant_is_modified(tenant_name=tenant_name, org_id=org_id)


def list_unmodified_tenants(request):
    """List unmodified tenants.

    GET /_private/api/tenant/unmodified/?limit=<limit>&offset=<offset>
    """
    logger.info(f"Unmodified tenants requested by: {request.user.username}")
    limit = int(request.GET.get("limit", 0))
    offset = int(request.GET.get("offset", 0))

    if limit:
        tenant_qs = Tenant.objects.filter(ready=True).exclude(tenant_name="public")[
            offset : (limit + offset)  # noqa: E203
        ]
    else:
        tenant_qs = Tenant.objects.filter(ready=True).exclude(tenant_name="public")
    to_return = []
    for tenant_obj in tenant_qs:
        if tenant_is_unmodified(tenant_name=tenant_obj.tenant_name, org_id=tenant_obj.org_id):
            to_return.append(tenant_obj.org_id)
    payload = {
        "unmodified_tenants": to_return,
        "unmodified_tenants_count": len(to_return),
        "total_tenants_count": tenant_qs.count(),
    }
    return HttpResponse(json.dumps(payload), content_type="application/json")


def list_tenants(request):
    """List tenant details.

    GET /_private/api/tenant/?ready=<true|false>&limit=<limit>&offset=<offset>
    """
    limit = int(request.GET.get("limit", 0))
    offset = int(request.GET.get("offset", 0))
    ready = request.GET.get("ready")
    tenant_qs = Tenant.objects.exclude(tenant_name="public").values("id", "tenant_name", "account_id", "org_id")

    if ready == "true":
        tenant_qs = tenant_qs.filter(ready=True)
    if ready == "false":
        tenant_qs = tenant_qs.filter(ready=False)
    if limit:
        tenant_qs = tenant_qs[offset : (limit + offset)]  # noqa: E203

    ready_tenants = tenant_qs.filter(ready=True)
    not_ready_tenants = tenant_qs.filter(ready=False)
    tenants_without_account_id = tenant_qs.filter(account_id__isnull=True)

    payload = {
        "ready_tenants": list(ready_tenants),
        "ready_tenants_count": len(ready_tenants),
        "not_ready_tenants": list(not_ready_tenants),
        "not_ready_tenants_count": len(not_ready_tenants),
        "tenants_without_account_id": list(tenants_without_account_id),
        "tenants_without_account_id_count": len(tenants_without_account_id),
        "total_tenants_count": tenant_qs.count(),
    }
    return HttpResponse(json.dumps(payload), content_type="application/json")


def tenant_view(request, org_id):
    """View method for internal tenant requests.

    DELETE /_private/api/tenant/<org_id>/
    """
    logger.info(f"Tenant view: {request.method} {request.user.username}")
    if request.method == "DELETE":
        if not destructive_ok("api"):
            return HttpResponse("Destructive operations disallowed.", status=400)

        tenant_obj = get_object_or_404(Tenant, org_id=org_id)
        with transaction.atomic():
            if tenant_is_unmodified(tenant_name=tenant_obj.tenant_name, org_id=org_id):
                logger.warning(f"Deleting tenant {org_id}. Requested by {request.user.username}")
                TENANTS.delete_tenant(org_id)
                tenant_obj.delete()
                return HttpResponse(status=204)
            else:
                return HttpResponse("Tenant cannot be deleted.", status=400)
    return HttpResponse('Invalid method, only "DELETE" is allowed.', status=405)


def run_migrations(request):
    """View method for running migrations.

    POST /_private/api/migrations/run/
    """
    if request.method == "POST":
        logger.info(f"Running migrations: {request.method} {request.user.username}")
        run_migrations_in_worker.delay()
        return HttpResponse("Migrations are running in a background worker.", status=202)
    return HttpResponse('Invalid method, only "POST" is allowed.', status=405)


def migration_progress(request):
    """View method for checking migration progress.

    GET /_private/api/migrations/progress/?migration_name=<migration_name>&limit=<limit>&offset=<offset>
    """
    if request.method == "GET":
        limit = int(request.GET.get("limit", 0))
        offset = int(request.GET.get("offset", 0))
        migration_name = request.GET.get("migration_name")
        app_name = request.GET.get("app", "management")
        if not migration_name:
            return HttpResponse(
                "Please specify a migration name in the `?migration_name=` param.",
                status=400,
            )
        tenants_completed_count = 0
        incomplete_tenants = []

        if limit:
            tenant_qs = Tenant.objects.exclude(tenant_name="public")[offset : (limit + offset)]  # noqa: E203
        else:
            tenant_qs = Tenant.objects.exclude(tenant_name="public")
        tenant_count = tenant_qs.count()
        for tenant in list(tenant_qs):
            migrations_have_run = MigrationRecorder.Migration.objects.filter(
                name=migration_name, app=app_name
            ).exists()
            if migrations_have_run:
                tenants_completed_count += 1
            else:
                incomplete_tenants.append(tenant.org_id)
        payload = {
            "migration_name": migration_name,
            "app_name": app_name,
            "tenants_completed_count": tenants_completed_count,
            "total_tenants_count": tenant_count,
            "incomplete_tenants": incomplete_tenants,
            "percent_completed": int((tenants_completed_count / tenant_count) * 100),
        }

        return HttpResponse(json.dumps(payload), content_type="application/json")
    return HttpResponse('Invalid method, only "GET" is allowed.', status=405)


def sync_schemas(request):
    """View method for syncing public and tenant schemas.

    POST /_private/api/utils/sync_schemas/
    """
    if request.method == "POST":
        args = {}
        schema_list_param = request.GET.get("schemas")
        if schema_list_param:
            schema_list = schema_list_param.split(",")
            args = {"schema_list": schema_list}
        msg = "Running schema sync in background worker."
        logger.info(msg)
        run_sync_schemas_in_worker.delay(args)
        return HttpResponse(msg, status=202)

    return HttpResponse('Invalid method, only "POST" is allowed.', status=405)


@bop_request_time_tracking.time()
def get_org_admin(request, org_or_account):
    """Get the org admin for an account.

    GET /_private/api/utils/get_org_admin/{org_or_account}/?type=account_id,org_id
    """
    default_limit = StandardResultsSetPagination.default_limit
    request_path = request.path
    try:
        limit = int(request.GET.get("limit", default_limit))
        offset = int(request.GET.get("offset", 0))
    except ValueError:
        error = {
            "detail": "Values for limit and offset must be positive numbers.",
            "source": "get_org_admin",
            "status": str(status.HTTP_400_BAD_REQUEST),
        }
        errors = {"errors": [error]}
        return HttpResponse(errors, status=status.HTTP_400_BAD_REQUEST)

    previous_offset = 0
    if offset - limit > 0:
        previous_offset = offset - limit
    if request.method == "GET":
        option_key = "type"
        valid_values = ["account_id", "org_id"]
        api_type_param = request.GET.get(option_key)
        if not api_type_param:
            return HttpResponse(
                f'Invalid request, must supply the "{option_key}" query parameter; Valid values: {valid_values}.',
                status=400,
            )
        if api_type_param == "account_id":
            path = f"/v2/accounts/{org_or_account}/users?admin_only=true"
        elif api_type_param == "org_id":
            path = f"/v3/accounts/{org_or_account}/users?admin_only=true"
        else:
            return HttpResponse(f'Valid options for "{option_key}": {valid_values}.', status=400)

        url = "{}://{}:{}{}{}".format(PROXY.protocol, PROXY.host, PROXY.port, PROXY.path, path)
        try:
            headers = {
                USER_ENV_HEADER: PROXY.user_env,
                CLIENT_ID_HEADER: PROXY.client_id,
                API_TOKEN_HEADER: PROXY.api_token,
            }
            params = PROXY._create_params(limit=limit, offset=offset)
            kwargs = {"headers": headers, "params": params, "verify": PROXY.ssl_verify}
            if PROXY.source_cert:
                kwargs["verify"] = PROXY.client_cert_path
            response = requests.get(url, **kwargs)
            resp = {"status_code": response.status_code}
            data = response.json()
            resp["data"] = {
                "userCount": data.get("userCount"),
                "users": data.get("users"),
            }
        except requests.exceptions.ConnectionError as conn:
            bop_request_status_count.labels(method="GET", status=500).inc()
            return HttpResponse(f"Unable to connect for URL {url} with error: {conn}", status=500)
        if response.status_code == status.HTTP_200_OK:
            response_data = {}
            data = resp.get("data", [])
            if isinstance(data, dict):
                count = data.get("userCount")
                data = data.get("users")
            elif isinstance(data, list):
                count = len(data)
            else:
                count = None
            response_data["meta"] = {"count": count}
            response_data["links"] = {
                "first": f"{request_path}?type={api_type_param}&limit={limit}&offset=0",
                "next": f"{request_path}?type={api_type_param}&limit={limit}&offset={offset + limit}",
                "previous": f"{request_path}?type={api_type_param}&limit={limit}&offset={previous_offset}",
                "last": f"{request_path}?type={api_type_param}&limit={limit}&offset=0",
            }
            if count and int(count) > limit:
                response_data["links"][
                    "last"
                ] = f"{request_path}?type={api_type_param}&limit={limit}&offset={count - limit}"
            response_data["data"] = data
            bop_request_status_count.labels(method=request.method, status=200).inc()
            return HttpResponse(json.dumps(response_data), status=resp.get("status_code"))
        else:
            bop_request_status_count.labels(method=request.method, status=response.status_code).inc()
            response_data = response.json()
            return HttpResponse(json.dumps(response_data), status=response.status_code)

    return HttpResponse('Invalid method, only "GET" is allowed.', status=405)


def user_lookup(request):
    """Get all groups, roles, and permissions for a provided user via username or email.

    If both params are provided, email is ignored and username is used.

    GET /_private/api/utils/user_lookup/?username=foo&email=bar@redhat.com
    """
    if request.method != "GET":
        return handle_error("Invalid http method - only 'GET' is allowed", 405)

    username = request.GET.get("username")
    email = request.GET.get("email")

    try:
        validate_user_lookup_input(username, email)
    except ValueError as err:
        return handle_error(f"Invalid request input - {err}", 400)

    try:
        user = get_user_from_bop(username, email)
    except UserNotFoundError as err:
        return handle_error(f"Not found - {err}", 404)
    except Exception as err:
        return handle_error(f"Internal error - couldn't get user from bop: {err}", 500)

    username = user["username"]
    user_org_id = user["org_id"]

    result = {
        "username": username,
        "email_address": user["email"],
    }

    try:
        user_tenant = Tenant.objects.get(org_id=user_org_id)
        logger.debug("queried rbac db for tenant: '%s' based on org_id: '%s'", user_tenant, user_org_id)
    except Exception as err:
        logger.error(f"error querying for tenant with org_id: '{user_org_id}' in rbac, err: {err}")
        return handle_error(f"Internal error - failed to query rbac for tenant with org_id: '{user_org_id}'", 500)

    try:
        principal = get_principal(username, request, verify_principal=False, from_query=False, user_tenant=user_tenant)
    except Exception as err:
        logger.error(f"error querying for principal with username: '{username}' in rbac, err: {err}")
        return handle_error(f"Internal error - failed to query rbac for user: '{username}'", 500)

    groups = groups_for_principal(principal, user_tenant, is_org_admin=user["is_org_admin"])

    user_groups = []
    for group in groups:
        roles = group.roles()
        user_roles = []
        for role in roles:
            accesses = Access.objects.filter(role=role)

            permissions = []
            for access in accesses:
                permission = access.permission
                permissions.append(f"{permission.application} | {permission.resource_type} | {permission.verb}")

            user_roles.append(
                {
                    "name": role.name,
                    "display_name": role.display_name,
                    "description": role.description if role.description else "",
                    "permissions": permissions,
                }
            )

        user_groups.append(
            {
                "name": group.name,
                "description": group.description if group.description else "",
                "roles": user_roles,
            }
        )

    result["groups"] = user_groups

    return HttpResponse(json.dumps(result, cls=DjangoJSONEncoder), content_type="application/json", status=200)


def validate_user_lookup_input(username, email):
    """Validate input from user_lookup endpoint."""
    if not username and not email:
        raise ValueError("you must provide either 'email' or 'username' as query params")

    if username and username.isspace():
        raise ValueError("username contains only whitespace")

    if not username and email.isspace():
        raise ValueError("email contains only whitespace")


def get_user_from_bop(username, email):
    """Retrieve user from bop via username or email."""
    principal = ""
    query_by = ""

    if username:
        principal = username
        query_by = "principal"
    elif email and not username:
        principal = email
        query_by = "email"
    else:
        raise Exception("must provide username or email to query bop for user")

    query_options = {"query_by": query_by, "include_permissions": True}
    logger.debug(f"querying bop for user with options: '{query_options}' and principal: '{principal}'")

    resp = PROXY.request_filtered_principals(principals=[principal], limit=1, offset=0, options=query_options)

    if isinstance(resp, dict) and "errors" in resp:
        status = resp.get("status_code")
        err = resp.get("errors")
        logger.error(
            f"Unexpected error when querying bop for user '{query_by}={principal}', status: '{status}', response: {err}"
        )
        raise Exception(f"unexpected status: '{status}' returned from bop")

    users = resp["data"]

    if len(users) == 0:
        raise UserNotFoundError(f"user with '{query_by}={principal}' not found in bop")

    user = users[0]

    if ("username" not in user) or (not user["username"]) or (user["username"].isspace()):
        logger.error(
            f"""invalid data for user '{query_by}={principal}':
             user found in bop but does not contain required 'username' field"""
        )
        raise Exception(
            f"invalid user data for user '{query_by}={principal}': user found in bop but no username exists"
        )

    if "is_org_admin" not in user:
        user["is_org_admin"] = False
        logger.warning(
            f"""invalid data for user '{query_by}={principal}':
             user found in bop but does not contain required 'is_org_admin' field"""
        )

    if "org_id" not in user:
        logger.error(
            f"""invalid data for user '{query_by}={principal}':
             user found in bop but does not contain required 'org_id' field"""
        )
        raise Exception(f"invalid user data for user '{query_by}={principal}': user found in bop but no org_id exists")

    logger.debug(f"successfully queried bop for user: '{user}' with queryBy: '{query_by}'")

    return user


def run_seeds(request):
    """View method for running seeds.

    POST /_private/api/seeds/run/?seed_types=permissions,roles,groups
    """
    if request.method == "POST":
        args = {}
        option_key = "seed_types"
        valid_values = ["permissions", "roles", "groups"]
        seed_types_param = request.GET.get(option_key)
        if seed_types_param:
            seed_types = seed_types_param.split(",")
            if not all([value in valid_values for value in seed_types]):
                return HttpResponse(f'Valid options for "{option_key}": {valid_values}.', status=400)
            args = {type: True for type in seed_types}
        logger.info(f"Running seeds: {request.method} {request.user.username}")
        run_seeds_in_worker.delay(args)
        return HttpResponse("Seeds are running in a background worker.", status=202)
    return HttpResponse('Invalid method, only "POST" is allowed.', status=405)


def car_expiry(request):
    """View method for running cross-account request expiry.

    POST /_private/api/cars/expire/
    """
    if request.method == "POST":
        logger.info("Running cross-account request expiration check.")
        cross_account_cleanup.delay()
        return HttpResponse("Expiry checks are running in a background worker.", status=202)
    return HttpResponse('Invalid method, only "POST" is allowed.', status=405)


def cars_clean(request):
    """View or update cross-account request associated with custom roles.

    GET or POST /_private/api/cars/clean/
    """
    if request.method not in ("GET", "POST"):
        return HttpResponse('Invalid method, only "GET" and "POST" are allowed.', status=405)
    if request.method == "POST" and not destructive_ok("api"):
        return HttpResponse("Destructive operations disallowed.", status=400)

    with transaction.atomic():
        request_roles = RequestsRoles.objects.filter(role__system=False).prefetch_related(
            "role", "cross_account_request"
        )
        if request.method == "GET":
            result = {
                str(request_role.cross_account_request.request_id): (
                    request_role.role.id,
                    request_role.role.display_name,
                )
                for request_role in request_roles
            }
            return HttpResponse(json.dumps(result), status=200)
        else:
            logger.info("Cleaning up cars.")
            request_roles.delete()
            return HttpResponse("Cars cleaned up.", status=200)


def set_tenant_ready(request):
    """View/set Tenant with ready flag true.

    GET /_private/api/utils/set_tenant_ready/
    POST /_private/api/utils/set_tenant_ready/?max_expected=1234
    """
    tenant_qs = Tenant.objects.exclude(tenant_name="public").filter(ready=False)
    if request.method == "GET":
        tenant_count = tenant_qs.count()
        return HttpResponse(f"Total of {tenant_count} tenants not set to be ready.", status=200)

    if request.method == "POST":
        if not destructive_ok("api"):
            return HttpResponse("Destructive operations disallowed.", status=400)
        logger.info("Setting flag ready to true for tenants.")
        max_expected = request.GET.get("max_expected")
        if not max_expected:
            return HttpResponse("Please specify a max_expected value.", status=400)
        with transaction.atomic():
            prev_count = tenant_qs.count()
            if prev_count > int(max_expected):
                return HttpResponse(
                    f"Total of {prev_count} tenants exceeds max_expected of {max_expected}.",
                    status=400,
                )
            tenant_qs.update(ready=True)
            return HttpResponse(
                f"Total of {prev_count} tenants has been updated. "
                f"{tenant_qs.count()} tenant with ready flag equal to false.",
                status=200,
            )
    return HttpResponse('Invalid method, only "POST" is allowed.', status=405)


def populate_tenant_account_id(request):
    """View method for populating Tenant#account_id values.

    POST /_private/api/utils/populate_tenant_account_id/
    """
    if request.method == "POST":
        logger.info("Setting account_id on all Tenant objects.")
        populate_tenant_account_id_in_worker.delay()
        return HttpResponse(
            "Tenant objects account_id values being updated in background worker.",
            status=200,
        )
    return HttpResponse('Invalid method, only "POST" is allowed.', status=405)


def invalid_default_admin_groups(request):
    """View method for querying/removing invalid default admin groups.

    GET /_private/api/utils/invalid_default_admin_groups/
    DELETE /_private/api/utils/invalid_default_admin_groups/
    """
    logger.info(f"Invalid default admin groups: {request.method} {request.user.username}")
    public_tenant = Tenant.objects.get(tenant_name="public")
    invalid_default_admin_groups_list = Group.objects.filter(
        admin_default=True, system=False, platform_default=False
    ).exclude(tenant=public_tenant)

    if request.method == "GET":
        payload = {
            "invalid_default_admin_groups": list(
                invalid_default_admin_groups_list.values(
                    "name", "admin_default", "system", "platform_default", "tenant"
                )
            ),
            "invalid_default_admin_groups_count": invalid_default_admin_groups_list.count(),
        }
        return HttpResponse(json.dumps(payload), content_type="application/json")
    if request.method == "DELETE":
        if not destructive_ok("api"):
            return HttpResponse("Destructive operations disallowed.", status=400)
        invalid_default_admin_groups_list.delete()
        return HttpResponse(status=204)
    return HttpResponse('Invalid method, only "DELETE" and "GET" are allowed.', status=405)


def role_removal(request):
    """View method for internal role removal requests.

    DELETE /_private/api/utils/role/
    """
    logger.info(f"Role removal: {request.method} {request.user.username}")
    if request.method == "DELETE":
        if not destructive_ok("api"):
            return HttpResponse("Destructive operations disallowed.", status=400)

        role_name = request.GET.get("name")
        if not role_name:
            return HttpResponse(
                'Invalid request, must supply the "name" query parameter.',
                status=400,
            )
        role_name = escape(role_name)
        # Add tenant public to prevent deletion of custom roles
        role_obj = get_object_or_404(Role, name=role_name, tenant=Tenant.objects.get(tenant_name="public"))
        with transaction.atomic():
            try:
                logger.warning(f"Deleting role '{role_name}'. Requested by '{request.user.username}'")
                role_obj.delete()
                return HttpResponse(f"Role '{role_name}' deleted.", status=204)
            except Exception:
                return HttpResponse("Role cannot be deleted.", status=400)
    return HttpResponse('Invalid method, only "DELETE" is allowed.', status=405)


def permission_removal(request):
    """View method for internal permission removal requests.

    DELETE /_private/api/utils/permission/
    """
    logger.info(f"Permission removal: {request.method} {request.user.username}")
    if request.method == "DELETE":
        if not destructive_ok("api"):
            return HttpResponse("Destructive operations disallowed.", status=400)

        permission = request.GET.get("permission")
        if not permission:
            return HttpResponse(
                'Invalid request, must supply the "permission" query parameter.',
                status=400,
            )

        permission = escape(permission)
        permission_obj = get_object_or_404(Permission, permission=permission)
        with transaction.atomic():
            try:
                logger.warning(f"Deleting permission '{permission}'. Requested by '{request.user.username}'")
                delete_permission(permission_obj)
                return HttpResponse(f"Permission '{permission}' deleted.", status=204)
            except Exception as e:
                return HttpResponse(f"Permission cannot be deleted. {str(e)}", status=400)
    return HttpResponse('Invalid method, only "DELETE" is allowed.', status=405)


def ocm_performance(request):
    """View method for running OCM performance tests.

    POST /_private/api/utils/ocm_performance/
    """
    if request.method == "POST":
        logger.info("Running OCM performance tests.")
        run_ocm_performance_in_worker.delay()
        return HttpResponse("OCM performance tests are running in a background worker.", status=202)
    return HttpResponse('Invalid method, only "POST" is allowed.', status=405)


def get_param_list(request, param_name, default: list = []):
    """Get a list of params from a request."""
    params = request.GET.get(param_name, [])
    if params:
        return params.split(",")
    else:
        return default


def data_migration(request):
    """View method for running migrations from V1 to V2 spiceDB schema.

    POST /_private/api/utils/data_migration/
    query params:
        exclude_apps: e.g., cost_management,rbac
        orgs: e.g., id_1,id_2
        write_relationships: True, False, outbox
        skip_roles: True or False
    """
    if request.method != "POST":
        return HttpResponse('Invalid method, only "POST" is allowed.', status=405)
    logger.info("Running V1 data migration.")

    args = {
        "exclude_apps": get_param_list(request, "exclude_apps", default=settings.V2_MIGRATION_APP_EXCLUDE_LIST),
        "orgs": get_param_list(request, "orgs"),
        "write_relationships": request.GET.get("write_relationships", "False"),
        "skip_roles": request.GET.get("skip_roles", "False").lower() == "true",
    }
    migrate_data_in_worker.delay(args)
    return HttpResponse("Data migration from V1 to V2 are running in a background worker.", status=202)


def bootstrap_pending_tenants(request):
    """List tenants which are not bootstrapped.

    GET /_private/api/utils/bootstrap_pending_tenants/
    """
    if request.method != "GET":
        return HttpResponse('Invalid method only "GET" is allowed.', status=405)

    public_tenant = Tenant._get_public_tenant()
    org_ids = list(
        Tenant.objects.filter(tenant_mapping__isnull=True)
        .exclude(id=public_tenant.id)
        .exclude(org_id__isnull=True)
        .values_list("org_id", flat=True)
    )

    response = {"org_ids": org_ids}

    return JsonResponse(response, content_type="application/json", status=200)


def fetch_replication_data(request):
    """
    Handle a GET request to fetch PostgreSQL replication-related data.

    This function executes multiple queries to retrieve information about:
    - Replication slots
    - Publications
    - Publication tables
    - Write-Ahead Log (WAL) LSN status for Debezium

    Returns:
        JsonResponse: A JSON object containing query results for each key.
        If an error occurs during query execution, returns a JSON response with the error message.
    """
    if request.method != "GET":
        return HttpResponse('Invalid method, only "GET" is allowed.', status=405)

    show_beta_feature = FEATURE_FLAGS.is_enabled("rbac.beta_feature")
    if show_beta_feature:
        return HttpResponse("rbac.show_beta_feature works.", status=200)

    show_alpha_feature = FEATURE_FLAGS.is_enabled("rbac.alpha_feature", {"orgId": 1000})
    if show_alpha_feature:
        return HttpResponse("rbac.alpha_feature works.", status=200)

    wal_lsn_query = """
                    SELECT pg_current_wal_lsn(), confirmed_flush_lsn
                    FROM pg_replication_slots
                    WHERE slot_name = 'debezium';
                    """
    queries = {
        "replication_slots": "SELECT slot_name, slot_type FROM pg_replication_slots;",
        "publications": "SELECT oid, pubname FROM pg_publication;",
        "publication_tables": "SELECT pubname, tablename FROM pg_publication_tables;",
        "wal_lsn": wal_lsn_query,
    }

    results = {}

    try:
        with connection.cursor() as cursor:
            for key, query in queries.items():
                cursor.execute(query)
                results[key] = cursor.fetchall()
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse(results, safe=False)


def bootstrap_tenant(request):
    """View method for bootstrapping a tenant.

    POST /_private/api/utils/bootstrap_tenant/?org_id=12345&force=false

    org_id:
        (required) The org_id of the Tenant to bootstrap.

    force:
        Whether or not to force replication to happen, even if the Tenant is already bootstrapped.
        Cannot be 'true' if replication is on, due to inconsistency risk.
    """
    if request.method != "POST":
        return HttpResponse('Invalid method, only "POST" is allowed.', status=405)
    logger.info("Running bootstrap tenant.")

    if not request.body:
        return HttpResponse('Invalid request, must supply the "org_ids" in body.', status=400)

    org_ids_data = json.loads(request.body.decode("utf-8").replace("'", '"'))
    force = request.GET.get("force", "false").lower() == "true"
    if "org_ids" not in org_ids_data or len(org_ids_data["org_ids"]) == 0:
        return HttpResponse(
            'Invalid request: the "org_ids" array in the body must contain at least one org_id', status=400
        )
    org_ids = org_ids_data["org_ids"]
    if force and settings.REPLICATION_TO_RELATION_ENABLED:
        return HttpResponse(
            "Forcing replication is not allowed when replication is on, "
            "due to race condition with default group customization.",
            status=400,
        )
    with transaction.atomic():
        bootstrap_service = V2TenantBootstrapService(OutboxReplicator())
        for org_id in org_ids:
            tenant = get_object_or_404(Tenant, org_id=org_id)
            bootstrap_service.bootstrap_tenant(tenant, force=force)
    return HttpResponse(f"Bootstrapping tenants with org_ids {org_ids} were finished.", status=200)


def list_or_delete_bindings_for_role(request, role_uuid):
    """View method for listing bindings for a role.

    GET or DELETE /_private/api/utils/bindings/?role__is_system=True
    """
    if request.method not in ["GET", "DELETE"]:
        return HttpResponse('Invalid method, only "GET" or "DELETE" is allowed.', status=405)
    if not role_uuid:
        return HttpResponse(
            'Invalid request, must supply the "role_uuid" query parameter.',
            status=400,
        )
    role = get_object_or_404(Role, uuid=role_uuid)
    bindings = role.binding_mappings.all()
    if request.GET:
        filter_args = {}
        for key, value in request.GET.items():
            if value.lower() == "true":
                value = True
            elif value.lower() == "false":
                value = False
            filter_args.update({key: value})
        bindings = bindings.filter(**filter_args)
    if request.method == "GET":
        serializer = BindingMappingSerializer(bindings, many=True)
        result = serializer.data or []
        return HttpResponse(json.dumps(result), content_type="application/json", status=200)
    else:
        info = delete_bindings(bindings)
        return HttpResponse(json.dumps(info), status=200)


def clean_binding_mapping(request, binding_id):
    """Clean bindingmapping for a role, delete not associated role anymore.

    POST /_private/api/utils/bindings/<binding_id>/clean
    Params:
        field=users or groups
    """
    if not destructive_ok("api"):
        return HttpResponse("Destructive operations disallowed.", status=400)
    if request.method != "POST":
        return HttpResponse('Invalid method, only "POST" is allowed.', status=405)
    field = request.GET.get("field")
    if not field or field not in ("users", "groups"):
        return HttpResponse(
            'Invalid request, must supply the "users" or "groups" in field.',
            status=400,
        )

    replicator = OutboxReplicator()
    try:
        with transaction.atomic():
            mapping = (
                BindingMapping.objects.select_for_update()
                .filter(
                    id=binding_id,
                )
                .get()
            )
            if field == "users":
                relations_to_remove = []
                # Check if the user should be removed
                if (
                    CrossAccountRequest.objects.filter(user_id__in=mapping.mappings["users"])
                    .filter(roles__id=mapping.role.id)
                    .filter(status="approved")
                    .exists()
                ):
                    raise Exception(
                        f"User(s) {mapping.mappings['users']} are still related to approved cross account requests."
                    )
                # After migration, if it is still old format with duplication, means
                # it only binds with expired cars, which we can remove
                mapping.update_data_format_for_user(relations_to_remove)
                if relations_to_remove:
                    replicator.replicate(
                        ReplicationEvent(
                            event_type=ReplicationEventType.EXPIRE_CROSS_ACCOUNT_REQUEST,
                            info={
                                "users": mapping.mappings["users"],
                            },
                            partition_key=PartitionKey.byEnvironment(),
                            remove=relations_to_remove,
                            add=[],
                        ),
                    )
            else:
                relations_to_remove = []
                if not mapping.role.system:
                    raise Exception("Groups can only be cleaned for system roles")
                # Get the list of group UUIDs from the mapping
                group_uuids = mapping.mappings.get("groups", [])

                # Get existing groups from the database
                existing_groups = {
                    str(group_uuid)
                    for group_uuid in Group.objects.filter(uuid__in=group_uuids).values_list("uuid", flat=True)
                }

                # Find missing groups
                missing_groups = set(group_uuids) - existing_groups
                if not missing_groups:
                    raise Exception("No groups to clean")
                for group in missing_groups:
                    removal = mapping.unassign_group(group)
                    if removal is not None:
                        relations_to_remove.append(removal)
                if relations_to_remove:
                    replicator.replicate(
                        ReplicationEvent(
                            event_type=ReplicationEventType.MIGRATE_TENANT_GROUPS,
                            info={
                                "groups": missing_groups,
                            },
                            partition_key=PartitionKey.byEnvironment(),
                            remove=relations_to_remove,
                            add=[],
                        ),
                    )
            mapping.save()
        return HttpResponse(f"Binding mapping {json.dumps(mapping.mappings)} cleaned.", status=200)
    except Exception as e:
        return handle_error(str(e), 400)


def migration_resources(request):
    """View or delete specific resources related to migration.

    DELETE /_private/api/utils/migration_resources/?resource=xxx&org_id=xxx
    GET /_private/api/utils/migration_resources/?resource=xxx&org_id=xxx&limit=1000
    options of resource: workspace, mapping(tenantmapping), binding(bindingmapping)
    org_id does not work for bindingmapping
    """
    resource = request.GET.get("resource")
    if not resource:
        return HttpResponse(
            'Invalid request, must supply the "resource" query parameter.',
            status=400,
        )
    resource = resource.lower()
    if resource not in RESOURCE_MODEL_MAPPING:
        return HttpResponse(
            f"Invalid request, resource should be in '{RESOURCE_MODEL_MAPPING.keys()}'.",
            status=400,
        )

    org_id = request.GET.get("org_id")

    if request.method == "DELETE":
        if not destructive_ok("api"):
            return HttpResponse("Destructive operations disallowed.", status=400)
        run_migration_resource_deletion.delay({"resource": resource, "org_id": org_id})
        logger.info(f"Deleting resources of type {resource}. Requested by '{request.user.username}'")
        return HttpResponse("Resource deletion is running in a background worker.", status=202)
    elif request.method == "GET":
        resource_objs = get_resources(resource, org_id)
        pg = WSGIRequestResultsSetPagination()
        page = pg.paginate_queryset(resource_objs, request)
        page = [str(record.id) for record in page]
        return HttpResponse(json.dumps(page), content_type="application/json", status=200)
    return HttpResponse(f"Invalid method, {request.method}", status=405)


def reset_imported_tenants(request: HttpRequest) -> HttpResponse:
    """Reset tenants imported via user import job.

    GET /_private/api/utils/reset_imported_tenants/?exclude_id=1&exclude_id=2
    DELETE /_private/api/utils/reset_imported_tenants/?exclude_id=1&exclude_id=2
    """
    # If GET: return a count of how many tenants would be deleted
    # If DELETE: delete the tenants
    # Request should accept a query parameter to exclude certain tenants so we can exclude the ~129
    excluded = request.GET.getlist("exclude_id", [])

    # The default query created with "ready=false" flag otherwise is used query that checks that tenant
    # does not have records in all tables.
    only_ready_false_flag = request.GET.get("only_ready_false_flag", "true").strip().lower() == "true"

    query = "FROM api_tenant WHERE tenant_name <> 'public' "

    if excluded:
        query += "AND id NOT IN %s "

    if only_ready_false_flag:
        query += "AND NOT ready"
    else:
        query += (
            "AND NOT EXISTS (SELECT 1 FROM management_principal WHERE management_principal.tenant_id = api_tenant.id) "
        )
        query += """AND NOT (
                  EXISTS    (SELECT 1
                             FROM   management_tenantmapping
                             WHERE  management_tenantmapping.tenant_id = api_tenant.id)
                  OR EXISTS (SELECT 1
                             FROM   management_access
                             WHERE  management_access.tenant_id = api_tenant.id)
                  OR EXISTS (SELECT 1
                             FROM   management_group
                             WHERE  management_group.tenant_id = api_tenant.id)
                  OR EXISTS (SELECT 1
                             FROM   management_permission
                             WHERE  management_permission.tenant_id = api_tenant.id)
                  OR EXISTS (SELECT 1
                             FROM   management_policy
                             WHERE  management_policy.tenant_id = api_tenant.id)
                  OR EXISTS (SELECT 1
                             FROM   management_resourcedefinition
                             WHERE  management_resourcedefinition.tenant_id =
                            api_tenant.id)
                  OR EXISTS (SELECT 1
                             FROM   management_role
                             WHERE  management_role.tenant_id = api_tenant.id)
                  OR EXISTS (SELECT 1
                             FROM   management_auditlog
                             WHERE  management_auditlog.tenant_id = api_tenant.id)
                  OR EXISTS (SELECT 1
                             FROM   management_workspace
                             WHERE  management_workspace.tenant_id = api_tenant.id)
                  )"""

    try:
        limit = int(request.GET.get("limit", "-1"))
    except ValueError:
        return HttpResponse("Invalid limit parameter, must be an integer.", status=400)

    if limit > 0:
        query += f" LIMIT {limit}"
    elif limit == 0:
        return HttpResponse("Limit is 0, nothing to do", status=200)

    if request.method == "GET":
        with connection.cursor() as cursor:
            if limit > 0:
                cursor.execute("SELECT COUNT(*) FROM (SELECT 1 " + query + ") subquery", (tuple(excluded),))
            else:
                cursor.execute(
                    "SELECT COUNT(*) " + query,
                    (tuple(excluded),),
                )
            count = cursor.fetchone()[0]

        return HttpResponse(f"{count} tenants would be deleted", status=200)

    if request.method == "DELETE":
        if not destructive_ok("api"):
            return HttpResponse("Destructive operations disallowed.", status=400)

        run_reset_imported_tenants.delay({"query": query, "limit": limit, "excluded": excluded})

        return HttpResponse("Tenants deleting in worker.", status=200)

    return HttpResponse("Invalid method", status=405)


ALLOWED_ROLE_UPDATE_ATTRIBUTES = {"system", "platform_default", "admin_default"}


def str_to_bool(value: str) -> bool:
    """Convert string to bool."""
    return value.strip().lower() == "true"


def handle_error(message: str, status_response: int) -> HttpResponse:
    """Return HttpResponse object."""
    return HttpResponse(json.dumps({"error": message}), content_type="application/json", status=status_response)


def get_role_response(role: Role) -> HttpResponse:
    """Return role response in HttpResponse object."""
    response_data = {
        "message": "Role retrieved successfully",
        "role": {
            "uuid": str(role.uuid),
            "name": role.name,
            "system": role.system,
            "admin_default": role.admin_default,
            "platform_default": role.platform_default,
        },
    }
    return HttpResponse(json.dumps(response_data), content_type="application/json", status=200)


def roles(request, uuid: str) -> HttpResponse:
    """Update or get role.

    GET /_private/api/role/uuid-uuid-uuid-uuid/
    PUT /_private/api/role/uuid-uuid-uuid-uuid/
    {
        "system": "true"
    }
    """
    try:
        role = get_object_or_404(Role, uuid=uuid)

        if request.method == "PUT":
            body = json.loads(request.body)

            invalid_keys = set(body.keys()) - ALLOWED_ROLE_UPDATE_ATTRIBUTES
            if invalid_keys:
                return handle_error(f"Invalid attributes: {', '.join(invalid_keys)}", 400)

            if "system" in body:
                role.system = str_to_bool(body["system"])

            if "platform_default" in body:
                role.platform_default = str_to_bool(body["platform_default"])

            if "admin_default" in body:
                role.admin_default = str_to_bool(body["admin_default"])

            role.save()
            return get_role_response(role)

        elif request.method == "GET":
            return get_role_response(role)

        return handle_error("Invalid request method", 405)

    except Exception as e:
        return handle_error(str(e), 500)


def trigger_error(request):
    """Trigger an error to confirm Sentry is working."""
    raise SentryDiagnosticError


def correct_resource_definitions(request):
    """Get/Fix resourceDefinitions with incorrect attributeFilters.

    Attribute filters with lists must use 'in' operation. Those with a single string must use 'equal'

    GET /_private/api/utils/resource_definitions/
        query param 'detail=false' (default) to get resource definitions count
        query param 'detail=true' to get resource definitions objects

    PATCH /_private/api/utils/resource_definitions/
        query param 'id=<resource_definitions_id>' to fix only 1 resource definition
        you can identify 'id' by GET request with 'detail=true' query param
    """
    list_query = """ FROM management_resourcedefinition
                WHERE "attributeFilter"->>'operation' = 'equal'
                AND jsonb_typeof("attributeFilter"->'value') = 'array';"""

    string_query = """ from management_resourcedefinition WHERE "attributeFilter"->>'operation' = 'in'
                AND jsonb_typeof("attributeFilter"->'value') = 'string';"""

    hbi_query = """ from management_resourcedefinition WHERE ("attributeFilter"->>'operation' <> 'in'
                OR jsonb_typeof("attributeFilter"->'value') <> 'array')
                AND "attributeFilter"->>'key' = 'group.id';"""

    operations_query = """FROM management_resourcedefinition WHERE "attributeFilter"->>'operation' != 'in'
                       AND "attributeFilter"->>'operation' != 'equal';"""

    query_params = request.GET

    if request.method == "GET":
        detail = query_params.get("detail") == "true"
        if detail:
            with connection.cursor() as cursor:
                cursor.execute("SELECT *" + list_query)
                list_rows = cursor.fetchall()

                cursor.execute("SELECT *" + string_query)
                string_rows = cursor.fetchall()

                cursor.execute("SELECT *" + hbi_query)
                hbi_rows = cursor.fetchall()

                cursor.execute("SELECT *" + operations_query)
                operation_rows = cursor.fetchall()

                response = [
                    {
                        "id": row[0],
                        "attributeFilter": json.loads(row[1]),
                        "access_id": row[2],
                        "tenant_id": row[3],
                    }
                    for row in list_rows + string_rows + hbi_rows + operation_rows
                ]

            return HttpResponse(json.dumps(response), content_type="application/json", status=200)

        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*)" + list_query)
            count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*)" + string_query)
            count += cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*)" + hbi_query)
            count += cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*)" + operations_query)
            count += cursor.fetchone()[0]

        return HttpResponse(f"{count} resource definitions would be corrected", status=200)

    elif request.method == "PATCH":
        resource_definition_id = query_params.get("id")

        if resource_definition_id:
            resource_definition = get_object_or_404(ResourceDefinition, id=resource_definition_id)
            resource_definition.attributeFilter = normalize_attribute_filter(resource_definition.attributeFilter)
            resource_definition.save()
            return HttpResponse(f"Resource definition id = {resource_definition_id} updated.", status=200)

        count = 0
        with connection.cursor() as cursor:
            cursor.execute("SELECT id " + list_query)
            result = cursor.fetchall()
            for id in result:
                resource_definition = ResourceDefinition.objects.get(id=id[0])
                resource_definition.attributeFilter = normalize_attribute_filter(resource_definition.attributeFilter)
                resource_definition.save()
                count += 1

            cursor.execute("SELECT id " + string_query)
            result = cursor.fetchall()
            for id in result:
                resource_definition = ResourceDefinition.objects.get(id=id[0])
                resource_definition.attributeFilter = normalize_attribute_filter(resource_definition.attributeFilter)
                resource_definition.save()
                count += 1

            cursor.execute("SELECT id " + hbi_query)
            result = cursor.fetchall()
            for id in result:
                resource_definition = ResourceDefinition.objects.get(id=id[0])
                resource_definition.attributeFilter = normalize_hbi_attribute_filter(
                    resource_definition.attributeFilter
                )
                resource_definition.save()
                count += 1

            cursor.execute("SELECT id " + operations_query)
            result = cursor.fetchall()
            for id in result:
                resource_definition = ResourceDefinition.objects.get(id=id[0])
                resource_definition.attributeFilter = normalize_operation_in_attribute_filter(
                    resource_definition.attributeFilter
                )
                resource_definition.save()
                count += 1

        return HttpResponse(f"Updated {count} bad resource definitions", status=200)

    return HttpResponse('Invalid method, only "GET" or "PATCH" are allowed.', status=405)


def normalize_attribute_filter(attribute_filter):
    """For Attribute Filter set valid 'operation' or convert 'value' from string into list."""
    op = attribute_filter.get("operation")
    value = attribute_filter.get("value")
    if op == "equal" and isinstance(value, list):
        attribute_filter["operation"] = "in"
    elif op == "in" and isinstance(value, str):
        if "," in value:
            attribute_filter["value"] = [item.strip() for item in value.split(",")]
        else:
            attribute_filter["operation"] = "equal"
    return attribute_filter


def normalize_hbi_attribute_filter(attribute_filter):
    """Set Attribute Filter 'operation' to 'in' and convert 'value' into list."""
    value = attribute_filter.get("value")
    attribute_filter["operation"] = "in"
    if not isinstance(value, list):
        if isinstance(value, dict):
            if "id" not in value:
                attribute_filter["value"] = [None]
            else:
                attribute_filter["value"] = [value["id"]]
        else:
            attribute_filter["value"] = [value]
    return attribute_filter


def normalize_operation_in_attribute_filter(attribute_filter):
    """Set Attribute Filter invalid 'operation' to valid operation if value type is 'str', 'int' or 'list'."""
    op = attribute_filter.get("operation")
    value = attribute_filter.get("value")
    if op != "equal" and isinstance(value, (str, int)):
        attribute_filter["operation"] = "equal"
    elif op != "in" and isinstance(value, list):
        attribute_filter["operation"] = "in"
    return attribute_filter


def username_lower(request):
    """Update the username for the principal to be lowercase."""
    if request.method not in ["POST", "GET"]:
        return HttpResponse("Invalid request method, only POST/GET are allowed.", status=405)
    if request.method == "POST" and not destructive_ok("api"):
        return HttpResponse("Destructive operations disallowed.", status=400)

    pre_names = []
    updated_names = []
    with transaction.atomic():
        principals = Principal.objects.filter(type="user").filter(username__regex=r"[A-Z]").order_by("username")
        for principal in principals:
            pre_names.append(principal.username)
            principal.username = principal.username.lower()
            updated_names.append(principal.username)
            pre_names.sort()
            updated_names.sort()
        if request.method == "GET":
            return HttpResponse(
                f"Usernames to be updated: {pre_names} to {updated_names}",
                status=200,
            )
        Principal.objects.bulk_update(principals, ["username"])
        return HttpResponse(f"Updated {len(principals)} usernames", status=200)


def principal_removal(request):
    """Get/Delete not active principals.

    GET or DELETE /_private/api/utils/principal/?usernames=a,b,c&user_type=service-account
    """
    logger.info(f"Principal edit or removal: {request.method} {request.user.username}")
    if request.method not in ["DELETE", "GET"]:
        return HttpResponse('Invalid method, only "DELETE" or "GET" is allowed.', status=405)

    if not request.GET.get("usernames"):
        return HttpResponse("Please provided a list of usernames with comma separated.", status=400)
    if not request.GET.get("user_type"):
        return HttpResponse("Please provided a type of principal.", status=400)
    usernames = request.GET.get("usernames").split(",")
    user_type = request.GET.get("user_type")

    principals = Principal.objects.filter(username__in=usernames).filter(type=user_type).prefetch_related("tenant")
    active_users = {}
    if request.GET.get("user_type") == "user":
        resp = PROXY.request_filtered_principals(usernames, org_id=None, options={"return_id": True})

        if isinstance(resp, dict) and "errors" in resp:
            return HttpResponse(resp.get("errors"), status=400)

        active_users = {(principal_data["username"], principal_data["org_id"]) for principal_data in resp["data"]}

    principals_delete = [
        principal for principal in principals if (principal.username, principal.tenant.org_id) not in active_users
    ]

    principal_usernames = [principal.username for principal in principals_delete]

    if request.method == "GET":
        return HttpResponse(
            f"Principals to be deleted: {principal_usernames}",
            status=200,
        )
    if not destructive_ok("api"):
        return HttpResponse("Destructive operations disallowed.", status=400)

    with transaction.atomic():
        bootstrap_service = V2TenantBootstrapService(OutboxReplicator())
        for principal in principals_delete:
            if not principal.user_id:
                principal.delete()
            else:
                user = User()
                user.username = principal.username
                user.org_id = principal.tenant.org_id
                user.is_active = False
                user.user_id = principal.user_id

                bootstrap_service.update_user(user)

        return HttpResponse(f"Users deleted: {principal_usernames}", status=204)


def retrieve_ungrouped_workspace(request):
    """
    GET or create ungrouped workspace for HBI.

    GET /_private/_s2s/workspaces/ungrouped/
    """
    if request.method != "GET":
        return HttpResponse("Invalid request method, only GET is allowed.", status=405)

    org_id = request.user.org_id

    if not org_id:
        return HttpResponse("No org_id found for the user.", status=400)

    try:
        with transaction.atomic():
            tenant = Tenant.objects.get(org_id=org_id)
            ungrouped_hosts = get_or_create_ungrouped_workspace(tenant)
            data = WorkspaceSerializer(ungrouped_hosts).data
            return HttpResponse(json.dumps(data), content_type="application/json", status=201)
    except Exception as e:
        return HttpResponse(str(e), status=500)


def lookup_resource(request):
    """POST to retrieve resource details from relations api."""
    # Parse JSON data from the POST request body
    req_data = json.loads(request.body)
    if not validate_relations_input("lookup_resources", req_data):
        return JsonResponse({"detail": "Invalid request body provided in request to lookup_resources."}, status=500)

    # Request parameters for resource lookup on relations api from post request
    resource_type_name = req_data["resource_type"]["name"]
    resource_type_namespace = req_data["resource_type"]["namespace"]
    resource_subject_name = req_data["subject"]["subject"]["type"]["name"]
    resource_subject_id = req_data["subject"]["subject"]["id"]
    resource_relation = req_data["relation"]
    token = jwt_manager.get_jwt_from_redis()

    try:
        with create_client_channel(settings.RELATION_API_SERVER) as channel:
            stub = lookup_pb2_grpc.KesselLookupServiceStub(channel)

            request_data = lookup_pb2.LookupResourcesRequest(
                resource_type=common_pb2.ObjectType(
                    name=resource_type_name,
                    namespace=resource_type_namespace,
                ),
                relation=resource_relation,
                subject=common_pb2.SubjectReference(
                    subject=common_pb2.ObjectReference(
                        type=common_pb2.ObjectType(namespace=resource_type_namespace, name=resource_subject_name),
                        id=resource_subject_id,
                    ),
                ),
            )
        # Pass JWT token in metadata
        metadata = [("authorization", f"Bearer {token}")]
        responses = stub.LookupResources(request_data, metadata=metadata)

        if responses:
            response_data = []
            for r in responses:
                response_to_dict = json_format.MessageToDict(r)
                response_data.append(response_to_dict)
            json_response = {"resources": response_data}
            return JsonResponse(json_response, status=200)
        return JsonResponse("No resource found", status=204, safe=False)
    except RpcError as e:
        logger.error(f"gRPC error: {str(e)}")
        return JsonResponse({"detail": "Error occurred in gRPC call", "error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return JsonResponse(
            {"detail": "Error occurred in call to lookup resources endpoint", "error": str(e)}, status=500
        )


def read_tuples(request):
    """POST read tuples from relations api."""
    # Parse JSON data from the POST request body
    req_data = json.loads(request.body)

    if not validate_relations_input("read_tuples", req_data):
        return JsonResponse({"detail": "Invalid request body provided in request to read_tuples."}, status=500)

    # Request parameters for read tuples on relations api from post request
    resource_namespace = req_data["filter"]["resource_namespace"]
    resource_type = req_data["filter"]["resource_type"]
    resource_id = req_data["filter"]["resource_id"]
    filter_relation = req_data["filter"]["relation"]
    subject_namespace = req_data["filter"]["subject_filter"]["subject_namespace"]
    subject_type = req_data["filter"]["subject_filter"]["subject_type"]
    subject_id = req_data["filter"]["subject_filter"]["subject_id"]
    subject_relation = req_data.get("filter", {}).get("subject_filter", {}).get("relation") or None
    token = jwt_manager.get_jwt_from_redis()

    try:
        with create_client_channel(settings.RELATION_API_SERVER) as channel:
            stub = relation_tuples_pb2_grpc.KesselTupleServiceStub(channel)

            request_data = relation_tuples_pb2.ReadTuplesRequest(
                filter=relation_tuples_pb2.RelationTupleFilter(
                    resource_namespace=resource_namespace,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    relation=filter_relation,
                    subject_filter=relation_tuples_pb2.SubjectFilter(
                        subject_namespace=subject_namespace,
                        subject_type=subject_type,
                        subject_id=subject_id,
                        relation=subject_relation,
                    ),
                )
            )

        # Pass JWT token in metadata
        metadata = [("authorization", f"Bearer {token}")]
        responses = stub.ReadTuples(request_data, metadata=metadata)

        if responses:
            response_data = []
            for r in responses:
                response_to_dict = json_format.MessageToDict(r)
                response_data.append(response_to_dict)
            json_response = {"tuples": response_data}
            return JsonResponse(json_response, status=200)
        return JsonResponse("No tuples found", status=204, safe=False)
    except RpcError as e:
        logger.error(f"gRPC error: {str(e)}")
        return JsonResponse({"detail": "Error occurred in gRPC call", "error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return JsonResponse({"detail": "Error occurred in call to read tuples endpoint", "error": str(e)}, status=500)


def check_relation(request):
    """POST to check relationship from relations api."""
    # Parse JSON data from the POST request body
    req_data = json.loads(request.body)

    if not validate_relations_input("check_relation", req_data):
        return JsonResponse({"detail": "Invalid request body provided in request to check_relation."}, status=500)

    # Request parameters for resource lookup on relations api from post request
    resource_name = req_data["resource"]["type"]["name"]
    resource_namespace = req_data["resource"]["type"]["namespace"]
    subject_name = req_data["subject"]["subject"]["type"]["name"]
    subject_namespace = req_data["subject"]["subject"]["type"]["namespace"]
    subject_id = req_data["subject"]["subject"]["id"]
    subject_relation = req_data.get("subject", {}).get("relation") or None
    resource_id = req_data["resource"]["id"]
    resource_relation = req_data["relation"]
    token = jwt_manager.get_jwt_from_redis()

    try:
        with create_client_channel(settings.RELATION_API_SERVER) as channel:
            stub = check_pb2_grpc.KesselCheckServiceStub(channel)

            request_data = check_pb2.CheckRequest(
                resource=common_pb2.ObjectReference(
                    type=common_pb2.ObjectType(namespace=resource_namespace, name=resource_name),
                    id=resource_id,
                ),
                relation=resource_relation,
                subject=common_pb2.SubjectReference(
                    relation=subject_relation,
                    subject=common_pb2.ObjectReference(
                        type=common_pb2.ObjectType(namespace=subject_namespace, name=subject_name),
                        id=subject_id,
                    ),
                ),
            )
        # Pass JWT token in metadata
        metadata = [("authorization", f"Bearer {token}")]
        response = stub.Check(request_data, metadata=metadata)

        if response:
            response_to_dict = json_format.MessageToDict(response)
            response_to_dict["allowed"] = response_to_dict["allowed"] != "ALLOWED_FALSE"

            return JsonResponse(response_to_dict, status=200)
        return JsonResponse("No relation found", status=204, safe=False)
    except RpcError as e:
        logger.error(f"gRPC error: {str(e)}")
        return JsonResponse({"detail": "Error occurred in gRPC call", "error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return JsonResponse(
            {"detail": "Error occurred in call to check relation endpoint", "error": str(e)}, status=500
        )


def check_inventory(request):
    """POST to check relationship from inventory api."""
    # Parse JSON data from the POST request body
    req_data = json.loads(request.body)

    if not validate_inventory_input("check", req_data):
        return JsonResponse(
            {"detail": "Invalid request body provided in request to check inventory."}, status=500
        )

    # Request parameters for check relation on inventory api from post request
    resource_id = req_data["resource"]["resource_id"]
    resource_type = req_data["resource"]["resource_type"]
    resource_reporter_type = req_data["resource"]["reporter"]["type"]
    resource_relation = req_data["relation"]
    subject_resource_id = req_data["subject"]["resource"]["resource_id"]
    subject_resource_type = req_data["subject"]["resource"]["resource_type"]
    subject_resource_reporter_type = req_data["subject"]["resource"]["reporter"]["type"]
    token = jwt_manager.get_jwt_from_redis()

    try:
        with create_client_channel(settings.INVENTORY_API_SERVER) as channel:
            stub = inventory_service_pb2_grpc.KesselInventoryServiceStub(channel)

            resource_ref = resource_reference_pb2.ResourceReference(
                resource_id=resource_id,
                resource_type=resource_type,
                reporter=reporter_reference_pb2.ReporterReference(type=resource_reporter_type),
            )

            subject = subject_reference_pb2.SubjectReference(
                resource=resource_reference_pb2.ResourceReference(
                    resource_id=subject_resource_id,
                    resource_type=subject_resource_type,
                    reporter=reporter_reference_pb2.ReporterReference(type=subject_resource_reporter_type),
                )
            )

        request = check_request_pb2.CheckRequest(
            subject=subject,
            relation=resource_relation,
            object=resource_ref,
        )
        # Pass JWT token in metadata
        metadata = [("authorization", f"Bearer {token}")]
        response = stub.Check(request, metadata=metadata)

        if response:
            response_to_dict = json_format.MessageToDict(response)
            response_to_dict["allowed"] = response_to_dict["allowed"] != "ALLOWED_FALSE"

            return JsonResponse(response_to_dict, status=200)
        return JsonResponse("No relation found", status=204, safe=False)
    except RpcError as e:
        logger.error(f"gRPC error: {str(e)}")
        return JsonResponse({"detail": "Error occurred in gRPC call", "error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return JsonResponse(
            {"detail": "Error occurred in call to check relation inventory endpoint", "error": str(e)}, status=500
        )


@require_http_methods(["GET", "DELETE"])
def workspace_removal(request):
    """
    Get or delete standard workspaces.

    GET /_private/api/utils/workspace/
        ?detail=false (default) : return count only
        ?detail=true            : return list of standard workspaces

    DELETE /_private/api/utils/workspace/
        ?id=<workspace_id>                  : delete a single workspace
        (no id)                             : delete all standard workspaces
        ?without_child_only=false (default) : delete all standard workspaces
        ?without_child_only=true            : delete only standard workspaces without children
    """
    query_params = request.GET
    logger.info(f"Workspace list or removal: {request.method} {request.user.username}")

    if request.method == "DELETE" and not destructive_ok("api"):
        return HttpResponse("Destructive operations disallowed.", status=403)

    # GET
    if request.method == "GET":
        if query_params.get("detail") == "true":
            workspaces = Workspace.objects.filter(type=Workspace.Types.STANDARD)
            serialized_ws = WorkspaceSerializer(workspaces, many=True).data
            # Add tenant id into response
            for ws_obj, ws_data in zip(workspaces, serialized_ws):
                ws_data["tenant_id"] = ws_obj.tenant_id
            payload = {"count": len(serialized_ws), "data": serialized_ws}
            return JsonResponse(payload, status=200)

        ws_count = Workspace.objects.filter(type=Workspace.Types.STANDARD).count()
        return HttpResponse(
            f"{ws_count} standard workspace(s) eligible for removal.", content_type="text/plain", status=200
        )

    # DELETE
    # delete 1 standard workspace
    if ws_id := query_params.get("id"):
        try:
            uuid.UUID(str(ws_id))
        except ValueError:
            return HttpResponse("Invalid workspace id format.", content_type="text/plain", status=400)

        if not Workspace.objects.filter(type=Workspace.Types.STANDARD, id=ws_id).first():
            return HttpResponse(
                f"Standard workspace with id='{ws_id}' not found.", content_type="text/plain", status=404
            )

        if ws := Workspace.objects.filter(type=Workspace.Types.STANDARD, id=ws_id, children__isnull=True).first():
            try:
                with transaction.atomic():
                    dual_write_handler = RelationApiDualWriteWorkspaceHandler(
                        ws, ReplicationEventType.DELETE_WORKSPACE
                    )
                    dual_write_handler.replicate_deleted_workspace(skip_ws_events=True)
                    ws.delete()
                logger.info(f"Deleted workspace id='{ws_id}'")
                return HttpResponse(f"Workspace with id='{ws_id}' deleted.", content_type="text/plain", status=200)
            except Exception as e:
                logger.exception(f"Workspace id='{ws_id}' deletion failed: {e}")
                return HttpResponse(str(e), status=500)

        return HttpResponse(
            f"Workspace with id='{ws_id}' cannot be removed because it has child workspace.",
            content_type="text/plain",
            status=400,
        )

    # delete all standard workspaces
    ws_count = Workspace.objects.filter(type=Workspace.Types.STANDARD).count()
    try:
        with transaction.atomic():
            while True:
                workspaces = Workspace.objects.filter(type=Workspace.Types.STANDARD, children__isnull=True)
                ws_without_child_count = workspaces.count()
                if not workspaces:
                    break
                for ws in workspaces:
                    dual_write_handler = RelationApiDualWriteWorkspaceHandler(
                        ws, ReplicationEventType.DELETE_WORKSPACE
                    )
                    dual_write_handler.replicate_deleted_workspace(skip_ws_events=True)
                    ws.delete()
                if query_params.get("without_child_only", "") == "true":
                    return HttpResponse(
                        f"{ws_without_child_count} workspace(s) deleted, "
                        f"another {ws_count - ws_without_child_count} standard workspace(s) exist in database.",
                        content_type="text/plain",
                        status=200,
                    )
        logger.info("All standard workspaces successfully deleted.")
        return HttpResponse(f"{ws_count} workspace(s) deleted.", content_type="text/plain", status=200)
    except Exception as e:
        logger.exception(f"Bulk workspace deletion failed: {e}")
        return HttpResponse(str(e), status=500)
