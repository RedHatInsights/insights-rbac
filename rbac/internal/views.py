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

import requests
from core.utils import destructive_ok
from django.conf import settings
from django.db import transaction
from django.db.migrations.recorder import MigrationRecorder
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from management.cache import TenantCache
from management.models import Group, Permission, Role
from management.principal.proxy import API_TOKEN_HEADER, CLIENT_ID_HEADER, USER_ENV_HEADER
from management.principal.proxy import PrincipalProxy
from management.principal.proxy import bop_request_status_count, bop_request_time_tracking
from management.tasks import (
    run_migrations_in_worker,
    run_ocm_performance_in_worker,
    run_reconcile_tenant_relations_in_worker,
    run_seeds_in_worker,
    run_sync_schemas_in_worker,
)
from rest_framework import status

from api.common.pagination import StandardResultsSetPagination
from api.models import Tenant
from api.tasks import cross_account_cleanup, populate_tenant_account_id_in_worker

logger = logging.getLogger(__name__)
TENANTS = TenantCache()


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
        tenant_qs = Tenant.objects.exclude(tenant_name="public")[offset : (limit + offset)]  # noqa: E203
    else:
        tenant_qs = Tenant.objects.exclude(tenant_name="public")
    to_return = []
    for tenant_obj in tenant_qs:
        if tenant_is_unmodified(tenant_name=tenant_obj.tenant_name, org_id=tenant_obj.org_id):
            if settings.AUTHENTICATE_WITH_ORG_ID:
                to_return.append(tenant_obj.org_id)
            else:
                to_return.append(tenant_obj.tenant_name)
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
        if not destructive_ok():
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
            return HttpResponse("Please specify a migration name in the `?migration_name=` param.", status=400)
        tenants_completed_count = 0
        incomplete_tenants = []

        if limit:
            tenant_qs = Tenant.objects.exclude(tenant_name="public")[offset : (limit + offset)]  # noqa: E203
        else:
            tenant_qs = Tenant.objects.exclude(tenant_name="public")
        tenant_count = tenant_qs.count()
        for idx, tenant in enumerate(list(tenant_qs)):
            migrations_have_run = MigrationRecorder.Migration.objects.filter(
                name=migration_name, app=app_name
            ).exists()
            if migrations_have_run:
                tenants_completed_count += 1
            else:
                if settings.AUTHENTICATE_WITH_ORG_ID:
                    incomplete_tenants.append(tenant.org_id)
                else:
                    incomplete_tenants.append(tenant.tenant_name)
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


def tenant_reconciliation(request):
    """View method for checking/executing tenant reconciliation.

    GET(read-only)|POST(updates enabled) /_private/api/utils/tenant_reconciliation/
    """
    args = {"readonly": True} if request.method == "GET" else {}
    msg = "Running tenant reconciliation in a background worker."

    if request.method in ["GET", "POST"]:
        logger.info(msg)
        run_reconcile_tenant_relations_in_worker.delay(args)
        return HttpResponse(msg, status=202)

    return HttpResponse('Invalid method, only "GET" and "POST" are allowed.', status=405)


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
    PROXY = PrincipalProxy()
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
            resp["data"] = {"userCount": data.get("userCount"), "users": data.get("users")}
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


def populate_tenant_account_id(request):
    """View method for populating Tenant#account_id values.

    POST /_private/api/utils/populate_tenant_account_id/
    """
    if request.method == "POST":
        logger.info("Setting account_id on all Tenant objects.")
        populate_tenant_account_id_in_worker.delay()
        return HttpResponse("Tenant objects account_id values being updated in background worker.", status=200)
    return HttpResponse('Invalid method, only "POST" is allowed.', status=405)


def invalid_default_admin_groups(request):
    """View method for querying/removing invalid default admin groups.

    GET /_private/api/utils/invalid_default_admin_groups/
    DELETE /_private/api/utils/invalid_default_admin_groups/
    """
    logger.info(f"Invalid default admin groups: {request.method} {request.user.username}")
    public_tenant = Tenant.objects.get(tenant_name="public")
    invalid_default_admin_groups = Group.objects.filter(
        admin_default=True, system=False, platform_default=False
    ).exclude(tenant=public_tenant)

    if request.method == "GET":
        payload = {
            "invalid_default_admin_groups": list(
                invalid_default_admin_groups.values("name", "admin_default", "system", "platform_default", "tenant")
            ),
            "invalid_default_admin_groups_count": invalid_default_admin_groups.count(),
        }
        return HttpResponse(json.dumps(payload), content_type="application/json")
    if request.method == "DELETE":
        if not destructive_ok():
            return HttpResponse("Destructive operations disallowed.", status=400)
        invalid_default_admin_groups.delete()
        return HttpResponse(status=204)
    return HttpResponse('Invalid method, only "DELETE" and "GET" are allowed.', status=405)


def role_removal(request, role_uuid):
    """View method for internal role removal requests.

    DELETE /_private/api/utils/roles/<role_uuid>/
    """
    logger.info(f"Role removal: {request.method} {request.user.username}")
    if request.method == "DELETE":
        if not destructive_ok():
            return HttpResponse("Destructive operations disallowed.", status=400)

        role_obj = get_object_or_404(Role, uuid=role_uuid)
        with transaction.atomic():
            try:
                logger.warning(f"Deleting role {role_uuid}. Requested by {request.user.username}")
                role_obj.delete()
                return HttpResponse(status=204)
            except Exception:
                return HttpResponse("Role cannot be deleted.", status=400)
    return HttpResponse('Invalid method, only "DELETE" is allowed.', status=405)


def permission_removal(request):
    """View method for internal permission removal requests.

    DELETE /_private/api/utils/permission/
    """
    logger.info(f"Permission removal: {request.method} {request.user.username}")
    if request.method == "DELETE":
        if not destructive_ok():
            return HttpResponse("Destructive operations disallowed.", status=400)

        permission = request.GET.get("permission")
        if not permission:
            return HttpResponse(
                'Invalid request, must supply the "permission" query parameter.',
                status=400,
            )

        permission_obj = get_object_or_404(Permission, permission=permission)
        with transaction.atomic():
            try:
                logger.warning(f"Deleting permission {permission}. Requested by {request.user.username}")
                permission_obj.delete()
                return HttpResponse(status=204)
            except Exception:
                return HttpResponse("Permission cannot be deleted.", status=400)
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


class SentryDiagnosticError(Exception):
    """Raise this to create an event in Sentry."""

    pass


def trigger_error(request):
    """Trigger an error to confirm Sentry is working."""
    raise SentryDiagnosticError
