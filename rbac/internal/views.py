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
import datetime
import json
import logging

import pytz
from django.conf import settings
from django.db import transaction
from django.db.migrations.recorder import MigrationRecorder
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from management.cache import TenantCache
from management.group.definer import seed_group
from management.models import Group, Role
from management.role.definer import seed_permissions, seed_roles
from management.tasks import (
    run_migrations_in_worker,
    run_reconcile_tenant_relations_in_worker,
    run_seeds_in_worker,
    run_sync_schemas_in_worker,
)
from tenant_schemas.utils import schema_exists, tenant_context

from api.models import Tenant
from api.tasks import cross_account_cleanup


logger = logging.getLogger(__name__)
TENANTS = TenantCache()


def destructive_ok():
    """Determine if it's ok to run destructive operations."""
    now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
    return now < settings.INTERNAL_DESTRUCTIVE_API_OK_UNTIL


def tenant_is_modified(schema_name):
    """Determine whether or not the tenant is modified."""
    # we need to check if the schema exists because if we don't, and it doesn't exist,
    # the search_path on the query will fall back to using the public schema, in
    # which case there will be custom groups/roles, and we won't be able to propertly
    # prune the tenant which has been created without a valid schema
    if not schema_exists(schema_name):
        return False

    return (Role.objects.filter(system=True).count() != Role.objects.count()) or (
        Group.objects.filter(system=True).count() != Group.objects.count()
    )


def tenant_is_unmodified(schema_name):
    """Determine whether or not the tenant is unmodified."""
    return not tenant_is_modified(schema_name)


def list_unmodified_tenants(request):
    """List unmodified tenants.

    GET /_private/api/tenant/unmodified/?limit=<limit>&offset=<offset>
    """
    logger.info(f"Unmodified tenants requested by: {request.user.username}")
    limit = int(request.GET.get("limit", 0))
    offset = int(request.GET.get("offset", 0))

    if limit:
        tenant_qs = Tenant.objects.exclude(schema_name="public")[offset : (limit + offset)]  # noqa: E203
    else:
        tenant_qs = Tenant.objects.exclude(schema_name="public")
    to_return = []
    for tenant_obj in tenant_qs:
        with tenant_context(tenant_obj):
            if tenant_is_unmodified(tenant_obj.schema_name):
                to_return.append(tenant_obj.schema_name)
    payload = {
        "unmodified_tenants": to_return,
        "unmodified_tenants_count": len(to_return),
        "total_tenants_count": tenant_qs.count(),
    }
    return HttpResponse(json.dumps(payload), content_type="application/json")


def tenant_view(request, tenant_schema_name):
    """View method for internal tenant requests.

    DELETE /_private/api/tenant/<schema_name>/
    """
    logger.info(f"Tenant view: {request.method} {request.user.username}")
    if request.method == "DELETE":
        if not destructive_ok():
            return HttpResponse("Destructive operations disallowed.", status=400)

        tenant_obj = get_object_or_404(Tenant, schema_name=tenant_schema_name)
        with transaction.atomic():
            with tenant_context(tenant_obj):
                if tenant_is_unmodified(tenant_obj.schema_name):
                    logger.warning(f"Deleting tenant {tenant_schema_name}. Requested by {request.user.username}")
                    TENANTS.delete_tenant(tenant_schema_name)
                    tenant_obj.delete()
                    return HttpResponse(status=204)
                else:
                    return HttpResponse("Tenant cannot be deleted.", status=400)
    return HttpResponse(f'Invalid method, only "DELETE" is allowed.', status=405)


def tenant_init(request, tenant_schema_name):
    """View method for resolving 'hung' tenants by re-initing them.

    POST /_private/api/tenant/<schema_name>/init/
    """
    if request.method == "POST":
        msg = f"Initializing schema, running migrations/seeds for tenant {tenant_schema_name}."
        logger.info(msg)

        tenant = get_object_or_404(Tenant, schema_name=tenant_schema_name)
        with transaction.atomic():
            with tenant_context(tenant):
                tenant.create_schema(check_if_exists=True)
                seed_permissions(tenant=tenant)
                seed_roles(tenant=tenant)
                seed_group(tenant=tenant)
                tenant.ready = True
                tenant.save()

        return HttpResponse(msg, status=202)
    return HttpResponse(f'Invalid method, only "POST" is allowed.', status=405)


def run_migrations(request):
    """View method for running migrations.

    POST /_private/api/migrations/run/
    """
    if request.method == "POST":
        schema_list = None
        if request.body:
            schema_list = json.loads(request.body).get("schemas")
        logger.info(f"Running migrations: {request.method} {request.user.username} {schema_list}")
        run_migrations_in_worker.delay(schema_list)
        return HttpResponse("Migrations are running in a background worker.", status=202)
    return HttpResponse(f'Invalid method, only "POST" is allowed.', status=405)


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
            tenant_qs = Tenant.objects.exclude(schema_name="public")[offset : (limit + offset)]  # noqa: E203
        else:
            tenant_qs = Tenant.objects.exclude(schema_name="public")
        tenant_count = tenant_qs.count()
        for idx, tenant in enumerate(list(tenant_qs)):
            with tenant_context(tenant):
                migrations_have_run = MigrationRecorder.Migration.objects.filter(
                    name=migration_name, app=app_name
                ).exists()
                if migrations_have_run:
                    tenants_completed_count += 1
                else:
                    incomplete_tenants.append(tenant.schema_name)
        payload = {
            "migration_name": migration_name,
            "app_name": app_name,
            "tenants_completed_count": tenants_completed_count,
            "total_tenants_count": tenant_count,
            "incomplete_tenants": incomplete_tenants,
            "percent_completed": int((tenants_completed_count / tenant_count) * 100),
        }

        return HttpResponse(json.dumps(payload), content_type="application/json")
    return HttpResponse(f'Invalid method, only "GET" is allowed.', status=405)


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

    return HttpResponse(f'Invalid method, only "GET" and "POST" are allowed.', status=405)


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

    return HttpResponse(f'Invalid method, only "POST" is allowed.', status=405)


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
    return HttpResponse(f'Invalid method, only "POST" is allowed.', status=405)


def car_expiry(request):
    """View method for running cross-account request expiry.

    POST /_private/api/cars/expire/
    """
    if request.method == "POST":
        logger.info("Running cross-account request expiration check.")
        cross_account_cleanup.delay()
        return HttpResponse("Expiry checks are running in a background worker.", status=202)
    return HttpResponse(f'Invalid method, only "POST" is allowed.', status=405)


class SentryDiagnosticError(Exception):
    """Raise this to create an event in Sentry."""

    pass


def trigger_error(request):
    """Trigger an error to confirm Sentry is working."""
    raise SentryDiagnosticError
