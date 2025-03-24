"""Helper utilities for api module."""

import logging

from django.db import connection, transaction
from django.shortcuts import get_object_or_404
from management.models import BindingMapping
from management.tenant_mapping.model import TenantMapping
from management.utils import account_id_for_tenant
from management.workspace.model import Workspace

from api.models import Tenant


RESOURCE_MODEL_MAPPING = {
    "workspace": Workspace,
    "mapping": TenantMapping,
    "binding": BindingMapping,
}
logger = logging.getLogger(__name__)


def populate_tenant_account_id():
    """Populate tenant's account id's."""
    tenants = Tenant.objects.filter(account_id__isnull=True).exclude(tenant_name="public")
    for tenant in tenants:
        with transaction.atomic():
            tenant.account_id = account_id_for_tenant(tenant)
            tenant.save()


def get_resources(resource, org_id):
    """Get queryset by org_id."""
    queryset = RESOURCE_MODEL_MAPPING[resource].objects.all()
    if org_id:
        if resource == "binding":
            raise ValueError("Binding cannot be filtered by org_id.")
        tenant = get_object_or_404(Tenant, org_id=org_id)
        queryset = queryset.filter(tenant=tenant)
    return queryset


def migration_resource_deletion(resource, org_id):
    """Delete migration related resources."""
    resource_objs = get_resources(resource, org_id)

    if resource == "workspace":
        # Have to delete the ones without children first or deletion will fail
        logger.info("Deleting workspaces without children.")
        resource_objs = resource_objs.order_by("id")
        chunk_delete(resource_objs.filter(children=None))
        logger.info("All workspaces without children removed.")
    chunk_delete(resource_objs)
    logger.info(f"Resources of type {resource} deleted.")


def chunk_delete(queryset):
    """Delete queryset in chunks."""
    count = 0
    while True:
        delimiter = list(queryset.values_list("id", flat=True)[:10000])
        if not delimiter:
            break
        queryset.filter(id__in=delimiter).delete()
        count += len(delimiter)
        logger.info(f"Deleted {count} records.")


def reset_imported_tenants(query: str, limit: int, excluded: list[str]):
    """Reset (delete) imported tenants based on the given query, limit, and excluded list.

    Args:
        query (str): The SQL query to select tenants.
        limit (int): The limit on the number of tenants to delete.
        excluded (list[str]): The list of tenant IDs to exclude from deletion.
    """
    if limit == 0:
        logger.info("Limit is 0, nothing to do.")
        return

    with connection.cursor() as cursor:
        if limit > 0:
            subquery = f"SELECT id {query}"
            cursor.execute(
                "WITH delete_batch AS (" + subquery + ") "
                "DELETE FROM api_tenant as t USING delete_batch as del where t.id = del.id",
                (tuple(excluded),),
            )
        else:
            cursor.execute(
                "DELETE " + query,
                (tuple(excluded),),
            )
        result = cursor.rowcount

    logger.info(f"Deleted {result} tenants.")
