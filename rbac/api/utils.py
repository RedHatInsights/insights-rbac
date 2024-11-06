"""Helper utilities for api module."""

import logging
from django.db import transaction
from django.shortcuts import get_object_or_404

from api.models import Tenant
from management.models import BindingMapping
from management.tenant_mapping.model import TenantMapping
from management.workspace.model import Workspace
from management.utils import account_id_for_tenant



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


def migration_resource_deletion(resource, org_id):
    resource_objs = RESOURCE_MODEL_MAPPING[resource].objects.all()
    if org_id:
        tenant = get_object_or_404(Tenant, org_id=org_id)
        if resource == "binding":
            resource_objs = resource_objs.filter(role__tenant=tenant)
        else:
            resource_objs = resource_objs.filter(tenant=tenant)
    else:
        if resource == "binding":
            public_tenant = Tenant.objects.get(tenant_name="public")
            resource_objs = resource_objs.exclude(role__tenant=public_tenant)
    if resource == "workspace":
        # Have to delete the ones without children first or deletion will fail
        logger.info("Deleting workspaces without children.")
        while(resource_objs.filter(children=None).exists()):
            resource_objs.filter(children=None).delete()
        logger.info("All workspaces without children removed.")
    resource_objs.delete()
    logger.info(f"Resources of type {resource} deleted.", status=204)
