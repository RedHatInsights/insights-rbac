"""Helper utilities for api module."""
from django.db import transaction

from api.models import Tenant
from management.utils import account_id_for_tenant


def populate_tenant_account_id():
    tenants = Tenant.objects.filter(account_id__isnull=True).exclude(tenant_name="public")
    for tenant in tenants:
        with transaction.atomic():
            tenant.account_id = account_id_for_tenant(tenant)
            tenant.save()
