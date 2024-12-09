from django.test import TestCase


from api.models import Tenant
from api.utils import migration_resource_deletion
from management.models import BindingMapping, Role, Workspace
from management.relation_replicator.noop_replicator import NoopReplicator
from management.tenant_mapping.model import TenantMapping
from management.tenant_service.v2 import V2TenantBootstrapService


class TestAPIUtils(TestCase):
    def test_migration_resource_deletion(self):
        org_id_1 = "12345678"
        org_id_2 = "87654321"
        bootstrap_service = V2TenantBootstrapService(NoopReplicator())
        bootstrapped_tenant_1 = bootstrap_service.new_bootstrapped_tenant(org_id_1)
        bootstrapped_tenant_2 = bootstrap_service.new_bootstrapped_tenant(org_id_2)
        tenant = bootstrapped_tenant_1.tenant
        another_tenant = bootstrapped_tenant_2.tenant

        migration_resource_deletion("workspace", org_id_2)
        self.assertFalse(Workspace.objects.filter(tenant=another_tenant).exists())
        self.assertEqual(Workspace.objects.filter(tenant=tenant).count(), 2)

        migration_resource_deletion("workspace", None)
        self.assertFalse(Workspace.objects.exists())

        # Delete tenantmappings
        migration_resource_deletion("mapping", org_id_2)
        self.assertFalse(TenantMapping.objects.filter(tenant=another_tenant).exists())

        migration_resource_deletion("mapping", None)
        self.assertFalse(TenantMapping.objects.exists())

        # Delete bindingmappings
        tenant_role = Role.objects.create(
            name="role",
            tenant=tenant,
        )
        another_role = Role.objects.create(
            name="role",
            tenant=another_tenant,
        )
        system_role = Role.objects.create(
            name="role",
            tenant=Tenant.objects.get_public_tenant(),
            system=True,
        )
        BindingMapping.objects.create(
            role=tenant_role,
        )
        BindingMapping.objects.create(
            role=another_role,
        )
        BindingMapping.objects.create(
            role=system_role,
        )
        with self.assertRaises(ValueError):
            migration_resource_deletion("binding", org_id_2)

        migration_resource_deletion("binding", None)
        self.assertFalse(BindingMapping.objects.exists())
