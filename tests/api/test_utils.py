from django.test import TestCase


from api.models import Tenant
from api.utils import migration_resource_deletion
from management.models import BindingMapping, Role, Workspace
from management.tenant_mapping.model import TenantMapping


class TestAPIUtils(TestCase):
    def test_migration_resource_deletion(self):
        org_id_1 = "12345678"
        org_id_2 = "87654321"
        tenant = Tenant.objects.create(
            org_id=org_id_1,
        )
        another_tenant = Tenant.objects.create(
            org_id=org_id_2,
        )
        root_workspaces = Workspace.objects.bulk_create(
            [
                Workspace(
                    name="Test Tenant Root Workspace",
                    type=Workspace.Types.ROOT,
                    tenant=tenant,
                ),
                Workspace(
                    name="Test Tenant Root Workspace",
                    type=Workspace.Types.ROOT,
                    tenant=another_tenant,
                ),
            ]
        )
        Workspace.objects.bulk_create(
            [
                Workspace(
                    name="Test Tenant Default Workspace",
                    type=Workspace.Types.DEFAULT,
                    tenant=tenant,
                    parent=root_workspaces[0],
                ),
                Workspace(
                    name="Test Tenant Default Workspace",
                    type=Workspace.Types.DEFAULT,
                    tenant=another_tenant,
                    parent=root_workspaces[1],
                ),
            ]
        )
        migration_resource_deletion("workspace", org_id_2)
        self.assertFalse(Workspace.objects.filter(tenant=another_tenant).exists())
        self.assertEqual(Workspace.objects.filter(tenant=tenant).count(), 2)
        root = Workspace.objects.create(
            name="Test Tenant Root Workspace",
            type=Workspace.Types.ROOT,
            tenant=another_tenant,
        )
        Workspace.objects.create(
            name="Test Tenant Default Workspace",
            type=Workspace.Types.DEFAULT,
            tenant=another_tenant,
            parent=root,
        )

        migration_resource_deletion("workspace", None)
        self.assertFalse(Workspace.objects.exists())

        # Delete tenantmappings
        TenantMapping.objects.bulk_create(
            [
                TenantMapping(
                    tenant=tenant,
                ),
                TenantMapping(
                    tenant=another_tenant,
                ),
            ]
        )
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
            tenant=Tenant.objects.get(tenant_name="public"),
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
        migration_resource_deletion("binding", org_id_2)
        self.assertFalse(BindingMapping.objects.filter(role=another_role).exists())

        migration_resource_deletion("binding", None)
        self.assertFalse(BindingMapping.objects.exists())
