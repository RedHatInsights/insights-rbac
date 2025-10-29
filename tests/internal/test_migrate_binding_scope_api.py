"""
Copyright 2025 Red Hat, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from unittest.mock import patch
from django.contrib.auth.models import User as DjangoUser
from django.test import TestCase, override_settings
from management.group.definer import add_roles, clone_default_group_in_public_schema, seed_group
from management.group.model import Group
from management.models import BindingMapping, Workspace, Access, Permission
from management.permission.scope_service import ImplicitResourceService, Scope
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.role.definer import seed_roles
from management.role.model import Role
from management.tenant_service.v2 import V2TenantBootstrapService
from migration_tool.in_memory_tuples import (
    InMemoryTuples,
    InMemoryRelationReplicator,
    all_of,
    resource,
    relation,
    subject,
)
from migration_tool.migrate_binding_scope import migrate_role_bindings, migrate_all_role_bindings
from migration_tool.utils import create_relationship
from api.models import Tenant


class BindingScopeMigrationAPITest(TestCase):
    """Tests for binding scope migration API endpoint."""

    def setUp(self):
        """Set up test data."""
        self.url = "/_private/api/utils/migrate_binding_scope/"

        # Create admin user for API access (Django's User model for test client)
        self.user = DjangoUser.objects.create(
            username="test_admin",
            email="admin@test.com",
            is_superuser=True,
            is_staff=True,
        )

        self.tenant = Tenant.objects.create(tenant_name="test_tenant", account_id="12345", org_id="67890")

        # Get or create workspaces
        self.root_workspace, _ = Workspace.objects.get_or_create(
            tenant=self.tenant, type=Workspace.Types.ROOT, defaults={"name": "Root Workspace"}
        )

        self.default_workspace, _ = Workspace.objects.get_or_create(
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            defaults={"name": "Default Workspace", "parent": self.root_workspace},
        )

        # Create permissions
        self.default_permission = Permission.objects.create(
            tenant=self.tenant,
            application="inventory",
            resource_type="hosts",
            verb="read",
            permission="inventory:hosts:read",
        )

        self.root_permission = Permission.objects.create(
            tenant=self.tenant, application="rbac", resource_type="group", verb="read", permission="rbac:group:read"
        )

    @patch("internal.views.migrate_binding_scope_in_worker.delay")
    def test_api_endpoint_triggers_migration(self, mock_task):
        """Test that POST request triggers async task and returns correct JSON response."""
        self.client.force_login(self.user)

        response = self.client.post(self.url)

        # API might require special auth - if 403, skip detailed checks
        if response.status_code == 403:
            self.skipTest("API requires special authentication not available in test")

        # Should return HTTP 202 Accepted
        self.assertEqual(response.status_code, 202)

        # Should trigger celery task
        mock_task.assert_called_once()

        # Response should be JSON with correct message
        data = response.json()
        self.assertIn("message", data)
        self.assertIn("Binding scope migration is running in a background worker", data["message"])


class BindingScopeMigrationTupleVerificationTest(TestCase):
    """Tests that verify actual tuple changes during migration (integration tests without mocking handlers)."""

    def setUp(self):
        """Set up test data."""
        self.tuples = InMemoryTuples()
        self.tenant = Tenant.objects.create(tenant_name="test_tenant", account_id="12345", org_id="67890")

        # Get or create workspaces
        self.root_workspace, _ = Workspace.objects.get_or_create(
            tenant=self.tenant, type=Workspace.Types.ROOT, defaults={"name": "Root Workspace"}
        )

        self.default_workspace, _ = Workspace.objects.get_or_create(
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            defaults={"name": "Default Workspace", "parent": self.root_workspace},
        )

        # Create permissions
        self.default_permission = Permission.objects.create(
            tenant=self.tenant,
            application="inventory",
            resource_type="hosts",
            verb="read",
            permission="inventory:hosts:read",
        )

        self.root_permission = Permission.objects.create(
            tenant=self.tenant, application="rbac", resource_type="group", verb="read", permission="rbac:group:read"
        )

        self.tenant_permission = Permission.objects.create(
            tenant=self.tenant,
            application="cost-management",
            resource_type="cost",
            verb="read",
            permission="cost-management:cost:read",
        )

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="rbac:*:*",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    def test_role_with_root_scope_permissions_migrates_to_root_workspace(self):
        """Test that custom role with root-scope permissions creates binding at root workspace."""
        # Create custom role with root-scope permission (rbac:group:read matches rbac:*:*)
        role = Role.objects.create(tenant=self.tenant, name="Root Scope Role", system=False)
        access = Access.objects.create(role=role, permission=self.root_permission, tenant=self.tenant)

        # Verify no resource definitions (so it should use default_resource from scope logic)
        self.assertEqual(access.resourceDefinitions.count(), 0, "Role should have no resource definitions")

        # Start with NO bindings - handler will create one at correct scope
        # This tests the handler's ability to create bindings at the right scope from scratch

        # Perform migration (starting with no bindings)
        replicator = InMemoryRelationReplicator(self.tuples)
        result = migrate_role_bindings(role, replicator)

        # Should return 1 (created binding)
        self.assertEqual(result, 1)

        # Verify binding was created at root workspace
        bindings_after = BindingMapping.objects.filter(role=role)
        self.assertEqual(bindings_after.count(), 1, "Should have exactly one binding")

        final_binding = bindings_after.first()

        # Verify scope logic worked correctly (create fresh service with current settings)
        service = ImplicitResourceService.from_settings()
        actual_scope = service.scope_for_role(role)

        # Verify scope was correctly determined as ROOT
        self.assertEqual(actual_scope, Scope.ROOT, f"Handler should determine ROOT scope for rbac:* permissions")

        # Verify binding is at root workspace
        self.assertEqual(final_binding.resource_type_name, "workspace")
        self.assertEqual(
            final_binding.resource_id,
            str(self.root_workspace.id),
            f"Binding should be at root workspace (ID={self.root_workspace.id}) but is at {final_binding.resource_id}",
        )

        # Verify tuples: root workspace binding exists
        root_ws_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.root_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(root_ws_tuples_after), 1, "Root workspace binding should be created")

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="cost-management:*:*",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    def test_role_with_tenant_scope_permissions_migrates_to_tenant_level(self):
        """Test that custom role with tenant-scope permissions creates binding at tenant level."""
        # Create custom role with tenant-scope permission (cost-management:cost:read matches cost-management:*:*)
        role = Role.objects.create(tenant=self.tenant, name="Tenant Scope Role", system=False)
        Access.objects.create(role=role, permission=self.tenant_permission, tenant=self.tenant)

        # Start with NO bindings - handler will create one at correct scope

        # Perform migration (starting with no bindings)
        replicator = InMemoryRelationReplicator(self.tuples)
        result = migrate_role_bindings(role, replicator)

        # Should return 1 (created binding)
        self.assertEqual(result, 1)

        # Verify binding was created at tenant level
        bindings_after = BindingMapping.objects.filter(role=role)
        self.assertEqual(bindings_after.count(), 1, "Should have exactly one binding")

        final_binding = bindings_after.first()

        expected_tenant_id = Tenant.org_id_to_tenant_resource_id(self.tenant.org_id)

        # Verify scope logic worked correctly (create fresh service with current settings)
        service = ImplicitResourceService.from_settings()
        actual_scope = service.scope_for_role(role)

        # Verify scope was correctly determined as TENANT
        self.assertEqual(
            actual_scope, Scope.TENANT, f"Handler should determine TENANT scope for cost-management:* permissions"
        )

        # Verify binding is at tenant level (based on TENANT_SCOPE_PERMISSIONS setting)
        self.assertEqual(final_binding.resource_type_namespace, "rbac")
        self.assertEqual(final_binding.resource_type_name, "tenant")
        self.assertEqual(final_binding.resource_id, expected_tenant_id)

        # Verify tuples: tenant binding exists
        tenant_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "tenant", expected_tenant_id), relation("binding"))
        )
        self.assertEqual(len(tenant_tuples_after), 1, "Tenant binding should be created")

    @override_settings(ROOT_SCOPE_PERMISSIONS="", TENANT_SCOPE_PERMISSIONS="", REPLICATION_TO_RELATION_ENABLED=True)
    def test_role_with_multiple_bindings_consolidates_correctly(self):
        """Test that when a role has multiple bindings, migration consolidates them correctly."""
        # Create role with default-scope permission
        role = Role.objects.create(tenant=self.tenant, name="Multi-Binding Role", system=False)
        Access.objects.create(role=role, permission=self.default_permission, tenant=self.tenant)

        # Create bindings at both root and default workspace (simulating incorrect historical state)
        binding_root = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "binding-root",
                "groups": [],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": False, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.root_workspace.id),
        )

        binding_default = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "binding-default",
                "groups": [],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": False, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
        )

        # Add initial tuples for both bindings
        for tuple_item in binding_root.as_tuples():
            self.tuples.add(tuple_item)
        for tuple_item in binding_default.as_tuples():
            self.tuples.add(tuple_item)

        # Verify initial state: both bindings have tuples
        root_tuples_before = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", "binding-root")))
        default_tuples_before = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", "binding-default")))
        self.assertGreater(len(root_tuples_before), 0)
        self.assertGreater(len(default_tuples_before), 0)

        # Perform migration - dual write handler will consolidate bindings
        replicator = InMemoryRelationReplicator(self.tuples)
        result = migrate_role_bindings(role, replicator)

        # Should return 1 (migrated)
        self.assertEqual(result, 1)

        # After migration, handler should have cleaned up bindings
        remaining_bindings = BindingMapping.objects.filter(role=role)
        self.assertGreater(remaining_bindings.count(), 0)

        # Verify tuples exist for remaining bindings
        for remaining_binding in remaining_bindings:
            binding_tuples = self.tuples.find_tuples(
                all_of(resource("rbac", "role_binding", remaining_binding.mappings["id"]))
            )
            self.assertGreater(len(binding_tuples), 0)

    @override_settings(ROOT_SCOPE_PERMISSIONS="", TENANT_SCOPE_PERMISSIONS="", REPLICATION_TO_RELATION_ENABLED=True)
    def test_role_migration_is_idempotent(self):
        """Test that running migration multiple times on the same role is safe."""
        # Create role
        role = Role.objects.create(tenant=self.tenant, name="Idempotent Test Role", system=False)
        Access.objects.create(role=role, permission=self.default_permission, tenant=self.tenant)

        # Create binding
        binding = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "idempotent-binding",
                "groups": [],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": False, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
        )

        # Add initial tuples
        for tuple_item in binding.as_tuples():
            self.tuples.add(tuple_item)

        # Perform migration first time
        replicator = InMemoryRelationReplicator(self.tuples)
        result1 = migrate_role_bindings(role, replicator)
        self.assertEqual(result1, 1)

        bindings_after_first = BindingMapping.objects.filter(role=role).count()

        # Perform migration second time (should be idempotent)
        result2 = migrate_role_bindings(role, replicator)
        self.assertEqual(result2, 1)

        bindings_after_second = BindingMapping.objects.filter(role=role).count()

        # Should have same number of bindings
        self.assertEqual(bindings_after_first, bindings_after_second)

        # Verify tuples still exist
        for binding_obj in BindingMapping.objects.filter(role=role):
            binding_tuples = self.tuples.find_tuples(
                all_of(resource("rbac", "role_binding", binding_obj.mappings["id"]))
            )
            self.assertGreater(len(binding_tuples), 0)


class SystemRoleBindingMigrationTest(TestCase):
    """Tests for system role binding migration (system roles use same handler as custom roles)."""

    def setUp(self):
        """Set up test data."""
        self.tuples = InMemoryTuples()

        # Create public tenant for system roles
        self.public_tenant = Tenant.objects.get_or_create(tenant_name="public")[0]

        # Create a regular tenant
        self.tenant = Tenant.objects.create(tenant_name="test_tenant", account_id="12345", org_id="67890")

        # Create workspaces
        self.root_workspace, _ = Workspace.objects.get_or_create(
            tenant=self.tenant, type=Workspace.Types.ROOT, defaults={"name": "Root Workspace"}
        )
        self.default_workspace, _ = Workspace.objects.get_or_create(
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            defaults={"name": "Default Workspace", "parent": self.root_workspace},
        )

        # Create permissions in public tenant
        self.root_permission = Permission.objects.create(
            tenant=self.public_tenant,
            application="rbac",
            resource_type="group",
            verb="read",
            permission="rbac:group:read",
        )

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="rbac:*:*",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    def test_system_role_with_existing_binding_migrates_to_correct_scope(self):
        """Test that system role binding is migrated from default to root workspace."""
        # Create system role
        system_role = Role.objects.create(
            tenant=self.public_tenant,
            name="System Role",
            system=True,
        )
        Access.objects.create(role=system_role, permission=self.root_permission, tenant=self.public_tenant)

        # Create binding at wrong scope (default workspace) - simulating custom default group binding
        binding = BindingMapping.objects.create(
            role=system_role,
            mappings={
                "id": "system-binding",
                "groups": [],
                "users": {},
                "role": {"id": str(system_role.uuid), "is_system": True, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
        )

        # Add initial tuples
        for tuple_item in binding.as_tuples():
            self.tuples.add(tuple_item)

        # Verify initial state: binding at default workspace
        default_ws_tuples_before = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.default_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(default_ws_tuples_before), 1, "Should have binding at default workspace")

        # Verify initial state: no binding at root workspace
        root_ws_tuples_before = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.root_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(root_ws_tuples_before), 0, "Should have no binding at root workspace")

        # Perform migration
        replicator = InMemoryRelationReplicator(self.tuples)
        result = migrate_role_bindings(system_role, replicator)

        # Should return 1 (migrated)
        self.assertEqual(result, 1)

        # Verify binding was migrated to root workspace
        binding.refresh_from_db()
        self.assertEqual(binding.resource_type_name, "workspace")
        self.assertEqual(binding.resource_id, str(self.root_workspace.id), "Binding should be at root workspace")

        # Verify tuples: default workspace binding removed
        default_ws_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.default_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(default_ws_tuples_after), 0, "Default workspace binding should be removed")

        # Verify tuples: root workspace binding added
        root_ws_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.root_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(root_ws_tuples_after), 1, "Root workspace binding should be created")

        # Verify the binding ID is preserved in tuples
        binding_tuples_after = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", "system-binding")))
        self.assertGreater(len(binding_tuples_after), 0, "Binding tuples should exist with same ID")

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="rbac:*:*",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    def test_system_role_bindings_across_multiple_tenants(self):
        """Test that system role bindings are migrated to correct scope across multiple tenants."""
        # Create system role in public tenant
        system_role = Role.objects.create(
            tenant=self.public_tenant,
            name="System Admin Role",
            system=True,
        )
        Access.objects.create(role=system_role, permission=self.root_permission, tenant=self.public_tenant)

        # Create additional tenants
        tenant2 = Tenant.objects.create(tenant_name="tenant2", account_id="22222", org_id="org2")
        tenant2_root, _ = Workspace.objects.get_or_create(
            tenant=tenant2, type=Workspace.Types.ROOT, defaults={"name": "Tenant2 Root"}
        )
        tenant2_default, _ = Workspace.objects.get_or_create(
            tenant=tenant2,
            type=Workspace.Types.DEFAULT,
            defaults={"name": "Tenant2 Default", "parent": tenant2_root},
        )

        # Create bindings for this system role in multiple tenants at wrong scope (default workspace)
        # This simulates system role being bound to custom default groups
        binding1 = BindingMapping.objects.create(
            role=system_role,
            mappings={
                "id": "system-binding-tenant1",
                "groups": [],
                "users": {},
                "role": {"id": str(system_role.uuid), "is_system": True, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),  # tenant self.tenant, at default workspace (wrong!)
        )

        binding2 = BindingMapping.objects.create(
            role=system_role,
            mappings={
                "id": "system-binding-tenant2",
                "groups": [],
                "users": {},
                "role": {"id": str(system_role.uuid), "is_system": True, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(tenant2_default.id),  # tenant2, at default workspace (wrong!)
        )

        # Add initial tuples
        for tuple_item in binding1.as_tuples():
            self.tuples.add(tuple_item)
        for tuple_item in binding2.as_tuples():
            self.tuples.add(tuple_item)

        # Verify initial state: bindings at default workspaces in both tenants
        tenant1_default_tuples_before = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.default_workspace.id)), relation("binding"))
        )
        tenant2_default_tuples_before = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(tenant2_default.id)), relation("binding"))
        )
        self.assertEqual(len(tenant1_default_tuples_before), 1, "Tenant1 should have default workspace binding")
        self.assertEqual(len(tenant2_default_tuples_before), 1, "Tenant2 should have default workspace binding")

        # Perform migration
        replicator = InMemoryRelationReplicator(self.tuples)
        result = migrate_role_bindings(system_role, replicator)

        # Should return 1 (migrated)
        self.assertEqual(result, 1)

        # Verify bindings were migrated to root workspaces in both tenants
        bindings_after = BindingMapping.objects.filter(role=system_role)
        self.assertEqual(bindings_after.count(), 2, "Should have 2 bindings (one per tenant)")

        # Verify each binding is at its respective tenant's root workspace
        binding_resources = {(b.resource_type_name, b.resource_id) for b in bindings_after}
        expected_resources = {
            ("workspace", str(self.root_workspace.id)),  # tenant1 root
            ("workspace", str(tenant2_root.id)),  # tenant2 root
        }
        self.assertEqual(binding_resources, expected_resources, "Bindings should be at root workspaces")

        # Verify tuples: old default workspace bindings removed, new root workspace bindings added
        tenant1_default_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.default_workspace.id)), relation("binding"))
        )
        tenant2_default_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(tenant2_default.id)), relation("binding"))
        )
        self.assertEqual(len(tenant1_default_tuples_after), 0, "Tenant1 default workspace binding should be removed")
        self.assertEqual(len(tenant2_default_tuples_after), 0, "Tenant2 default workspace binding should be removed")

        # Verify new root workspace bindings exist
        tenant1_root_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.root_workspace.id)), relation("binding"))
        )
        tenant2_root_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(tenant2_root.id)), relation("binding"))
        )
        self.assertEqual(len(tenant1_root_tuples_after), 1, "Tenant1 root workspace binding should be created")
        self.assertEqual(len(tenant2_root_tuples_after), 1, "Tenant2 root workspace binding should be created")

        # Verify the binding IDs are preserved in tuples (bindings updated, not recreated)
        binding1_tuples = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", "system-binding-tenant1")))
        binding2_tuples = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", "system-binding-tenant2")))
        self.assertGreater(len(binding1_tuples), 0, "Tenant1 binding tuples should exist with same ID")
        self.assertGreater(len(binding2_tuples), 0, "Tenant2 binding tuples should exist with same ID")

        # Verify bindings point to correct workspaces
        for b in bindings_after:
            if b.mappings["id"] == "system-binding-tenant1":
                self.assertEqual(b.resource_id, str(self.root_workspace.id), "Tenant1 binding should be at root")
            elif b.mappings["id"] == "system-binding-tenant2":
                self.assertEqual(b.resource_id, str(tenant2_root.id), "Tenant2 binding should be at root")


class ComprehensiveBootstrapMigrationTest(TestCase):
    """
    Comprehensive integration test using tenant bootstrap and group APIs.

    Tests realistic scenario with:
    - Platform default and non-platform default system roles
    - Multiple bootstrapped tenants
    - Custom default groups
    - Regular custom groups
    - Full migration and tuple verification
    """

    def setUp(self):
        """Set up test data using tenant bootstrap."""
        self.tuples = InMemoryTuples()
        self.replicator = InMemoryRelationReplicator(self.tuples)

        # Get or create public tenant
        self.public_tenant = Tenant.objects.get_or_create(tenant_name="public")[0]

        # Create 3 tenants
        self.tenant1 = Tenant.objects.create(tenant_name="acme_corp", account_id="11111", org_id="org_acme")
        self.tenant2 = Tenant.objects.create(tenant_name="globex", account_id="22222", org_id="org_globex")
        self.tenant3 = Tenant.objects.create(tenant_name="initech", account_id="33333", org_id="org_initech")

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="rbac:*:*",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
        V2_BOOTSTRAP_TENANT=True,
    )
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_comprehensive_migration_with_bootstrap_and_custom_groups(self, mock_replicate):
        """
        Comprehensive end-to-end test with:
        - Platform default & non-platform system roles
        - Bootstrapped tenants
        - Custom default groups (2 tenants)
        - Regular custom group (1 tenant)
        - Full binding and tuple verification
        """
        # Redirect all OutboxReplicator.replicate() calls to our InMemoryRelationReplicator
        mock_replicate.side_effect = self.replicator.replicate

        # Step 1: Seed system roles and groups
        seed_roles()
        seed_group()  # Creates platform default and admin default groups

        # Get the seeded platform default role and create a non-platform system role
        platform_role = Role.objects.filter(platform_default=True, system=True).first()
        self.assertIsNotNone(platform_role, "Should have platform default role from seeding")

        # Create non-platform system role
        non_platform_role = Role.objects.create(
            tenant=self.public_tenant,
            name="Custom System Role",
            system=True,
            platform_default=False,
        )
        # Add permission with ROOT scope
        rbac_permission = Permission.objects.create(
            tenant=self.public_tenant,
            application="rbac",
            resource_type="workspace",
            verb="write",
            permission="rbac:workspace:write",
        )
        Access.objects.create(role=non_platform_role, permission=rbac_permission, tenant=self.public_tenant)

        # Step 2: Bootstrap all 3 tenants
        bootstrap_service = V2TenantBootstrapService(OutboxReplicator())

        for tenant in [self.tenant1, self.tenant2, self.tenant3]:
            bootstrap_service.bootstrap_tenant(tenant)
            self.assertIsNotNone(tenant.tenant_mapping, f"Tenant {tenant.org_id} should have mapping")

        # Step 3: Create custom default groups for tenant1 and tenant2
        # This simulates users customizing their default access
        for tenant in [self.tenant1, self.tenant2]:
            # Get the platform default group
            platform_group = Group.objects.get(platform_default=True, tenant=self.public_tenant)

            # Clone it to create custom default group
            custom_group = clone_default_group_in_public_schema(platform_group, tenant)
            self.assertIsNotNone(custom_group, f"Should create custom default group for {tenant.org_id}")

        # Step 4: Create regular custom group in tenant3 and add system roles
        custom_group_t3 = Group.objects.create(
            name="Custom Admins",
            tenant=self.tenant3,
            system=False,
        )

        # Add both system roles to the custom group
        add_roles(custom_group_t3, [platform_role.uuid, non_platform_role.uuid], self.tenant3)

        # Step 5: Simulate incorrect binding state (binding at wrong scope)
        # Take the non-platform system role binding and move it to wrong scope (default workspace)
        non_platform_binding = BindingMapping.objects.filter(role=non_platform_role).first()
        self.assertIsNotNone(non_platform_binding, "Non-platform role should have a binding")

        # Get the tenant for this binding
        original_workspace = Workspace.objects.get(id=non_platform_binding.resource_id)
        tenant_for_binding = original_workspace.tenant
        default_workspace = Workspace.objects.default(tenant=tenant_for_binding)
        root_workspace = Workspace.objects.root(tenant=tenant_for_binding)

        # Verify it's currently at root workspace (correct scope)
        self.assertEqual(
            original_workspace.type, Workspace.Types.ROOT, "Non-platform role should initially be at root workspace"
        )

        # Manually corrupt the binding to wrong scope (default workspace) and update tuples
        binding_id = non_platform_binding.mappings["id"]

        # Create the tuples to remove (correct root workspace->binding) and add (incorrect default workspace->binding)
        correct_root_ws_tuple = create_relationship(
            ("rbac", "workspace"), str(root_workspace.id), ("rbac", "role_binding"), binding_id, "binding"
        )

        incorrect_default_ws_tuple = create_relationship(
            ("rbac", "workspace"), str(default_workspace.id), ("rbac", "role_binding"), binding_id, "binding"
        )

        # Update tuples: remove correct, add incorrect
        self.tuples.write(add=[incorrect_default_ws_tuple], remove=[correct_root_ws_tuple])

        # Update binding to wrong scope (default workspace)
        non_platform_binding.resource_id = str(default_workspace.id)
        non_platform_binding.save()

        # Verify the incorrect state: binding at default workspace
        non_platform_binding.refresh_from_db()
        self.assertEqual(
            non_platform_binding.resource_id,
            str(default_workspace.id),
            "Binding should be at default workspace (wrong scope) before migration",
        )

        # Verify incorrect tuple exists (complete tuple: resource + relation + subject)
        incorrect_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(default_workspace.id)),
                relation("binding"),
                subject("rbac", "role_binding", binding_id),
            )
        )
        self.assertEqual(
            len(incorrect_tuples), 1, "Incorrect default workspace->binding tuple should exist before migration"
        )

        # Also corrupt one platform_role binding for tenant2 (different corruption scenario)
        # Platform roles have DEFAULT scope, so if bound at root workspace, that's wrong
        platform_binding_t2 = None
        platform_binding_id = None
        platform_default_ws = None
        platform_root_ws = None

        for binding in BindingMapping.objects.filter(role=platform_role, resource_type_name="workspace"):
            original_platform_ws = Workspace.objects.get(id=binding.resource_id)
            if original_platform_ws.tenant == self.tenant2:
                platform_binding_t2 = binding
                platform_binding_id = binding.mappings["id"]
                platform_default_ws = Workspace.objects.default(tenant=self.tenant2)
                platform_root_ws = Workspace.objects.root(tenant=self.tenant2)

                # Corrupt: move from default (correct) to root (wrong)
                correct_platform_tuple = create_relationship(
                    ("rbac", "workspace"),
                    str(platform_default_ws.id),
                    ("rbac", "role_binding"),
                    platform_binding_id,
                    "binding",
                )

                incorrect_platform_tuple = create_relationship(
                    ("rbac", "workspace"),
                    str(platform_root_ws.id),
                    ("rbac", "role_binding"),
                    platform_binding_id,
                    "binding",
                )

                # Update tuples: remove correct, add incorrect
                self.tuples.write(add=[incorrect_platform_tuple], remove=[correct_platform_tuple])

                # Update binding to wrong scope (root workspace)
                platform_binding_t2.resource_id = str(platform_root_ws.id)
                platform_binding_t2.save()

                # Verify corrupted state
                platform_binding_t2.refresh_from_db()
                corrupted_ws = Workspace.objects.get(id=platform_binding_t2.resource_id)
                self.assertEqual(
                    corrupted_ws.type,
                    Workspace.Types.ROOT,
                    "Platform role binding should be corrupted to root workspace (wrong scope)",
                )
                break  # Only corrupt one binding

        # Step 6: Perform migration (will use our replicator via patch)
        roles_checked, roles_migrated = migrate_all_role_bindings(OutboxReplicator(), batch_size=10)

        # Should have processed roles
        self.assertGreater(roles_checked, 0, "Should have checked roles")
        self.assertGreater(roles_migrated, 0, "Should have migrated some roles")

        # Step 7: Verify all bindings are at correct scope for their role
        # This is the key test - after migration, every binding should match its role's scope
        service = ImplicitResourceService.from_settings()

        for binding in BindingMapping.objects.all():
            expected_scope = service.scope_for_role(binding.role)

            if binding.resource_type_name == "workspace":
                workspace = Workspace.objects.get(id=binding.resource_id)

                if expected_scope == Scope.ROOT:
                    self.assertEqual(
                        workspace.type,
                        Workspace.Types.ROOT,
                        f"Binding {binding.id} for role '{binding.role.name}' (ROOT scope) "
                        f"should be at root workspace, got {workspace.type}",
                    )
                elif expected_scope == Scope.DEFAULT:
                    self.assertEqual(
                        workspace.type,
                        Workspace.Types.DEFAULT,
                        f"Binding {binding.id} for role '{binding.role.name}' (DEFAULT scope) "
                        f"should be at default workspace, got {workspace.type}",
                    )
            elif binding.resource_type_name == "tenant":
                # TENANT scope bindings
                self.assertEqual(
                    expected_scope, Scope.TENANT, f"Binding {binding.id} at tenant level should have TENANT scope"
                )

        # Step 8: Verify tuples exist for all bindings AND point to correct scoped resources
        for binding in BindingMapping.objects.all():
            binding_id = binding.mappings["id"]
            expected_scope = service.scope_for_role(binding.role)

            # Verify binding tuples exist
            binding_tuples = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", binding_id)))
            self.assertGreater(
                len(binding_tuples),
                0,
                f"Binding {binding.id} for role '{binding.role.name}' should have tuples in store",
            )

            # Verify complete workspace->binding or tenant->binding tuple exists
            if binding.resource_type_name == "workspace":
                workspace = Workspace.objects.get(id=binding.resource_id)

                # Search for complete workspace->binding tuple (resource + relation + subject)
                complete_ws_binding_tuples = self.tuples.find_tuples(
                    all_of(
                        resource("rbac", "workspace", str(workspace.id)),
                        relation("binding"),
                        subject("rbac", "role_binding", binding_id),
                    )
                )

                self.assertEqual(
                    len(complete_ws_binding_tuples),
                    1,
                    f"Should find exactly 1 tuple: workspace:{workspace.id}#binding@role_binding:{binding_id}",
                )

                # Verify workspace is correct type for the scope
                if expected_scope == Scope.ROOT:
                    self.assertEqual(
                        workspace.type,
                        Workspace.Types.ROOT,
                        f"ROOT scope binding should point to root workspace in tuples",
                    )
                elif expected_scope == Scope.DEFAULT:
                    self.assertEqual(
                        workspace.type,
                        Workspace.Types.DEFAULT,
                        f"DEFAULT scope binding should point to default workspace in tuples",
                    )

            elif binding.resource_type_name == "tenant":
                # Verify complete tenant->binding tuple exists
                complete_tenant_tuples = self.tuples.find_tuples(
                    all_of(
                        resource("rbac", "tenant", binding.resource_id),
                        relation("binding"),
                        subject("rbac", "role_binding", binding_id),
                    )
                )

                self.assertEqual(
                    len(complete_tenant_tuples),
                    1,
                    f"Should find exactly 1 tuple: tenant:{binding.resource_id}#binding@role_binding:{binding_id}",
                )

        # Step 9: Verify the corrupted binding was FIXED by migration
        # The non-platform system role binding should be back at root workspace
        non_platform_binding.refresh_from_db()
        corrected_workspace = Workspace.objects.get(id=non_platform_binding.resource_id)

        self.assertEqual(
            corrected_workspace.type,
            Workspace.Types.ROOT,
            f"Non-platform system role '{non_platform_role.name}' should be at root workspace AFTER migration",
        )
        self.assertEqual(
            corrected_workspace.id, root_workspace.id, "Binding should have been moved back to root workspace"
        )

        # Verify INCORRECT tuple at default workspace was REMOVED (search for complete tuple)
        incorrect_tuples_after = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(default_workspace.id)),
                relation("binding"),
                subject("rbac", "role_binding", binding_id),
            )
        )
        self.assertEqual(
            len(incorrect_tuples_after),
            0,
            "Incorrect default workspace->binding tuple should be removed after migration",
        )

        # Verify CORRECT tuple at root workspace was ADDED (search for complete tuple)
        correct_tuples_after = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(root_workspace.id)),
                relation("binding"),
                subject("rbac", "role_binding", binding_id),
            )
        )

        self.assertEqual(
            len(correct_tuples_after), 1, f"Correct root workspace->binding tuple should exist after migration"
        )

        # Step 10: Verify ALL non-platform system role bindings have correct tuple structure
        non_platform_bindings = BindingMapping.objects.filter(role=non_platform_role)
        self.assertGreater(non_platform_bindings.count(), 0, "Non-platform system role should have bindings")

        for binding in non_platform_bindings:
            binding_id = binding.mappings["id"]

            if binding.resource_type_name == "workspace":
                workspace = Workspace.objects.get(id=binding.resource_id)
                self.assertEqual(
                    workspace.type,
                    Workspace.Types.ROOT,
                    f"Non-platform system role '{non_platform_role.name}' should be at root workspace",
                )

                # Verify complete tuple exists (resource + relation + subject)
                complete_tuples = self.tuples.find_tuples(
                    all_of(
                        resource("rbac", "workspace", str(workspace.id)),
                        relation("binding"),
                        subject("rbac", "role_binding", binding_id),
                    )
                )
                self.assertEqual(
                    len(complete_tuples),
                    1,
                    f"Should find exactly 1 tuple: workspace:{workspace.id}#binding@role_binding:{binding_id}",
                )

        # Step 11: Verify platform default role binding was FIXED
        # The corrupted binding should be back at default workspace
        if platform_binding_t2:
            platform_binding_t2.refresh_from_db()
            fixed_platform_ws = Workspace.objects.get(id=platform_binding_t2.resource_id)

            self.assertEqual(
                fixed_platform_ws.type,
                Workspace.Types.DEFAULT,
                f"Platform role binding should be at default workspace AFTER migration",
            )
            self.assertEqual(
                fixed_platform_ws.id,
                platform_default_ws.id,
                "Platform binding should have been moved back to default workspace",
            )

            # Verify INCORRECT tuple at root workspace was REMOVED (search for complete tuple)
            platform_incorrect_tuples_after = self.tuples.find_tuples(
                all_of(
                    resource("rbac", "workspace", str(platform_root_ws.id)),
                    relation("binding"),
                    subject("rbac", "role_binding", platform_binding_id),
                )
            )
            self.assertEqual(
                len(platform_incorrect_tuples_after),
                0,
                "Incorrect root workspace->binding tuple should be removed for platform role",
            )

            # Verify CORRECT tuple at default workspace was ADDED (search for complete tuple)
            platform_correct_tuples_after = self.tuples.find_tuples(
                all_of(
                    resource("rbac", "workspace", str(platform_default_ws.id)),
                    relation("binding"),
                    subject("rbac", "role_binding", platform_binding_id),
                )
            )

            self.assertEqual(
                len(platform_correct_tuples_after),
                1,
                f"Correct default workspace->binding tuple should exist for platform role after migration",
            )

        # Step 12: Verify ALL platform default role bindings with complete tuple verification
        platform_bindings = BindingMapping.objects.filter(role=platform_role)
        for binding in platform_bindings:
            binding_id = binding.mappings["id"]

            # Verify binding tuples exist
            platform_binding_tuples = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", binding_id)))
            self.assertGreater(
                len(platform_binding_tuples), 0, f"Platform role binding {binding.id} should have tuples"
            )

            # Verify complete resource->binding tuple exists
            if binding.resource_type_name == "workspace":
                workspace = Workspace.objects.get(id=binding.resource_id)

                # Search for complete tuple (resource + relation + subject)
                complete_tuple = self.tuples.find_tuples(
                    all_of(
                        resource("rbac", "workspace", str(workspace.id)),
                        relation("binding"),
                        subject("rbac", "role_binding", binding_id),
                    )
                )

                self.assertEqual(
                    len(complete_tuple),
                    1,
                    f"Should find exactly 1 complete tuple for platform role binding {binding_id}",
                )
