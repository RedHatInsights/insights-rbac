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

from unittest.mock import Mock, patch
from django.conf import settings
from django.test import TestCase, override_settings
from management.models import BindingMapping, Workspace, Access, Permission
from management.permission.scope_service import Scope, ImplicitResourceService
from management.role.model import Role, ResourceDefinition
from migration_tool.in_memory_tuples import InMemoryTuples, InMemoryRelationReplicator, all_of, relation, resource
from migration_tool.migrate_binding_scope import (
    determine_binding_scope_for_role,
    should_migrate_binding,
    migrate_binding_scope,
)
from api.models import Tenant


class BindingScopeMigrationTest(TestCase):
    """Tests for binding scope migration."""

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

    @override_settings(ROOT_SCOPE_PERMISSIONS="", TENANT_SCOPE_PERMISSIONS="")
    def test_migrate_binding_scope_no_change_needed(self):
        """Test that migration is skipped if binding is already at correct scope."""
        role = Role.objects.create(tenant=self.tenant, name="Test Role", system=False)
        Access.objects.create(role=role, permission=self.default_permission, tenant=self.tenant)

        binding = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "test-binding-id",
                "groups": [],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": False, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
        )

        replicator = InMemoryRelationReplicator(self.tuples)
        result = migrate_binding_scope(binding, self.tenant, replicator)

        # Should return False since no migration needed
        self.assertFalse(result)

        # No tuples should be added or removed
        self.assertEqual(len(self.tuples), 0)

    @override_settings(ROOT_SCOPE_PERMISSIONS="", TENANT_SCOPE_PERMISSIONS="")
    def test_migrate_binding_scope_from_root_to_default(self):
        """Test migrating binding from root workspace to default workspace."""
        role = Role.objects.create(tenant=self.tenant, name="Test Role", system=False)
        Access.objects.create(role=role, permission=self.default_permission, tenant=self.tenant)

        # Create binding at root workspace (simulating incorrect historical state)
        binding = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "test-binding-id",
                "groups": [],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": False, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.root_workspace.id),
        )

        # Add initial tuples to store (simulating existing state in relations API)
        for tuple in binding.as_tuples():
            self.tuples.add(tuple)

        # Verify initial state: root workspace binding exists
        root_binding_tuples_before = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.root_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(root_binding_tuples_before), 1)

        # Verify initial state: default workspace binding doesn't exist yet
        default_binding_tuples_before = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.default_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(default_binding_tuples_before), 0)

        replicator = InMemoryRelationReplicator(self.tuples)
        result = migrate_binding_scope(binding, self.tenant, replicator)

        # Should return True since migration happened
        self.assertTrue(result)

        # Verify binding was updated
        binding.refresh_from_db()
        self.assertEqual(binding.resource_id, str(self.default_workspace.id))

        # Verify tuples after migration
        # Root workspace -> binding tuple should be removed
        root_binding_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.root_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(root_binding_tuples_after), 0)

        # Default workspace -> binding tuple should be added
        default_binding_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.default_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(default_binding_tuples_after), 1)

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="cost-management:*:*",
        PRINCIPAL_USER_DOMAIN="redhat",
    )
    @patch("migration_tool.migrate_binding_scope.default_implicit_resource_service")
    def test_migrate_binding_scope_from_default_to_tenant(self, mock_scope_service):
        """Test migrating binding from default workspace to tenant level."""
        # Set up mock scope service with test settings
        mock_scope_service.scope_for_role = ImplicitResourceService.from_settings().scope_for_role

        role = Role.objects.create(tenant=self.tenant, name="Tenant Scope Role", system=False)
        Access.objects.create(role=role, permission=self.tenant_permission, tenant=self.tenant)

        binding = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "test-binding-id",
                "groups": [],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": False, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
        )

        # Add initial tuples to the store (simulate existing state)
        for tuple in binding.as_tuples():
            self.tuples.add(tuple)

        expected_tenant_id = Tenant.org_id_to_tenant_resource_id(self.tenant.org_id)

        # Verify initial state: default workspace binding exists
        workspace_tuples_before = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.default_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(workspace_tuples_before), 1)

        # Verify initial state: tenant binding doesn't exist yet
        tenant_tuples_before = self.tuples.find_tuples(
            all_of(resource("rbac", "tenant", expected_tenant_id), relation("binding"))
        )
        self.assertEqual(len(tenant_tuples_before), 0)

        replicator = InMemoryRelationReplicator(self.tuples)
        result = migrate_binding_scope(binding, self.tenant, replicator)

        # Should return True since migration happened
        self.assertTrue(result)

        # Verify binding was updated to tenant level
        binding.refresh_from_db()
        self.assertEqual(binding.resource_type_namespace, "rbac")
        self.assertEqual(binding.resource_type_name, "tenant")
        self.assertEqual(binding.resource_id, expected_tenant_id)

        # Verify tuples after migration
        # Workspace binding tuple should be removed
        workspace_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "workspace", str(self.default_workspace.id)), relation("binding"))
        )
        self.assertEqual(len(workspace_tuples_after), 0)

        # Tenant binding tuple should be added
        tenant_tuples_after = self.tuples.find_tuples(
            all_of(resource("rbac", "tenant", expected_tenant_id), relation("binding"))
        )
        self.assertEqual(len(tenant_tuples_after), 1)

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="cost-management:*:*",
        PRINCIPAL_USER_DOMAIN="redhat",
    )
    @patch("migration_tool.migrate_binding_scope.default_implicit_resource_service")
    def test_migrate_multiple_bindings_to_tenant_scope(self, mock_scope_service):
        """Test migrating a role with bindings at both default and root to tenant scope."""
        # Set up mock scope service with test settings
        mock_scope_service.scope_for_role = ImplicitResourceService.from_settings().scope_for_role

        # Role with tenant-scoped permission
        role = Role.objects.create(tenant=self.tenant, name="Tenant Scope Role", system=False)
        Access.objects.create(role=role, permission=self.tenant_permission, tenant=self.tenant)

        # Create bindings at both default and root workspace
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

        replicator = InMemoryRelationReplicator(self.tuples)

        # Migrate default binding first - migrates to tenant level
        result1 = migrate_binding_scope(binding_default, self.tenant, replicator)
        self.assertTrue(result1)

        # Verify it migrated to tenant level
        binding_default.refresh_from_db()
        expected_tenant_id = Tenant.org_id_to_tenant_resource_id(self.tenant.org_id)
        self.assertEqual(binding_default.resource_type_name, "tenant")
        self.assertEqual(binding_default.resource_id, expected_tenant_id)

        # Now migrate root binding - should be deleted because default already migrated to tenant
        result2 = migrate_binding_scope(binding_root, self.tenant, replicator)
        self.assertTrue(result2)  # Returns True because it was deleted

        # Root binding should be deleted
        with self.assertRaises(BindingMapping.DoesNotExist):
            binding_root.refresh_from_db()

        # Only binding_default should remain (at tenant level)
        remaining_bindings = BindingMapping.objects.filter(role=role)
        self.assertEqual(remaining_bindings.count(), 1)
        self.assertEqual(remaining_bindings.first().id, binding_default.id)

    @override_settings(ROOT_SCOPE_PERMISSIONS="rbac:*:*", TENANT_SCOPE_PERMISSIONS="")
    @patch("migration_tool.migrate_binding_scope.default_implicit_resource_service")
    def test_migrate_multiple_bindings_to_root_scope(self, mock_scope_service):
        """Test migrating a role with bindings at both default and root to root scope."""
        # Set up mock scope service with test settings
        mock_scope_service.scope_for_role = ImplicitResourceService.from_settings().scope_for_role

        # Role with root-scoped permission
        role = Role.objects.create(tenant=self.tenant, name="Root Scope Role", system=False)
        Access.objects.create(role=role, permission=self.root_permission, tenant=self.tenant)

        # Create bindings at both default and root workspace
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

        # Add initial tuples to the store (simulate existing state)
        for tuple in binding_default.as_tuples():
            self.tuples.add(tuple)
        for tuple in binding_root.as_tuples():
            self.tuples.add(tuple)

        # Verify initial state: both bindings have tuples
        default_tuples_before = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", "binding-default")))
        root_tuples_before = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", "binding-root")))
        self.assertGreater(len(default_tuples_before), 0)
        self.assertGreater(len(root_tuples_before), 0)

        initial_tuple_count = len(self.tuples)

        replicator = InMemoryRelationReplicator(self.tuples)

        # Migrate root binding first (it's already at correct scope, no change)
        result2 = migrate_binding_scope(binding_root, self.tenant, replicator)
        self.assertFalse(result2)  # Already at correct scope

        # No tuples should be added or removed for root binding
        self.assertEqual(len(self.tuples), initial_tuple_count)

        # Now migrate default binding - should be deleted because root binding already exists
        result1 = migrate_binding_scope(binding_default, self.tenant, replicator)
        self.assertTrue(result1)  # Returns True because it was deleted

        # Root binding should still exist at root workspace
        binding_root.refresh_from_db()
        self.assertEqual(binding_root.resource_type_name, "workspace")
        self.assertEqual(binding_root.resource_id, str(self.root_workspace.id))

        # Default binding should be deleted
        with self.assertRaises(BindingMapping.DoesNotExist):
            binding_default.refresh_from_db()

        # Verify tuples after deletion - all tuples for default binding should be removed
        default_tuples_after = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", "binding-default")))
        self.assertEqual(len(default_tuples_after), 0)

        # Root binding tuples should still exist
        root_tuples_after = self.tuples.find_tuples(all_of(resource("rbac", "role_binding", "binding-root")))
        self.assertEqual(len(root_tuples_after), len(root_tuples_before))

        # Verify only one binding remains for the role
        remaining_bindings = BindingMapping.objects.filter(role=role)
        self.assertEqual(remaining_bindings.count(), 1)
        self.assertEqual(remaining_bindings.first().id, binding_root.id)

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="cost-management:*:*",
        PRINCIPAL_USER_DOMAIN="redhat",
    )
    @patch("migration_tool.migrate_binding_scope.default_implicit_resource_service")
    def test_skip_migration_with_explicit_workspace_resource_definition(self, mock_scope_service):
        """Test that bindings with explicit workspace resource definitions are not migrated."""
        # Set up mock scope service with test settings
        mock_scope_service.scope_for_role = ImplicitResourceService.from_settings().scope_for_role

        # Role with tenant-scoped permission but explicit workspace resource definition
        role = Role.objects.create(tenant=self.tenant, name="Role with Explicit Workspace", system=False)
        access = Access.objects.create(role=role, permission=self.tenant_permission, tenant=self.tenant)

        # Add explicit resource definition for default workspace
        ResourceDefinition.objects.create(
            access=access,
            tenant=self.tenant,
            attributeFilter={"key": "group.id", "operation": "equal", "value": str(self.default_workspace.id)},
        )

        # Create binding at default workspace
        binding = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "test-binding-id",
                "groups": [],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": False, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
        )

        # Should NOT migrate because of explicit resource definition
        should_migrate = should_migrate_binding(binding, self.tenant)
        self.assertFalse(should_migrate)

        # The actual migration loop would skip this binding
        # If should_migrate_binding returns False, migrate_binding_scope is never called
        # So the binding remains unchanged at default workspace
        binding.refresh_from_db()
        self.assertEqual(binding.resource_type_namespace, "rbac")
        self.assertEqual(binding.resource_type_name, "workspace")
        self.assertEqual(binding.resource_id, str(self.default_workspace.id))
