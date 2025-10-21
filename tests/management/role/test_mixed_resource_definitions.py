#
# Copyright 2025 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Tests for roles with mixed resource definitions (some with, some without)."""
from django.test import override_settings

from management.models import Permission, Workspace
from management.role.model import BindingMapping, Role
from migration_tool.migrate_role import migrate_role
from tests.identity_request import IdentityRequest


@override_settings(
    REPLICATION_TO_RELATION_ENABLED=True,
    PRINCIPAL_USER_DOMAIN="redhat",
    ROOT_SCOPE_PERMISSIONS="advisor:*:*,vulnerability:*:*",
    TENANT_SCOPE_PERMISSIONS="rbac:*:*,cost-management:*:*",
)
class MixedResourceDefinitionTests(IdentityRequest):
    """Test roles with some accesses having resource definitions and some without."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        # Create workspaces
        self.root_workspace = Workspace.objects.create(
            name="Root Workspace",
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
        )
        self.default_workspace = Workspace.objects.create(
            name="Default Workspace",
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            parent=self.root_workspace,
        )
        self.specific_workspace = Workspace.objects.create(
            name="Specific Workspace",
            tenant=self.tenant,
            type=Workspace.Types.STANDARD,
            parent=self.default_workspace,
        )

        # Create permissions
        self.default_perm = Permission.objects.create(
            permission="inventory:host:read",
            tenant=self.tenant,
        )
        self.workspace_perm = Permission.objects.create(
            permission="inventory:group:write",
            tenant=self.tenant,
        )
        self.root_perm = Permission.objects.create(
            permission="advisor:recommendation:read",
            tenant=self.tenant,
        )

    def tearDown(self):
        """Tear down test data."""
        Workspace.objects.all().update(parent=None)
        Workspace.objects.all().delete()
        super().tearDown()

    def test_role_with_default_and_workspace_specific_accesses_creates_multiple_bindings(self):
        """
        Test that a role with mixed accesses creates separate V2 roles and bindings.
        
        Scenario:
        - One access without resource definition (should bind to default workspace scope)
        - One access with specific workspace resource definition (should bind to that workspace)
        
        Expected:
        - 2 V2 role bindings created
        - 2 BindingMapping records created
        - One bound to default workspace
        - One bound to specific workspace
        """
        # Create a role with mixed accesses
        role = Role.objects.create(
            name="Mixed Access Role",
            tenant=self.tenant,
        )
        
        # Access 1: No resource definition - should bind to default workspace
        access1 = role.access.create(permission=self.default_perm, tenant=self.tenant)
        
        # Access 2: With resource definition - should bind to specific workspace
        access2 = role.access.create(permission=self.workspace_perm, tenant=self.tenant)
        access2.resourceDefinitions.create(
            tenant=self.tenant,
            attributeFilter={
                "key": "group.id",
                "operation": "equal",
                "value": str(self.specific_workspace.id),
            },
        )

        # Migrate the role
        relationships, mappings = migrate_role(role, self.default_workspace)

        # Verify 2 bindings were created
        self.assertEqual(len(mappings), 2, "Should create 2 role bindings")

        # Verify BindingMapping records exist in database
        db_mappings = BindingMapping.objects.filter(role=role)
        self.assertEqual(db_mappings.count(), 2, "Should have 2 BindingMapping records in database")

        # Check that one is bound to default workspace and one to specific workspace
        resource_ids = {m.resource_id for m in mappings}
        expected_ids = {str(self.default_workspace.id), str(self.specific_workspace.id)}
        self.assertEqual(
            resource_ids,
            expected_ids,
            f"Should have bindings to both default and specific workspace. Got: {resource_ids}",
        )

        # Verify all are workspace bindings
        for mapping in mappings:
            self.assertEqual(mapping.resource_type_namespace, "rbac")
            self.assertEqual(mapping.resource_type_name, "workspace")

    def test_role_with_scope_based_and_workspace_specific_accesses(self):
        """
        Test that a role with scope-based (ROOT) and workspace-specific accesses creates correct bindings.
        
        Scenario:
        - One access with ROOT scope permission (no resource definition)
        - One access with specific workspace resource definition
        
        Expected:
        - 2 V2 role bindings created
        - One bound to root workspace (based on scope)
        - One bound to specific workspace (based on resource definition)
        """
        role = Role.objects.create(
            name="Scope + Workspace Role",
            tenant=self.tenant,
        )
        
        # Access 1: ROOT scope permission without resource definition
        role.access.create(permission=self.root_perm, tenant=self.tenant)
        
        # Access 2: With specific workspace resource definition
        access2 = role.access.create(permission=self.workspace_perm, tenant=self.tenant)
        access2.resourceDefinitions.create(
            tenant=self.tenant,
            attributeFilter={
                "key": "group.id",
                "operation": "equal",
                "value": str(self.specific_workspace.id),
            },
        )

        # Migrate the role
        relationships, mappings = migrate_role(role, self.default_workspace)

        # Verify 2 bindings were created
        self.assertEqual(len(mappings), 2, "Should create 2 role bindings")

        # Check resource IDs
        resource_ids = {m.resource_id for m in mappings}
        expected_ids = {str(self.root_workspace.id), str(self.specific_workspace.id)}
        self.assertEqual(
            resource_ids,
            expected_ids,
            f"Should have bindings to root and specific workspace. Got: {resource_ids}",
        )

    def test_updating_role_from_workspace_to_scope_updates_binding_mapping(self):
        """
        Test that updating a role's accesses properly updates BindingMapping.
        
        Scenario:
        1. Create role with workspace-specific access
        2. Verify BindingMapping created for that workspace
        3. Update role to remove resource definition (should bind to scope instead)
        4. Verify BindingMapping is updated to new resource
        """
        # Step 1: Create role with workspace-specific access
        role = Role.objects.create(
            name="Workspace Specific Role",
            tenant=self.tenant,
        )
        access = role.access.create(permission=self.workspace_perm, tenant=self.tenant)
        access.resourceDefinitions.create(
            tenant=self.tenant,
            attributeFilter={
                "key": "group.id",
                "operation": "equal",
                "value": str(self.specific_workspace.id),
            },
        )

        # Step 2: Migrate and verify initial binding
        relationships, initial_mappings = migrate_role(role, self.default_workspace)
        self.assertEqual(len(initial_mappings), 1)
        initial_mapping = initial_mappings[0]
        self.assertEqual(initial_mapping.resource_id, str(self.specific_workspace.id))
        
        # Save to database
        initial_mapping.save()
        initial_mapping_id = initial_mapping.id

        # Step 3: Update role - remove resource definition
        access.resourceDefinitions.all().delete()

        # Step 4: Re-migrate with current bindings
        relationships, updated_mappings = migrate_role(
            role, self.default_workspace, current_bindings=BindingMapping.objects.filter(role=role)
        )

        # Verify still 1 binding but to different resource
        self.assertEqual(len(updated_mappings), 1)
        updated_mapping = updated_mappings[0]
        
        # Should now be bound to default workspace (since no resource definition)
        self.assertEqual(updated_mapping.resource_id, str(self.default_workspace.id))
        
        # Verify it reused the same BindingMapping record (updated, not created new)
        self.assertEqual(updated_mapping.id, initial_mapping_id, "Should reuse same BindingMapping record")

    def test_role_with_multiple_accesses_same_and_different_workspaces(self):
        """
        Test complex scenario with multiple accesses to same and different resources.
        
        Scenario:
        - 2 different permissions without resource definitions (should group together)
        - 1 permission with specific workspace A
        - 1 permission with specific workspace B
        
        Expected:
        - 3 V2 role bindings
        - One with both default permissions bound to default workspace
        - One with workspace A permission bound to workspace A
        - One with workspace B permission bound to workspace B
        """
        workspace_a = Workspace.objects.create(
            name="Workspace A",
            tenant=self.tenant,
            type=Workspace.Types.STANDARD,
            parent=self.default_workspace,
        )
        workspace_b = Workspace.objects.create(
            name="Workspace B",
            tenant=self.tenant,
            type=Workspace.Types.STANDARD,
            parent=self.default_workspace,
        )

        role = Role.objects.create(
            name="Complex Role",
            tenant=self.tenant,
        )
        
        # Two accesses without resource definitions
        role.access.create(permission=self.default_perm, tenant=self.tenant)
        role.access.create(
            permission=Permission.objects.create(permission="inventory:host:write", tenant=self.tenant),
            tenant=self.tenant,
        )
        
        # Access with workspace A
        access_a = role.access.create(
            permission=Permission.objects.create(permission="inventory:group:read", tenant=self.tenant),
            tenant=self.tenant,
        )
        access_a.resourceDefinitions.create(
            tenant=self.tenant,
            attributeFilter={"key": "group.id", "operation": "equal", "value": str(workspace_a.id)},
        )
        
        # Access with workspace B
        access_b = role.access.create(permission=self.workspace_perm, tenant=self.tenant)
        access_b.resourceDefinitions.create(
            tenant=self.tenant,
            attributeFilter={"key": "group.id", "operation": "equal", "value": str(workspace_b.id)},
        )

        # Migrate the role
        relationships, mappings = migrate_role(role, self.default_workspace)

        # Verify 3 bindings
        self.assertEqual(len(mappings), 3, "Should create 3 role bindings")

        # Check resources
        resource_ids = {m.resource_id for m in mappings}
        expected_ids = {str(self.default_workspace.id), str(workspace_a.id), str(workspace_b.id)}
        self.assertEqual(resource_ids, expected_ids)

        # Verify BindingMapping records
        db_mappings = BindingMapping.objects.filter(role=role)
        self.assertEqual(db_mappings.count(), 3)

        # Find the default workspace binding and verify it has both permissions
        default_binding = next(m for m in mappings if m.resource_id == str(self.default_workspace.id))
        role_binding = default_binding.get_role_binding()
        self.assertEqual(len(role_binding.role.permissions), 2, "Default workspace binding should have 2 permissions")

