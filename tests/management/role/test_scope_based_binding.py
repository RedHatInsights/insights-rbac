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
"""Tests for scope-based role binding integration."""
from django.test import TestCase, override_settings
from django.urls import reverse
from unittest.mock import patch
from rest_framework import status
from rest_framework.test import APIClient

from management.group.relation_api_dual_write_group_handler import RelationApiDualWriteGroupHandler
from management.models import Group, Permission, Role, Workspace
from management.permission.scope_service import ImplicitResourceService, Scope
from management.relation_replicator.logging_replicator import LoggingReplicator
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.role.model import BindingMapping
from migration_tool.migrate_role import migrate_role
from migration_tool.in_memory_tuples import (
    InMemoryRelationReplicator,
    InMemoryTuples,
    all_of,
    resource,
    relation,
)
from tests.identity_request import IdentityRequest


@override_settings(
    REPLICATION_TO_RELATION_ENABLED=True,
    PRINCIPAL_USER_DOMAIN="redhat",
    ROOT_SCOPE_PERMISSIONS="advisor:*:*,vulnerability:*:*,drift:*:*",
    TENANT_SCOPE_PERMISSIONS="rbac:*:*,cost-management:*:*",
)
class ScopeBasedBindingIntegrationTests(IdentityRequest):
    """Integration tests for scope-based role binding."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        # Create workspaces for the tenant
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

        # Create permissions for different scopes
        self.tenant_perm, _ = Permission.objects.get_or_create(
            permission="rbac:role:read",
            tenant=self.tenant,
        )
        self.root_perm, _ = Permission.objects.get_or_create(
            permission="advisor:recommendation:read",
            tenant=self.tenant,
        )
        self.default_perm, _ = Permission.objects.get_or_create(
            permission="inventory:host:read",
            tenant=self.tenant,
        )

    def tearDown(self):
        """Tear down test data."""
        # Update all workspaces to remove parent references first
        Workspace.objects.all().update(parent=None)
        Workspace.objects.all().delete()
        super().tearDown()

    def test_tenant_scope_permissions_bind_to_tenant(self):
        """Test that tenant-level permissions bind to tenant resource."""
        # Create a role with only tenant-scoped permissions
        role = Role.objects.create(
            name="Tenant Role",
            tenant=self.tenant,
        )
        role.access.create(permission=self.tenant_perm, tenant=self.tenant)

        # Migrate the role
        relationships, mappings = migrate_role(role, self.default_workspace)

        # Verify binding is to tenant, not workspace
        self.assertEqual(len(mappings), 1)
        mapping = mappings[0]
        self.assertEqual(mapping.resource_type_namespace, "rbac")
        self.assertEqual(mapping.resource_type_name, "tenant")
        self.assertIn(self.tenant.org_id, mapping.resource_id)

    def test_root_scope_permissions_bind_to_root_workspace(self):
        """Test that root-level permissions bind to root workspace."""
        # Create a role with only root-scoped permissions
        role = Role.objects.create(
            name="Root Workspace Role",
            tenant=self.tenant,
        )
        role.access.create(permission=self.root_perm, tenant=self.tenant)

        # Migrate the role
        relationships, mappings = migrate_role(role, self.default_workspace)

        # Verify binding is to root workspace
        self.assertEqual(len(mappings), 1)
        mapping = mappings[0]
        self.assertEqual(mapping.resource_type_namespace, "rbac")
        self.assertEqual(mapping.resource_type_name, "workspace")
        self.assertEqual(mapping.resource_id, str(self.root_workspace.id))

    def test_default_scope_permissions_bind_to_default_workspace(self):
        """Test that default-level permissions bind to default workspace."""
        # Create a role with only default-scoped permissions
        role = Role.objects.create(
            name="Default Workspace Role",
            tenant=self.tenant,
        )
        role.access.create(permission=self.default_perm, tenant=self.tenant)

        # Migrate the role
        relationships, mappings = migrate_role(role, self.default_workspace)

        # Verify binding is to default workspace
        self.assertEqual(len(mappings), 1)
        mapping = mappings[0]
        self.assertEqual(mapping.resource_type_namespace, "rbac")
        self.assertEqual(mapping.resource_type_name, "workspace")
        self.assertEqual(mapping.resource_id, str(self.default_workspace.id))

    def test_mixed_permissions_bind_to_highest_scope(self):
        """Test that mixed permission roles bind to the highest scope level."""
        # Create a role with permissions from all scopes
        role = Role.objects.create(
            name="Mixed Scope Role",
            tenant=self.tenant,
        )
        role.access.create(permission=self.tenant_perm, tenant=self.tenant)
        role.access.create(permission=self.root_perm, tenant=self.tenant)
        role.access.create(permission=self.default_perm, tenant=self.tenant)

        # Migrate the role
        relationships, mappings = migrate_role(role, self.default_workspace)

        # Verify binding is to tenant (highest scope)
        self.assertEqual(len(mappings), 1)
        mapping = mappings[0]
        self.assertEqual(mapping.resource_type_namespace, "rbac")
        self.assertEqual(mapping.resource_type_name, "tenant")
        self.assertIn(self.tenant.org_id, mapping.resource_id)

    def test_root_and_default_permissions_bind_to_root(self):
        """Test that root + default permissions bind to root workspace."""
        # Create a role with root and default scoped permissions
        role = Role.objects.create(
            name="Root + Default Role",
            tenant=self.tenant,
        )
        role.access.create(permission=self.root_perm, tenant=self.tenant)
        role.access.create(permission=self.default_perm, tenant=self.tenant)

        # Migrate the role
        relationships, mappings = migrate_role(role, self.default_workspace)

        # Verify binding is to root workspace
        self.assertEqual(len(mappings), 1)
        mapping = mappings[0]
        self.assertEqual(mapping.resource_type_namespace, "rbac")
        self.assertEqual(mapping.resource_type_name, "workspace")
        self.assertEqual(mapping.resource_id, str(self.root_workspace.id))

    def test_wildcard_permissions_match_scope(self):
        """Test that wildcard permissions are correctly matched to scope."""
        # Create permissions with wildcards
        wildcard_perm, _ = Permission.objects.get_or_create(
            permission="cost-management:*:*",
            tenant=self.tenant,
        )

        role = Role.objects.create(
            name="Wildcard Permission Role",
            tenant=self.tenant,
        )
        role.access.create(permission=wildcard_perm, tenant=self.tenant)

        # Migrate the role
        relationships, mappings = migrate_role(role, self.default_workspace)

        # Verify binding is to tenant (cost-management is tenant-scoped)
        self.assertEqual(len(mappings), 1)
        mapping = mappings[0]
        self.assertEqual(mapping.resource_type_namespace, "rbac")
        self.assertEqual(mapping.resource_type_name, "tenant")

    def test_unconfigured_app_binds_to_default(self):
        """Test that unconfigured apps bind to default workspace."""
        # Create permission for an app not in scope configuration
        unconfigured_perm, _ = Permission.objects.get_or_create(
            permission="patch:advisory:read",
            tenant=self.tenant,
        )

        role = Role.objects.create(
            name="Unconfigured App Role",
            tenant=self.tenant,
        )
        role.access.create(permission=unconfigured_perm, tenant=self.tenant)

        # Migrate the role
        relationships, mappings = migrate_role(role, self.default_workspace)

        # Verify binding is to default workspace
        self.assertEqual(len(mappings), 1)
        mapping = mappings[0]
        self.assertEqual(mapping.resource_type_namespace, "rbac")
        self.assertEqual(mapping.resource_type_name, "workspace")
        self.assertEqual(mapping.resource_id, str(self.default_workspace.id))

    def test_updating_role_from_default_to_root_scope_rebinds(self):
        """
        Test that adding a new permission with preset ROOT scope creates proper bindings.

        1. Create role with default permission (DEFAULT scope -> default workspace)
        2. Verify binding to default workspace only
        3. Update role to add advisor permission (preset ROOT scope)
        4. Verify default workspace binding is replaced with root workspace binding
        """
        # Step 1: Create role with default-scoped permission
        default_perm, _ = Permission.objects.get_or_create(
            permission="inventory:host:read",
            tenant=self.tenant,
        )
        role = Role.objects.create(
            name="Inventory Role",
            tenant=self.tenant,
        )
        role.access.create(permission=default_perm, tenant=self.tenant)

        # Step 2: Migrate and verify binding to default workspace
        relationships, mappings = migrate_role(role, self.default_workspace)

        self.assertEqual(len(mappings), 1)
        initial_mapping = mappings[0]
        self.assertEqual(initial_mapping.resource_type_namespace, "rbac")
        self.assertEqual(initial_mapping.resource_type_name, "workspace")
        self.assertEqual(initial_mapping.resource_id, str(self.default_workspace.id))

        # Save the initial mapping to database
        initial_mapping.save()

        # Step 3: Update role to add ROOT-scoped permission
        root_perm, _ = Permission.objects.get_or_create(
            permission="advisor:recommendation:read",
            tenant=self.tenant,
        )
        role.access.create(permission=root_perm, tenant=self.tenant)

        # Step 4: Re-migrate and verify binding changed to root workspace
        relationships, updated_mappings = migrate_role(
            role, self.default_workspace, current_bindings=BindingMapping.objects.filter(role=role)
        )

        # Should still be 1 mapping (single binding for the role's permissions)
        self.assertEqual(len(updated_mappings), 1)
        updated_mapping = updated_mappings[0]

        # Verify it's now bound to root workspace (highest scope)
        self.assertEqual(updated_mapping.resource_type_namespace, "rbac")
        self.assertEqual(updated_mapping.resource_type_name, "workspace")
        self.assertEqual(updated_mapping.resource_id, str(self.root_workspace.id))

        # Verify it's a different resource than before
        self.assertNotEqual(updated_mapping.resource_id, initial_mapping.resource_id)

    @override_settings(
        REPLICATION_TO_RELATION_ENABLED=True,
        ROOT_SCOPE_PERMISSIONS="",  # Initially empty - no ROOT scope permissions
        TENANT_SCOPE_PERMISSIONS="",
        ROLE_CREATE_ALLOW_LIST="app",
    )
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_role_with_scope_update_creates_bindings_to_both_scopes(self, mock_replicate):
        """
        Test that updating role after scope changes creates cumulative bindings.

        Scenario (Cascading Scope Changes):
        1. Create role with 'app' permissions (DEFAULT scope → default workspace)
        2. Verify binding to default workspace only
        3. Change settings to make 'app' ROOT scope
        4. Update the role → verify 2 bindings (DEFAULT + ROOT)
        5. Change settings AGAIN to make 'app' TENANT scope
        6. Update the role → verify 3 bindings (DEFAULT + ROOT + TENANT)

        This validates that bindings accumulate as scope configuration evolves,
        providing backward compatibility across configuration changes.
        """
        # Set up InMemoryTuples for tracking relations
        self.tuples = InMemoryTuples()
        self.replicator = InMemoryRelationReplicator(self.tuples)
        mock_replicate.side_effect = self.replicator.replicate

        # Create app permissions
        app_perm_read, _ = Permission.objects.get_or_create(
            permission="app:resource:read",
            tenant=self.tenant,
        )
        app_perm_write, _ = Permission.objects.get_or_create(
            permission="app:resource:write",
            tenant=self.tenant,
        )

        # Step 1: Create role with app permissions (DEFAULT scope initially)
        role_data = {
            "name": "TestRole",
            "display_name": "Test Role for Dual Binding",
            "access": [{"permission": "app:resource:read", "resourceDefinitions": []}],
        }

        url = reverse("v1_management:role-list")
        client = APIClient()
        response = client.post(url, role_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)

        # Assign role to a group to create binding
        test_group = Group.objects.create(name="TestGroup", tenant=self.tenant)
        policy = test_group.policies.create(name="TestPolicy", tenant=self.tenant)
        policy.roles.add(role)

        # Step 2: Verify initial binding to default workspace
        default_workspace_bindings = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(self.default_workspace.id)),
                relation("binding"),
            )
        )

        self.assertGreater(
            len(default_workspace_bindings),
            0,
            "Should have binding to default workspace initially",
        )

        # Verify no binding to root workspace yet
        root_workspace_bindings = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(self.root_workspace.id)),
                relation("binding"),
            )
        )

        self.assertEqual(
            len(root_workspace_bindings),
            0,
            "Should not have binding to root workspace initially",
        )

        # Step 3: Change settings to make 'app' ROOT scope
        with override_settings(ROOT_SCOPE_PERMISSIONS="app:*:*", TENANT_SCOPE_PERMISSIONS=""):
            from django.conf import settings
            from management.permission.scope_service import ImplicitResourceService, Scope

            # Step 4: Update the role to trigger migration logic
            updated_role_data = {
                "name": "TestRole",
                "display_name": "Test Role for Dual Binding - Updated",
                "access": [
                    {"permission": "app:resource:read", "resourceDefinitions": []},
                    {"permission": "app:resource:write", "resourceDefinitions": []},
                ],
            }

            update_url = reverse("v1_management:role-detail", kwargs={"uuid": role_uuid})
            update_response = client.put(update_url, updated_role_data, format="json", **self.headers)
            self.assertEqual(update_response.status_code, status.HTTP_200_OK)

            default_workspace_bindings_after = self.tuples.find_tuples(
                all_of(
                    resource("rbac", "workspace", str(self.default_workspace.id)),
                    relation("binding"),
                )
            )

            root_workspace_bindings_after = self.tuples.find_tuples(
                all_of(
                    resource("rbac", "workspace", str(self.root_workspace.id)),
                    relation("binding"),
                )
            )

            has_default = len(default_workspace_bindings_after) > 0
            has_root = len(root_workspace_bindings_after) > 0

            # Verify dual bindings exist - both default and root workspace bindings should be present
            if has_default and has_root:
                # Success: Both bindings exist (dual binding behavior)
                self.assertEqual(len(default_workspace_bindings_after) + len(root_workspace_bindings_after), 2)
            else:
                self.fail(f"Expected both DEFAULT and ROOT bindings, got DEFAULT={has_default}, ROOT={has_root}")

        # Step 6: Change settings AGAIN to make 'app' TENANT scope
        with override_settings(ROOT_SCOPE_PERMISSIONS="", TENANT_SCOPE_PERMISSIONS="app:*:*"):
            # Step 7: Update the role again (remove app:resource:write)
            updated_role_data2 = {
                "name": "TestRole",
                "display_name": "Test Role for Dual Binding - Updated Again",
                "access": [
                    {"permission": "app:resource:read", "resourceDefinitions": []},
                ],
            }

            update_response2 = client.put(update_url, updated_role_data2, format="json", **self.headers)
            self.assertEqual(update_response2.status_code, status.HTTP_200_OK)

            # Step 8: Verify THREE bindings now exist
            # Get tenant resource ID
            tenant_resource_id = f"{settings.PRINCIPAL_USER_DOMAIN}/{self.tenant.org_id}"
            tenant_bindings = self.tuples.find_tuples(
                all_of(
                    resource("rbac", "tenant", tenant_resource_id),
                    relation("binding"),
                )
            )

            default_bindings_final = self.tuples.find_tuples(
                all_of(
                    resource("rbac", "workspace", str(self.default_workspace.id)),
                    relation("binding"),
                )
            )

            root_bindings_final = self.tuples.find_tuples(
                all_of(
                    resource("rbac", "workspace", str(self.root_workspace.id)),
                    relation("binding"),
                )
            )

            has_tenant = len(tenant_bindings) > 0
            has_default_final = len(default_bindings_final) > 0
            has_root_final = len(root_bindings_final) > 0

            # Step 8: Verify THREE bindings exist (cascade of scope changes: DEFAULT → ROOT → TENANT)
            self.assertTrue(has_default_final, "DEFAULT workspace binding should still exist")
            self.assertTrue(has_root_final, "ROOT workspace binding should still exist")
            self.assertTrue(has_tenant, "TENANT binding should now exist")

            # Verify we have exactly 3 bindings total
            total_bindings = len(default_bindings_final) + len(root_bindings_final) + len(tenant_bindings)
            self.assertEqual(
                total_bindings, 3, f"Expected 3 bindings (DEFAULT + ROOT + TENANT), but got {total_bindings}"
            )


@override_settings(
    ROOT_SCOPE_PERMISSIONS="advisor:*:*,vulnerability:*:*,drift:*:*",
    TENANT_SCOPE_PERMISSIONS="rbac:*:*,cost-management:*:*",
)
class ScopeServiceUnitTests(TestCase):
    """Unit tests for the scope service."""

    def test_scope_service_tenant_permissions(self):
        """Test that tenant scope permissions are correctly identified."""
        service = ImplicitResourceService.from_settings()

        self.assertEqual(service.scope_for_permission("rbac:role:read"), Scope.TENANT)
        self.assertEqual(service.scope_for_permission("rbac:group:write"), Scope.TENANT)
        self.assertEqual(service.scope_for_permission("cost-management:report:read"), Scope.TENANT)

    def test_scope_service_root_permissions(self):
        """Test that root scope permissions are correctly identified."""
        service = ImplicitResourceService.from_settings()

        self.assertEqual(service.scope_for_permission("advisor:recommendation:read"), Scope.ROOT)
        self.assertEqual(service.scope_for_permission("vulnerability:cve:read"), Scope.ROOT)
        self.assertEqual(service.scope_for_permission("drift:baseline:write"), Scope.ROOT)

    def test_scope_service_default_permissions(self):
        """Test that default scope permissions are correctly identified."""
        service = ImplicitResourceService.from_settings()

        self.assertEqual(service.scope_for_permission("inventory:host:read"), Scope.DEFAULT)
        self.assertEqual(service.scope_for_permission("patch:advisory:read"), Scope.DEFAULT)

    def test_highest_scope_for_mixed_permissions(self):
        """Test that highest_scope_for_permissions returns the highest scope."""
        service = ImplicitResourceService.from_settings()

        # Mix of all scopes should return TENANT
        scope = service.highest_scope_for_permissions(
            [
                "inventory:host:read",  # DEFAULT
                "advisor:recommendation:read",  # ROOT
                "rbac:role:read",  # TENANT
            ]
        )
        self.assertEqual(scope, Scope.TENANT)

        # Mix of DEFAULT and ROOT should return ROOT
        scope = service.highest_scope_for_permissions(
            [
                "inventory:host:read",  # DEFAULT
                "advisor:recommendation:read",  # ROOT
            ]
        )
        self.assertEqual(scope, Scope.ROOT)

        # Only DEFAULT should return DEFAULT
        scope = service.highest_scope_for_permissions(
            [
                "inventory:host:read",  # DEFAULT
                "patch:advisory:read",  # DEFAULT
            ]
        )
        self.assertEqual(scope, Scope.DEFAULT)

    def test_v2_bound_resource_for_permission(self):
        """Test that v2_bound_resource_for_permission returns correct resource."""
        service = ImplicitResourceService.from_settings()

        tenant_org_id = "123456"
        root_workspace_id = "root-uuid"
        default_workspace_id = "default-uuid"

        # Test tenant scope
        resource = service.v2_bound_resource_for_permission(
            ["rbac:role:read"],
            tenant_org_id=tenant_org_id,
            root_workspace_id=root_workspace_id,
            default_workspace_id=default_workspace_id,
        )
        self.assertEqual(resource.resource_type, ("rbac", "tenant"))
        self.assertIn(tenant_org_id, resource.resource_id)

        # Test root scope
        resource = service.v2_bound_resource_for_permission(
            ["advisor:recommendation:read"],
            tenant_org_id=tenant_org_id,
            root_workspace_id=root_workspace_id,
            default_workspace_id=default_workspace_id,
        )
        self.assertEqual(resource.resource_type, ("rbac", "workspace"))
        self.assertEqual(resource.resource_id, root_workspace_id)

        # Test default scope
        resource = service.v2_bound_resource_for_permission(
            ["inventory:host:read"],
            tenant_org_id=tenant_org_id,
            root_workspace_id=root_workspace_id,
            default_workspace_id=default_workspace_id,
        )
        self.assertEqual(resource.resource_type, ("rbac", "workspace"))
        self.assertEqual(resource.resource_id, default_workspace_id)


@override_settings(
    REPLICATION_TO_RELATION_ENABLED=True,
    PRINCIPAL_USER_DOMAIN="redhat",
    ROOT_SCOPE_PERMISSIONS="advisor:*:*,vulnerability:*:*,drift:*:*",
    TENANT_SCOPE_PERMISSIONS="rbac:*:*,cost-management:*:*",
)
class ScopeBasedDualWriteTests(IdentityRequest):
    """Tests for scope-based binding in dual write handler."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        # Create workspaces for the tenant
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

        # Create tenant mapping (required by RelationApiDualWriteSubjectHandler)
        from management.tenant_mapping.model import TenantMapping

        self.tenant_mapping, _ = TenantMapping.objects.get_or_create(tenant=self.tenant)

    def tearDown(self):
        """Tear down test data."""
        # Update all workspaces to remove parent references first
        Workspace.objects.all().update(parent=None)
        Workspace.objects.all().delete()
        super().tearDown()

    def create_system_role_with_permissions(self, name, permissions):
        """Helper to create a system role with given permissions."""
        from api.models import Tenant

        public_tenant, _ = Tenant.objects.get_or_create(tenant_name="public")

        role = Role.objects.create(
            name=name,
            system=True,
            tenant=public_tenant,
        )
        for perm_str in permissions:
            perm, _ = Permission.objects.get_or_create(
                permission=perm_str,
                tenant=public_tenant,
            )
            role.access.create(permission=perm, tenant=public_tenant)
        return role

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_system_role_tenant_scope_binds_to_tenant(self, mock_replicate):
        """Test that system roles with tenant-scoped permissions bind to tenant."""
        # Create a system role with tenant-scoped permissions
        role = self.create_system_role_with_permissions(
            "Tenant Admin", ["rbac:role:read", "rbac:group:write", "cost-management:report:read"]
        )

        # Create a group and assign the role
        group = Group.objects.create(
            name="Test Group",
            tenant=self.tenant,
        )

        # Use the dual write handler to assign the role
        handler = RelationApiDualWriteGroupHandler(
            group=group,
            event_type=ReplicationEventType.ASSIGN_ROLE,
            replicator=LoggingReplicator(),
        )
        handler.generate_relations_to_add_roles([role])

        # Check that binding was created for tenant, not workspace
        binding = BindingMapping.objects.filter(role=role).first()
        self.assertIsNotNone(binding)
        self.assertEqual(binding.resource_type_namespace, "rbac")
        self.assertEqual(binding.resource_type_name, "tenant")
        self.assertIn(self.tenant.org_id, binding.resource_id)

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_system_role_root_scope_binds_to_root_workspace(self, mock_replicate):
        """Test that system roles with root-scoped permissions bind to root workspace."""
        # Create a system role with root-scoped permissions
        role = self.create_system_role_with_permissions(
            "Advisor User", ["advisor:recommendation:read", "vulnerability:cve:read"]
        )

        # Create a group and assign the role
        group = Group.objects.create(
            name="Test Group",
            tenant=self.tenant,
        )

        # Use the dual write handler to assign the role
        handler = RelationApiDualWriteGroupHandler(
            group=group,
            event_type=ReplicationEventType.ASSIGN_ROLE,
            replicator=LoggingReplicator(),
        )
        handler.generate_relations_to_add_roles([role])

        # Check that binding was created for root workspace
        binding = BindingMapping.objects.filter(role=role).first()
        self.assertIsNotNone(binding)
        self.assertEqual(binding.resource_type_namespace, "rbac")
        self.assertEqual(binding.resource_type_name, "workspace")
        self.assertEqual(binding.resource_id, str(self.root_workspace.id))

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_system_role_default_scope_binds_to_default_workspace(self, mock_replicate):
        """Test that system roles with default-scoped permissions bind to default workspace."""
        # Create a system role with default-scoped permissions
        role = self.create_system_role_with_permissions(
            "Inventory User", ["inventory:host:read", "patch:advisory:read"]
        )

        # Create a group and assign the role
        group = Group.objects.create(
            name="Test Group",
            tenant=self.tenant,
        )

        # Use the dual write handler to assign the role
        handler = RelationApiDualWriteGroupHandler(
            group=group,
            event_type=ReplicationEventType.ASSIGN_ROLE,
            replicator=LoggingReplicator(),
        )
        handler.generate_relations_to_add_roles([role])

        # Check that binding was created for default workspace
        binding = BindingMapping.objects.filter(role=role).first()
        self.assertIsNotNone(binding)
        self.assertEqual(binding.resource_type_namespace, "rbac")
        self.assertEqual(binding.resource_type_name, "workspace")
        self.assertEqual(binding.resource_id, str(self.default_workspace.id))

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_system_role_mixed_scope_binds_to_highest_scope(self, mock_replicate):
        """Test that system roles with mixed permissions bind to highest scope."""
        # Create a system role with mixed permissions (all scopes)
        role = self.create_system_role_with_permissions(
            "Mixed Scope Role",
            [
                "inventory:host:read",  # DEFAULT
                "advisor:recommendation:read",  # ROOT
                "rbac:role:read",  # TENANT
            ],
        )

        # Create a group and assign the role
        group = Group.objects.create(
            name="Test Group",
            tenant=self.tenant,
        )

        # Use the dual write handler to assign the role
        handler = RelationApiDualWriteGroupHandler(
            group=group,
            event_type=ReplicationEventType.ASSIGN_ROLE,
            replicator=LoggingReplicator(),
        )
        handler.generate_relations_to_add_roles([role])

        # Check that binding was created for tenant (highest scope)
        binding = BindingMapping.objects.filter(role=role).first()
        self.assertIsNotNone(binding)
        self.assertEqual(binding.resource_type_namespace, "rbac")
        self.assertEqual(binding.resource_type_name, "tenant")
        self.assertIn(self.tenant.org_id, binding.resource_id)
