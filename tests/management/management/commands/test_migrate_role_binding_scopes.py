from django.test import TestCase
from django.conf import settings

from api.models import Tenant
from management.models import BindingMapping, Role, Workspace, Access, Permission
from management.management.commands.migrate_role_binding_scopes import Command


class TestMigrateRoleBindingScopesCommand(TestCase):
    """Test the migrate_role_binding_scopes management command."""

    def setUp(self):
        """Set up test data."""
        self.command = Command()

        # Create a test tenant
        self.tenant = Tenant.objects.create(tenant_name="test-tenant", org_id="12345")

        # Create workspaces for the tenant (root first, then default with root as parent)
        self.root_workspace = Workspace.objects.create(
            name="Root Workspace",
            description="Root workspace for tenant",
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
        )

        self.default_workspace = Workspace.objects.create(
            name="Default Workspace",
            description="Default workspace for tenant",
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            parent=self.root_workspace,
        )

        # Create test roles with different permission scopes
        self.default_scope_role = Role.objects.create(
            name="Default Scope Role",
            description="Role with default workspace permissions",
            tenant=self.tenant,
            system=True,
        )

        self.root_scope_role = Role.objects.create(
            name="Root Scope Role", description="Role with root workspace permissions", tenant=self.tenant, system=True
        )

        self.tenant_scope_role = Role.objects.create(
            name="Tenant Scope Role", description="Role with tenant-level permissions", tenant=self.tenant, system=True
        )

        # Create custom role for testing mappings-based permissions
        self.custom_role = Role.objects.create(
            name="Custom Role",
            description="Custom role with permissions in mappings",
            tenant=self.tenant,
            system=False,
        )

    def _create_permission_and_access(self, role, permission_string):
        """Helper method to create Permission and Access objects for system roles."""
        # Permissions must use the public tenant
        public_tenant = Tenant.objects.get(tenant_name="public")

        permission, _ = Permission.objects.get_or_create(permission=permission_string, tenant=public_tenant)
        access = Access.objects.create(
            permission=permission, role=role, tenant=role.tenant  # Access uses the role's tenant
        )
        return access

    def test_migrate_default_workspace_binding_to_root(self):
        """Test migrating a default workspace binding to root workspace based on permissions."""
        # Create Access objects for system role with root-level permissions
        self._create_permission_and_access(self.root_scope_role, "advisor:recommendation:read")
        self._create_permission_and_access(self.root_scope_role, "advisor:system:read")

        # Create a binding mapping currently bound to default workspace
        binding_mapping = BindingMapping.objects.create(
            role=self.root_scope_role,
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
            mappings={},  # System roles don't use mappings
        )

        # Run the migration with small batch size
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Refresh from database
        binding_mapping.refresh_from_db()

        # Assert binding was migrated to root workspace
        self.assertEqual(binding_mapping.resource_type_namespace, "rbac")
        self.assertEqual(binding_mapping.resource_type_name, "workspace")
        self.assertEqual(binding_mapping.resource_id, str(self.root_workspace.id))

    def test_migrate_default_workspace_binding_to_tenant(self):
        """Test migrating a default workspace binding to tenant level based on permissions."""
        # Create Access objects for system role with tenant-level permissions
        self._create_permission_and_access(self.tenant_scope_role, "rbac:principal:read")
        self._create_permission_and_access(self.tenant_scope_role, "rbac:role:write")

        # Create a binding mapping currently bound to default workspace
        binding_mapping = BindingMapping.objects.create(
            role=self.tenant_scope_role,
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
            mappings={},  # System roles don't use mappings
        )

        # Run the migration with small batch size
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Refresh from database
        binding_mapping.refresh_from_db()

        # Assert binding was migrated to tenant level
        expected_tenant_id = f"{settings.PRINCIPAL_USER_DOMAIN}/{self.tenant.org_id}"
        self.assertEqual(binding_mapping.resource_type_namespace, "rbac")
        self.assertEqual(binding_mapping.resource_type_name, "tenant")
        self.assertEqual(binding_mapping.resource_id, expected_tenant_id)

    def test_keep_default_workspace_binding_for_default_scope_permissions(self):
        """Test that default workspace bindings with default-level permissions remain unchanged."""
        # Create Access objects for system role with default-level permissions
        self._create_permission_and_access(self.default_scope_role, "inventory:groups:read")
        self._create_permission_and_access(self.default_scope_role, "inventory:hosts:write")

        # Create a binding mapping currently bound to default workspace
        binding_mapping = BindingMapping.objects.create(
            role=self.default_scope_role,
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
            mappings={},  # System roles don't use mappings
        )

        original_resource_id = binding_mapping.resource_id

        # Run the migration
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Refresh from database
        binding_mapping.refresh_from_db()

        # Assert binding remained at default workspace
        self.assertEqual(binding_mapping.resource_type_namespace, "rbac")
        self.assertEqual(binding_mapping.resource_type_name, "workspace")
        self.assertEqual(binding_mapping.resource_id, original_resource_id)

    def test_skip_non_default_workspace_bindings(self):
        """Test that bindings not pointing to default workspace are skipped."""
        # Create a binding mapping bound to root workspace (should be skipped)
        binding_mapping = BindingMapping.objects.create(
            role=self.root_scope_role,
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.root_workspace.id),  # Already bound to root
            mappings={"role": {"permissions": ["rbac_principal_read"]}},  # Even with tenant-level permissions
        )

        original_resource_id = binding_mapping.resource_id

        # Run the migration
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Refresh from database
        binding_mapping.refresh_from_db()

        # Assert binding was not changed (still bound to root workspace)
        self.assertEqual(binding_mapping.resource_id, original_resource_id)

    def test_mixed_permission_scopes_uses_highest_scope(self):
        """Test that role with mixed permission scopes gets bound to the highest scope."""
        # Create Access objects for system role with mixed permission levels
        self._create_permission_and_access(self.root_scope_role, "inventory:groups:read")  # Default level
        self._create_permission_and_access(
            self.root_scope_role, "advisor:recommendation:read"
        )  # Root level - this should win
        self._create_permission_and_access(self.root_scope_role, "patch:system:read")  # Default level

        # Create a binding with both default and root level permissions
        # Should be migrated to root workspace (highest scope)
        binding_mapping = BindingMapping.objects.create(
            role=self.root_scope_role,
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
            mappings={},  # System roles don't use mappings
        )

        # Run the migration
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Refresh from database
        binding_mapping.refresh_from_db()

        # Assert binding was migrated to root workspace (highest scope)
        self.assertEqual(binding_mapping.resource_type_namespace, "rbac")
        self.assertEqual(binding_mapping.resource_type_name, "workspace")
        self.assertEqual(binding_mapping.resource_id, str(self.root_workspace.id))

    def test_binding_without_permissions_kept_default(self):
        """Test that bindings without permissions remain at default workspace."""
        # Create a binding mapping with no permissions (system role with no Access objects)
        binding_mapping = BindingMapping.objects.create(
            role=self.default_scope_role,
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
            mappings={},  # System roles don't use mappings, and no Access objects created
        )

        original_resource_id = binding_mapping.resource_id

        # Run the migration
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Refresh from database
        binding_mapping.refresh_from_db()

        # Assert binding remained at default workspace
        self.assertEqual(binding_mapping.resource_id, original_resource_id)

    def test_custom_role_with_mappings_migrated_to_root(self):
        """Test that custom roles with permissions in mappings are migrated correctly."""
        # Create a binding mapping for custom role with root-level permissions in mappings
        binding_mapping = BindingMapping.objects.create(
            role=self.custom_role,
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.default_workspace.id),
            mappings={
                "role": {
                    "permissions": [
                        "advisor_recommendation_read",  # Root level permission in V2 format
                        "advisor_system_read",
                    ]
                }
            },
        )

        # Run the migration
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Refresh from database
        binding_mapping.refresh_from_db()

        # Assert binding was migrated to root workspace
        self.assertEqual(binding_mapping.resource_type_namespace, "rbac")
        self.assertEqual(binding_mapping.resource_type_name, "workspace")
        self.assertEqual(binding_mapping.resource_id, str(self.root_workspace.id))

    def test_batch_processing_efficiency(self):
        """Test that batch processing handles multiple bindings efficiently."""
        # Create multiple binding mappings for different tenants
        tenant2 = Tenant.objects.create(tenant_name="test-tenant-2", org_id="67890")

        root_workspace2 = Workspace.objects.create(
            name="Root Workspace 2",
            description="Root workspace for tenant 2",
            tenant=tenant2,
            type=Workspace.Types.ROOT,
        )

        default_workspace2 = Workspace.objects.create(
            name="Default Workspace 2",
            description="Default workspace for tenant 2",
            tenant=tenant2,
            type=Workspace.Types.DEFAULT,
            parent=root_workspace2,
        )

        role2 = Role.objects.create(name="Role 2", description="Role for tenant 2", tenant=tenant2, system=True)

        # Create permissions for both roles
        self._create_permission_and_access(self.root_scope_role, "advisor:recommendation:read")

        # Create permission for role2 (permissions use public tenant, access uses role's tenant)
        public_tenant = Tenant.objects.get(tenant_name="public")
        permission2, _ = Permission.objects.get_or_create(
            permission="advisor:recommendation:read", tenant=public_tenant
        )
        Access.objects.create(permission=permission2, role=role2, tenant=tenant2)

        # Create bindings for both tenants
        bindings = []
        for i, (tenant, workspace, role) in enumerate(
            [(self.tenant, self.default_workspace, self.root_scope_role), (tenant2, default_workspace2, role2)]
        ):
            binding = BindingMapping.objects.create(
                role=role,
                resource_type_namespace="rbac",
                resource_type_name="workspace",
                resource_id=str(workspace.id),
                mappings={},  # System roles don't use mappings
            )
            bindings.append(binding)

        # Run migration with batch size of 1 to test batching
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Verify both bindings were migrated to their respective root workspaces
        for i, binding in enumerate(bindings):
            binding.refresh_from_db()
            expected_root_workspace = self.root_workspace if i == 0 else root_workspace2
            self.assertEqual(binding.resource_type_name, "workspace")
            self.assertEqual(binding.resource_id, str(expected_root_workspace.id))
