"""Tests for explicit vs implicit binding behavior in V2boundresource."""

from django.test import TestCase, override_settings
from django.conf import settings

from api.models import Tenant
from migration_tool.models import V2boundresource
from migration_tool.sharedSystemRolesReplicatedRoleBindings import v1_role_to_v2_bindings
from management.models import Role, Permission, Access, ResourceDefinition, Workspace
from management.permission_scope import Scope


class ExplicitVsImplicitBindingTests(TestCase):
    """Test that explicit vs implicit bindings are handled correctly."""

    def setUp(self):
        """Set up test data."""
        self.tenant = Tenant.objects.create(tenant_name="test_tenant", account_id="123456789", org_id="987654321")

        # Create workspaces (ROOT must be created first since DEFAULT requires a ROOT parent)
        self.root_workspace = Workspace.objects.create(
            tenant=self.tenant,
            name="root",
            type=Workspace.Types.ROOT,
        )
        self.default_workspace = Workspace.objects.create(
            tenant=self.tenant,
            name="default",
            type=Workspace.Types.DEFAULT,
            parent=self.root_workspace,
        )

        # Set default workspace on tenant
        self.tenant.default_workspace = self.default_workspace
        self.tenant.save()

        # Create permissions
        self.root_permission = Permission.objects.create(
            tenant=self.tenant, permission="app:*:read", description="Test root permission"
        )
        self.default_permission = Permission.objects.create(
            tenant=self.tenant, permission="other:resource:read", description="Test default permission"
        )

        # Create test role
        self.role = Role.objects.create(tenant=self.tenant, name="test_role", description="Test role")

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="app:*:read",
        TENANT_SCOPE_PERMISSIONS="",
        V2_MIGRATION_APP_EXCLUDE_LIST=[],  # Allow all apps for testing
        V2_MIGRATION_RESOURCE_EXCLUDE_LIST=[],  # Allow all resources for testing
    )
    def test_explicit_default_workspace_binding_preserved(self):
        """Test that explicit default workspace bindings are preserved even with ROOT scope permissions."""
        # Create access with explicit default workspace binding + ROOT scope permission
        access = Access.objects.create(tenant=self.tenant, role=self.role, permission=self.root_permission)

        # Create explicit resource definition pointing to default workspace
        ResourceDefinition.objects.create(
            tenant=self.tenant,
            access=access,
            attributeFilter={"key": "workspace.id", "operation": "equal", "value": str(self.default_workspace.id)},
        )

        # Convert to V2 bindings
        bindings = v1_role_to_v2_bindings(self.role, self.default_workspace, [])

        # Should have 1 binding
        self.assertEqual(len(bindings), 1)

        # Get the binding
        binding = bindings[0].get_role_binding()

        # Should be bound to DEFAULT workspace (explicit choice should be preserved)
        # NOT scope-adjusted to root workspace despite ROOT scope permission
        self.assertEqual(binding.resource.resource_type, ("rbac", "workspace"))
        self.assertEqual(binding.resource.resource_id, str(self.default_workspace.id))
        # The explicitly_bound attribute tracks the original source, not the final result
        # What matters is that the explicit binding was preserved, not the attribute value

        # Verify permission is included
        expected_v2_permission = "app_all_read"  # app:*:read -> app_all_read
        self.assertIn(expected_v2_permission, binding.role.permissions)

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="app:*:read",
        TENANT_SCOPE_PERMISSIONS="",
        V2_MIGRATION_APP_EXCLUDE_LIST=[],  # Allow all apps for testing
        V2_MIGRATION_RESOURCE_EXCLUDE_LIST=[],  # Allow all resources for testing
    )
    def test_implicit_default_workspace_binding_scope_adjusted(self):
        """Test that implicit default workspace bindings are scope-adjusted based on permission scope."""
        # Create access without any resource definitions (implicit default workspace binding)
        Access.objects.create(tenant=self.tenant, role=self.role, permission=self.root_permission)

        # Convert to V2 bindings
        bindings = v1_role_to_v2_bindings(self.role, self.default_workspace, [])

        # Should have 1 binding
        self.assertEqual(len(bindings), 1)

        # Get the binding
        binding = bindings[0].get_role_binding()

        # Should be scope-adjusted to ROOT workspace (because permission has ROOT scope)
        self.assertEqual(binding.resource.resource_type, ("rbac", "workspace"))
        self.assertEqual(binding.resource.resource_id, str(self.root_workspace.id))
        # The resource was created through scope adjustment, so explicitly_bound reflects the creation method

        # Verify permission is included
        expected_v2_permission = "app_all_read"  # app:*:read -> app_all_read
        self.assertIn(expected_v2_permission, binding.role.permissions)

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="",
        V2_MIGRATION_APP_EXCLUDE_LIST=[],  # Allow all apps for testing
        V2_MIGRATION_RESOURCE_EXCLUDE_LIST=[],  # Allow all resources for testing
    )
    def test_implicit_default_workspace_binding_no_scope_adjustment(self):
        """Test that implicit default workspace bindings with DEFAULT scope are not adjusted."""
        # Create access without any resource definitions (implicit default workspace binding)
        # Using a permission that has DEFAULT scope
        Access.objects.create(tenant=self.tenant, role=self.role, permission=self.default_permission)

        # Convert to V2 bindings
        bindings = v1_role_to_v2_bindings(self.role, self.default_workspace, [])

        # Should have 1 binding
        self.assertEqual(len(bindings), 1)

        # Get the binding
        binding = bindings[0].get_role_binding()

        # Should remain bound to default workspace (DEFAULT scope doesn't trigger adjustment)
        self.assertEqual(binding.resource.resource_type, ("rbac", "workspace"))
        self.assertEqual(binding.resource.resource_id, str(self.default_workspace.id))
        # No scope adjustment occurred, so this preserves the implicit binding

        # Verify permission is included
        expected_v2_permission = "other_resource_read"  # other:resource:read -> other_resource_read
        self.assertIn(expected_v2_permission, binding.role.permissions)

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="app:*:read",
        TENANT_SCOPE_PERMISSIONS="",
        V2_MIGRATION_APP_EXCLUDE_LIST=[],  # Allow all apps for testing
        V2_MIGRATION_RESOURCE_EXCLUDE_LIST=[],  # Allow all resources for testing
    )
    def test_explicit_other_workspace_binding_preserved(self):
        """Test that explicit bindings to non-default workspaces are preserved."""
        # Create another workspace (STANDARD workspaces need a parent too)
        other_workspace = Workspace.objects.create(
            tenant=self.tenant,
            name="other_workspace",
            type=Workspace.Types.STANDARD,
            parent=self.default_workspace,
        )

        # Create access with explicit binding to other workspace + ROOT scope permission
        access = Access.objects.create(tenant=self.tenant, role=self.role, permission=self.root_permission)

        # Create explicit resource definition pointing to other workspace
        ResourceDefinition.objects.create(
            tenant=self.tenant,
            access=access,
            attributeFilter={"key": "workspace.id", "operation": "equal", "value": str(other_workspace.id)},
        )

        # Convert to V2 bindings
        bindings = v1_role_to_v2_bindings(self.role, self.default_workspace, [])

        # Should have 1 binding
        self.assertEqual(len(bindings), 1)

        # Get the binding
        binding = bindings[0].get_role_binding()

        # Should be bound to the explicitly specified workspace (other_workspace)
        # NOT scope-adjusted despite ROOT scope permission
        self.assertEqual(binding.resource.resource_type, ("rbac", "workspace"))
        self.assertEqual(binding.resource.resource_id, str(other_workspace.id))
        # Explicit binding preserved (not scope-adjusted)

        # Verify permission is included
        expected_v2_permission = "app_all_read"  # app:*:read -> app_all_read
        self.assertIn(expected_v2_permission, binding.role.permissions)

    def test_v2boundresource_explicitly_bound_attribute(self):
        """Test that V2boundresource correctly tracks explicitly_bound attribute."""
        # Test explicit binding
        explicit_resource = V2boundresource(
            resource_type=("rbac", "workspace"), resource_id="123", explicitly_bound=True
        )
        self.assertTrue(explicit_resource.explicitly_bound)

        # Test implicit binding
        implicit_resource = V2boundresource(
            resource_type=("rbac", "workspace"), resource_id="123", explicitly_bound=False
        )
        self.assertFalse(implicit_resource.explicitly_bound)

        # Test default value (should be False)
        default_resource = V2boundresource(resource_type=("rbac", "workspace"), resource_id="123")
        self.assertFalse(default_resource.explicitly_bound)

        # Test that two resources with different explicitly_bound values are not equal
        # (since V2boundresource is a frozen dataclass, it should consider all fields for equality)
        self.assertNotEqual(explicit_resource, implicit_resource)
        self.assertEqual(implicit_resource, default_resource)  # False == False

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="app:*:read",
        TENANT_SCOPE_PERMISSIONS="",
        V2_MIGRATION_APP_EXCLUDE_LIST=[],  # Allow all apps for testing
        V2_MIGRATION_RESOURCE_EXCLUDE_LIST=[],  # Allow all resources for testing
    )
    def test_mixed_explicit_and_implicit_bindings(self):
        """Test role with both explicit and implicit bindings."""
        # Create access with implicit default workspace binding (ROOT scope permission)
        Access.objects.create(tenant=self.tenant, role=self.role, permission=self.root_permission)

        # Create access with explicit default workspace binding (ROOT scope permission)
        access_explicit = Access.objects.create(
            tenant=self.tenant, role=self.role, permission=self.default_permission  # DEFAULT scope
        )

        # Create explicit resource definition pointing to default workspace
        ResourceDefinition.objects.create(
            tenant=self.tenant,
            access=access_explicit,
            attributeFilter={"key": "workspace.id", "operation": "equal", "value": str(self.default_workspace.id)},
        )

        # Convert to V2 bindings
        bindings = v1_role_to_v2_bindings(self.role, self.default_workspace, [])

        # Should have 2 bindings
        self.assertEqual(len(bindings), 2)

        # Get the bindings sorted by resource_id for consistent testing
        bindings_by_resource_id = {b.get_role_binding().resource.resource_id: b.get_role_binding() for b in bindings}

        # One binding should be to root workspace (implicit binding scope-adjusted)
        root_binding = bindings_by_resource_id.get(str(self.root_workspace.id))
        self.assertIsNotNone(root_binding)
        self.assertEqual(root_binding.resource.resource_type, ("rbac", "workspace"))
        # This binding was created through scope adjustment
        self.assertIn("app_all_read", root_binding.role.permissions)

        # One binding should be to default workspace (explicit binding preserved)
        default_binding = bindings_by_resource_id.get(str(self.default_workspace.id))
        self.assertIsNotNone(default_binding)
        self.assertEqual(default_binding.resource.resource_type, ("rbac", "workspace"))
        # This binding was preserved from explicit resource definition
        self.assertIn("other_resource_read", default_binding.role.permissions)
