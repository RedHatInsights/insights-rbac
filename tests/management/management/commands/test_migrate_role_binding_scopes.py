import uuid
from django.test import TestCase, override_settings
from django.conf import settings
from unittest.mock import patch

from api.models import Tenant
from management.models import BindingMapping, Role, Workspace, Access, Permission
from management.management.commands.migrate_role_binding_scopes import Command
from management.permission_scope import Scope, _implicit_resource_service as permission_service
from migration_tool.in_memory_tuples import (
    InMemoryTuples,
    InMemoryRelationReplicator,
    all_of,
    resource,
    relation,
)
from migration_tool.models import V2role, V2boundresource, V2rolebinding
from migration_tool.utils import create_relationship


@override_settings(ROOT_SCOPE_APPS="advisor,vulnerability,drift", TENANT_SCOPE_APPS="rbac,cost-management")
class TestMigrateRoleBindingScopesCommand(TestCase):
    """Test the migrate_role_binding_scopes management command."""

    def setUp(self):
        """Set up test data."""
        self.command = Command()

        # Set up in-memory tuples for testing
        self.tuples = InMemoryTuples()
        self.replicator = InMemoryRelationReplicator(self.tuples)

        # Create a test tenant
        self.tenant = Tenant.objects.create(tenant_name="test-tenant", org_id="12345")

        # Clean up any existing workspaces for this tenant to ensure clean state
        Workspace.objects.filter(tenant=self.tenant).delete()

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

    def tearDown(self):
        """Clean up test data."""
        self.tuples.clear()

    def _create_permission_and_access(self, role, permission_string):
        """Helper method to create Permission and Access objects for system roles."""
        # Permissions must use the public tenant
        public_tenant = Tenant.objects.get(tenant_name="public")

        permission, _ = Permission.objects.get_or_create(permission=permission_string, tenant=public_tenant)
        return Access.objects.create(
            permission=permission, role=role, tenant=role.tenant  # Access uses the role's tenant
        )

    @patch("management.management.commands.migrate_role_binding_scopes.OutboxReplicator")
    def test_migrate_default_workspace_binding_to_root(self, mock_outbox_replicator):
        """Test migrating a default workspace binding to root workspace based on permissions."""
        # Redirect replication to in-memory store by mocking the OutboxReplicator constructor
        mock_outbox_replicator.return_value = self.replicator

        # Mock the scope functions to return ROOT scope for our test
        with patch(
            "management.management.commands.migrate_role_binding_scopes.permission_service.highest_scope_for_permissions"
        ) as mock_highest_scope:
            # Make the scope function return ROOT scope (value=2) for our advisor permissions
            mock_highest_scope.return_value = Scope.ROOT
            # Create Access objects for system role with root-level permissions
            self._create_permission_and_access(self.root_scope_role, "advisor:recommendation:read")
            self._create_permission_and_access(self.root_scope_role, "advisor:system:read")

            # Create a binding mapping currently bound to default workspace using the proper factory method

            # Create a V2 role for the system role
            v2_role = V2role(
                id=str(self.root_scope_role.uuid),
                is_system=True,
                permissions=frozenset(["advisor:recommendation:read", "advisor:system:read"]),
            )

            # Create a V2 bound resource for the default workspace
            v2_resource = V2boundresource(
                resource_type=("rbac", "workspace"), resource_id=str(self.default_workspace.id)
            )

            # Create a V2 role binding
            v2_rolebinding = V2rolebinding(
                id=str(uuid.uuid4()), role=v2_role, resource=v2_resource, groups=frozenset(), users=frozenset()
            )

            # Create the binding mapping using the factory method
            binding_mapping = BindingMapping.for_role_binding(v2_rolebinding, self.root_scope_role)
            binding_mapping.save()  # Save it to get a primary key

            # Create initial tuples that bind to default workspace using the same method as migration
            # This ensures the tuple format matches exactly what the migration command expects
            initial_tuples = list(binding_mapping.as_tuples())
            self.tuples.write(initial_tuples, [])

            # Verify initial default workspace bindings exist
            initial_default_bindings = self.tuples.find_tuples(
                all_of(resource("rbac", "workspace", str(self.default_workspace.id)), relation("binding"))
            )
            self.assertGreater(len(initial_default_bindings), 0, "Should have initial bindings to default workspace")

            # Run the migration with small batch size
            self.command._migrate_role_binding_scopes(batch_size=1)

            # Check that default workspace bindings are removed after migration
            remaining_default_bindings = self.tuples.find_tuples(
                all_of(resource("rbac", "workspace", str(self.default_workspace.id)), relation("binding"))
            )
            self.assertEqual(
                len(remaining_default_bindings), 0, "Default workspace bindings should be removed after migration"
            )

            # Check that root workspace bindings are created
            new_root_bindings = self.tuples.find_tuples(
                all_of(resource("rbac", "workspace", str(self.root_workspace.id)), relation("binding"))
            )
            self.assertGreater(len(new_root_bindings), 0, "Root workspace bindings should be created after migration")

    @patch("management.management.commands.migrate_role_binding_scopes.OutboxReplicator")
    @override_settings(PRINCIPAL_USER_DOMAIN="redhat")
    def test_migrate_default_workspace_binding_to_tenant(self, mock_outbox_replicator):
        """Test migrating a default workspace binding to tenant level based on permissions."""
        # Redirect replication to in-memory store by mocking the OutboxReplicator constructor
        mock_outbox_replicator.return_value = self.replicator

        # Force service to pick up any settings
        from management.permission_scope import _implicit_resource_service as svc

        svc.refresh_from_settings()

        with patch(
            "management.management.commands.migrate_role_binding_scopes.permission_service.highest_scope_for_permissions"
        ) as mock_highest_scope:
            # Make the scope function return TENANT scope for rbac permissions
            mock_highest_scope.return_value = Scope.TENANT

            # Create Access objects for system role with tenant-level permissions
            self._create_permission_and_access(self.tenant_scope_role, "rbac:principal:read")
            self._create_permission_and_access(self.tenant_scope_role, "rbac:role:write")

            # Create a binding mapping currently bound to default workspace using the proper factory method

            # Create a V2 role for the system role
            v2_role = V2role(
                id=str(self.tenant_scope_role.uuid),
                is_system=True,
                permissions=frozenset(["rbac:principal:read", "rbac:role:write"]),
            )

            # Create a V2 bound resource for the default workspace
            v2_resource = V2boundresource(
                resource_type=("rbac", "workspace"), resource_id=str(self.default_workspace.id)
            )

            # Create a V2 role binding
            v2_rolebinding = V2rolebinding(
                id=str(uuid.uuid4()), role=v2_role, resource=v2_resource, groups=frozenset(), users=frozenset()
            )

            # Create the binding mapping using the factory method
            binding_mapping = BindingMapping.for_role_binding(v2_rolebinding, self.tenant_scope_role)
            binding_mapping.save()  # Save it to get a primary key

            # Run the migration with small batch size
            self.command._migrate_role_binding_scopes(batch_size=1)

            # Refresh from database
            binding_mapping.refresh_from_db()

            # Assert binding was migrated to tenant level
            expected_tenant_id = f"{settings.PRINCIPAL_USER_DOMAIN}/{self.tenant.org_id}"
            self.assertEqual(binding_mapping.resource_type_namespace, "rbac")
            self.assertEqual(binding_mapping.resource_type_name, "tenant")
            self.assertEqual(binding_mapping.resource_id, expected_tenant_id)

    @patch("management.management.commands.migrate_role_binding_scopes.OutboxReplicator")
    def test_keep_default_workspace_binding_for_default_scope_permissions(self, mock_outbox_replicator):
        """Test that default workspace bindings with default-level permissions remain unchanged."""
        # Redirect replication to in-memory store by mocking the OutboxReplicator constructor
        mock_outbox_replicator.return_value = self.replicator

        with patch(
            "management.management.commands.migrate_role_binding_scopes.permission_service.highest_scope_for_permissions"
        ) as mock_highest_scope:
            # Make the scope function return DEFAULT scope (no migration should happen)
            mock_highest_scope.return_value = Scope.DEFAULT

            # Create Access objects for system role with default-level permissions
            self._create_permission_and_access(self.default_scope_role, "inventory:groups:read")
            self._create_permission_and_access(self.default_scope_role, "inventory:hosts:write")

            # Create a V2 role for the system role
            v2_role = V2role(
                id=str(self.default_scope_role.uuid),
                is_system=True,
                permissions=frozenset(["inventory:groups:read", "inventory:hosts:write"]),
            )

            v2_resource = V2boundresource(
                resource_type=("rbac", "workspace"), resource_id=str(self.default_workspace.id)
            )

            v2_rolebinding = V2rolebinding(
                id=str(uuid.uuid4()), role=v2_role, resource=v2_resource, groups=frozenset(), users=frozenset()
            )

            binding_mapping = BindingMapping.for_role_binding(v2_rolebinding, self.default_scope_role)
            binding_mapping.save()  # Save it to get a primary key

        original_resource_id = binding_mapping.resource_id

        # Run the migration
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Refresh from database
        binding_mapping.refresh_from_db()

        # Assert binding remained at default workspace
        self.assertEqual(binding_mapping.resource_id, original_resource_id)

    @patch("management.management.commands.migrate_role_binding_scopes.OutboxReplicator")
    def test_skip_non_default_workspace_bindings(self, mock_outbox_replicator):
        """Test that bindings not pointing to default workspace are skipped."""
        # Redirect replication to in-memory store by mocking the OutboxReplicator constructor
        mock_outbox_replicator.return_value = self.replicator

        with patch(
            "management.management.commands.migrate_role_binding_scopes.permission_service.highest_scope_for_permissions"
        ) as mock_highest_scope:
            # Make the scope function return ROOT scope
            mock_highest_scope.return_value = Scope.ROOT

            # Create a binding mapping bound to root workspace (should be skipped) using proper factory method

            # Create a V2 role for the system role
            v2_role = V2role(
                id=str(self.root_scope_role.uuid), is_system=True, permissions=frozenset(["rbac:principal:read"])
            )

            # Create a V2 bound resource for the ROOT workspace (not default)
            v2_resource = V2boundresource(
                resource_type=("rbac", "workspace"), resource_id=str(self.root_workspace.id)  # Already bound to root
            )

            # Create a V2 role binding
            v2_rolebinding = V2rolebinding(
                id=str(uuid.uuid4()), role=v2_role, resource=v2_resource, groups=frozenset(), users=frozenset()
            )

            # Create the binding mapping using the factory method
            binding_mapping = BindingMapping.for_role_binding(v2_rolebinding, self.root_scope_role)
            binding_mapping.save()  # Save it to get a primary key

        original_resource_id = binding_mapping.resource_id

        # Run the migration
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Refresh from database
        binding_mapping.refresh_from_db()

        # Assert binding was not changed (still bound to root workspace)
        self.assertEqual(binding_mapping.resource_id, original_resource_id)

    @patch("management.management.commands.migrate_role_binding_scopes.OutboxReplicator")
    def test_mixed_permission_scopes_uses_highest_scope(self, mock_outbox_replicator):
        """Test that role with mixed permission scopes gets bound to the highest scope."""
        # Redirect replication to in-memory store by mocking the OutboxReplicator constructor
        mock_outbox_replicator.return_value = self.replicator

        with patch(
            "management.management.commands.migrate_role_binding_scopes.permission_service.highest_scope_for_permissions"
        ) as mock_highest_scope:
            # Make the scope function return ROOT scope (highest scope among mixed permissions)
            mock_highest_scope.return_value = Scope.ROOT
            # Create Access objects for system role with mixed permission levels
            self._create_permission_and_access(self.root_scope_role, "inventory:groups:read")  # Default level
            self._create_permission_and_access(
                self.root_scope_role, "advisor:recommendation:read"
            )  # Root level - this should win
            self._create_permission_and_access(self.root_scope_role, "patch:system:read")  # Default level

            # Create a binding with both default and root level permissions using proper factory method
            # Should be migrated to root workspace (highest scope)
            from migration_tool.models import V2role, V2boundresource, V2rolebinding

            # Create a V2 role for the system role with mixed permissions
            v2_role = V2role(
                id=str(self.root_scope_role.uuid),
                is_system=True,
                permissions=frozenset(
                    [
                        "inventory:groups:read",
                        "advisor:recommendation:read",
                        "patch:system:read",
                    ]
                ),
            )

            # Create a V2 bound resource for the default workspace
            v2_resource = V2boundresource(
                resource_type=("rbac", "workspace"), resource_id=str(self.default_workspace.id)
            )

            # Create a V2 role binding
            v2_rolebinding = V2rolebinding(
                id=str(uuid.uuid4()), role=v2_role, resource=v2_resource, groups=frozenset(), users=frozenset()
            )

            # Create the binding mapping using the factory method
            binding_mapping = BindingMapping.for_role_binding(v2_rolebinding, self.root_scope_role)
            binding_mapping.save()  # Save it to get a primary key

            # Run the migration
            self.command._migrate_role_binding_scopes(batch_size=1)

            # Refresh from database
            binding_mapping.refresh_from_db()

            # Assert binding was migrated to root workspace (highest scope)
            self.assertEqual(binding_mapping.resource_type_namespace, "rbac")
            self.assertEqual(binding_mapping.resource_type_name, "workspace")

            # Verify the resource_id points to a valid root workspace for this tenant
            migrated_workspace = Workspace.objects.get(id=binding_mapping.resource_id)
            self.assertEqual(migrated_workspace.type, Workspace.Types.ROOT)
            self.assertEqual(migrated_workspace.tenant, self.tenant)

    @patch("management.management.commands.migrate_role_binding_scopes.OutboxReplicator")
    def test_binding_without_permissions_kept_default(self, mock_outbox_replicator):
        """Test that bindings without permissions remain at default workspace."""
        # Redirect replication to in-memory store by mocking the OutboxReplicator constructor
        mock_outbox_replicator.return_value = self.replicator

        with patch(
            "management.management.commands.migrate_role_binding_scopes.permission_service.highest_scope_for_permissions"
        ) as mock_highest_scope:
            # Make the scope function return DEFAULT scope (no permissions, so stays default)
            mock_highest_scope.return_value = Scope.DEFAULT

            # Create a V2 role for the system role with no permissions
            v2_role = V2role(
                id=str(self.default_scope_role.uuid), is_system=True, permissions=frozenset()  # No permissions
            )

            # Create a V2 bound resource for the default workspace
            v2_resource = V2boundresource(
                resource_type=("rbac", "workspace"), resource_id=str(self.default_workspace.id)
            )

            # Create a V2 role binding
            v2_rolebinding = V2rolebinding(
                id=str(uuid.uuid4()), role=v2_role, resource=v2_resource, groups=frozenset(), users=frozenset()
            )

            # Create the binding mapping using the factory method
            binding_mapping = BindingMapping.for_role_binding(v2_rolebinding, self.default_scope_role)
            binding_mapping.save()  # Save it to get a primary key

        original_resource_id = binding_mapping.resource_id

        # Run the migration
        self.command._migrate_role_binding_scopes(batch_size=1)

        # Refresh from database
        binding_mapping.refresh_from_db()

        # Assert binding remained at default workspace
        self.assertEqual(binding_mapping.resource_id, original_resource_id)

    @override_settings(ROOT_SCOPE_APPS="advisor,vulnerability,drift", TENANT_SCOPE_APPS="rbac,cost-management")
    @patch("management.management.commands.migrate_role_binding_scopes.OutboxReplicator")
    def test_custom_role_with_mappings_migrated_to_root(self, mock_outbox_replicator):
        """Test that custom roles with permissions in mappings are migrated correctly."""
        # Redirect replication to in-memory store by mocking the OutboxReplicator constructor
        mock_outbox_replicator.return_value = self.replicator

        with patch(
            "management.management.commands.migrate_role_binding_scopes.permission_service.highest_scope_for_permissions"
        ) as mock_highest_scope_v2:
            # Make the scope function return ROOT scope for advisor permissions
            mock_highest_scope_v2.return_value = Scope.ROOT
            # Create a V2 role for the custom role
            v2_role = V2role(
                id=str(self.custom_role.uuid),
                is_system=False,  # Custom role
                permissions=frozenset(["advisor_recommendation_read", "advisor_system_read"]),
            )

            # Create a V2 bound resource for the default workspace
            v2_resource = V2boundresource(
                resource_type=("rbac", "workspace"), resource_id=str(self.default_workspace.id)
            )

            # Create a V2 role binding
            v2_rolebinding = V2rolebinding(
                id=str(uuid.uuid4()), role=v2_role, resource=v2_resource, groups=frozenset(), users=frozenset()
            )

            # Create the binding mapping using the factory method
            binding_mapping = BindingMapping.for_role_binding(v2_rolebinding, self.custom_role)
            binding_mapping.save()  # Save it to get a primary key

            # Run the migration
            self.command._migrate_role_binding_scopes(batch_size=1)

            # Refresh from database
            binding_mapping.refresh_from_db()

            # Assert binding was migrated to root workspace
            self.assertEqual(binding_mapping.resource_type_namespace, "rbac")
            self.assertEqual(binding_mapping.resource_type_name, "workspace")

            # Verify the resource_id points to a valid root workspace for this tenant
            migrated_workspace = Workspace.objects.get(id=binding_mapping.resource_id)
            self.assertEqual(migrated_workspace.type, Workspace.Types.ROOT)
            self.assertEqual(migrated_workspace.tenant, self.tenant)

    @override_settings(ROOT_SCOPE_APPS="advisor,vulnerability,drift", TENANT_SCOPE_APPS="rbac,cost-management")
    @patch("management.management.commands.migrate_role_binding_scopes.OutboxReplicator")
    def test_batch_processing_efficiency(self, mock_outbox_replicator):
        """Test that batch processing handles multiple bindings efficiently."""
        # Redirect replication to in-memory store by mocking the OutboxReplicator constructor
        mock_outbox_replicator.return_value = self.replicator

        with patch(
            "management.management.commands.migrate_role_binding_scopes.permission_service.highest_scope_for_permissions"
        ) as mock_highest_scope:
            # Make the scope function return ROOT scope for advisor permissions
            mock_highest_scope.return_value = Scope.ROOT
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

            # Create bindings for both tenants using proper factory method
            from migration_tool.models import V2role, V2boundresource, V2rolebinding

            bindings = []
            expected_tenants = []
            for tenant, workspace, role in [
                (self.tenant, self.default_workspace, self.root_scope_role),
                (tenant2, default_workspace2, role2),
            ]:
                # Create a V2 role for the system role
                v2_role = V2role(
                    id=str(role.uuid), is_system=True, permissions=frozenset(["advisor:recommendation:read"])
                )

                # Create a V2 bound resource for the default workspace
                v2_resource = V2boundresource(resource_type=("rbac", "workspace"), resource_id=str(workspace.id))

                # Create a V2 role binding
                v2_rolebinding = V2rolebinding(
                    id=str(uuid.uuid4()), role=v2_role, resource=v2_resource, groups=frozenset(), users=frozenset()
                )

                # Create the binding mapping using the factory method
                binding = BindingMapping.for_role_binding(v2_rolebinding, role)
                binding.save()  # Save it to get a primary key

                bindings.append(binding)
                expected_tenants.append(tenant)

            # Run migration with batch size of 1 to test batching
            self.command._migrate_role_binding_scopes(batch_size=1)

            # Verify both bindings were migrated to their respective root workspaces
            for binding, expected_tenant in zip(bindings, expected_tenants):
                binding.refresh_from_db()
                self.assertEqual(binding.resource_type_name, "workspace")

                # Verify the resource_id points to a valid root workspace for the correct tenant
                migrated_workspace = Workspace.objects.get(id=binding.resource_id)
                self.assertEqual(migrated_workspace.type, Workspace.Types.ROOT)
                self.assertEqual(migrated_workspace.tenant, expected_tenant)
