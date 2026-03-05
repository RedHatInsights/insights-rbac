#
# Copyright 2026 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Test the RoleV2Service."""

from django.test import override_settings
from management.exceptions import RequiredFieldError
from management.models import Permission
from management.role.v2_exceptions import RoleAlreadyExistsError
from management.role.v2_model import CustomRoleV2, RoleV2
from management.role.v2_service import RoleV2Service
from migration_tool.in_memory_tuples import (
    InMemoryRelationReplicator,
    InMemoryTuples,
    all_of,
    relation,
    resource,
    subject,
)
from tests.identity_request import IdentityRequest

from api.models import Tenant


@override_settings(ATOMIC_RETRY_DISABLED=True)
class RoleV2ServiceTests(IdentityRequest):
    """Test the RoleV2Service domain service."""

    def setUp(self):
        """Set up the RoleV2Service tests."""
        super().setUp()
        self.service = RoleV2Service(tenant=self.tenant)

        # Create test permissions
        self.permission1 = Permission.objects.create(permission="inventory:hosts:read", tenant=self.tenant)
        self.permission2 = Permission.objects.create(permission="inventory:hosts:write", tenant=self.tenant)
        self.permission3 = Permission.objects.create(permission="cost:reports:read", tenant=self.tenant)

    def tearDown(self):
        """Tear down RoleV2Service tests."""
        from management.utils import PRINCIPAL_CACHE

        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

        # Clear principal cache to avoid test isolation issues
        PRINCIPAL_CACHE.delete_all_principals_for_tenant(self.tenant.org_id)

        super().tearDown()

    # ==========================================================================
    # Tests for create()
    # ==========================================================================

    def test_create_role_with_single_permission(self):
        """Test creating a role with a single permission."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        role = self.service.create(
            name="Test Role",
            description="A test role",
            permission_data=permission_data,
            tenant=self.tenant,
        )

        self.assertIsInstance(role, CustomRoleV2)
        self.assertEqual(role.name, "Test Role")
        self.assertEqual(role.description, "A test role")
        self.assertEqual(role.type, RoleV2.Types.CUSTOM)
        self.assertEqual(role.tenant, self.tenant)
        self.assertEqual(role.permissions.count(), 1)
        self.assertIn(self.permission1, role.permissions.all())

    def test_create_role_with_multiple_permissions(self):
        """Test creating a role with multiple permissions."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
            {"application": "inventory", "resource_type": "hosts", "operation": "write"},
            {"application": "cost", "resource_type": "reports", "operation": "read"},
        ]

        role = self.service.create(
            name="Multi Permission Role",
            description="Role with multiple permissions",
            permission_data=permission_data,
            tenant=self.tenant,
        )

        self.assertEqual(role.permissions.count(), 3)
        self.assertIn(self.permission1, role.permissions.all())
        self.assertIn(self.permission2, role.permissions.all())
        self.assertIn(self.permission3, role.permissions.all())

    def test_create_role_with_empty_description_raises_error(self):
        """Test that creating a role with empty description raises RequiredFieldError."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        with self.assertRaises(RequiredFieldError) as context:
            self.service.create(
                name="No Description Role",
                description="",
                permission_data=permission_data,
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field_name, "description")

    def test_create_role_with_whitespace_only_description_raises_error(self):
        """Test that whitespace-only description raises RequiredFieldError."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        with self.assertRaises(RequiredFieldError) as context:
            self.service.create(
                name="Whitespace Description Role",
                description="   ",
                permission_data=permission_data,
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field_name, "description")

    def test_create_role_with_empty_permissions_raises_error(self):
        """Test that creating a role with empty permissions raises RequiredFieldError."""
        with self.assertRaises(RequiredFieldError) as context:
            self.service.create(
                name="Empty Permissions Role",
                description="Valid description",
                permission_data=[],
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field_name, "permissions")

    def test_create_role_with_permission_missing_required_field_raises_error(self):
        """Test that permission missing a required field raises RequiredFieldError."""
        permission_data = [
            {"resource_type": "hosts", "operation": "read"},  # Missing 'application'
        ]

        with self.assertRaises(RequiredFieldError) as context:
            self.service.create(
                name="Missing App Permission Role",
                description="Valid description",
                permission_data=permission_data,
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field_name, "application")

    def test_create_role_with_missing_name_raises_error(self):
        """Test that creating a role with blank name raises RequiredFieldError."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        with self.assertRaises(RequiredFieldError) as context:
            self.service.create(
                name="",
                description="Valid description",
                permission_data=permission_data,
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field_name, "name")

    def test_create_role_with_duplicate_name_raises_error(self):
        """Test that creating a role with a duplicate name raises RoleAlreadyExistsError."""
        permission_data1 = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]
        permission_data2 = [
            {"application": "inventory", "resource_type": "hosts", "operation": "write"},
        ]

        # Create first role
        self.service.create(
            name="Duplicate Name",
            description="First role",
            permission_data=permission_data1,
            tenant=self.tenant,
        )

        # Attempt to create second role with same name
        with self.assertRaises(RoleAlreadyExistsError) as cm:
            self.service.create(
                name="Duplicate Name",
                description="Second role",
                permission_data=permission_data2,
                tenant=self.tenant,
            )

        self.assertIn("Duplicate Name", str(cm.exception))
        self.assertEqual(cm.exception.name, "Duplicate Name")

    def test_create_role_generates_uuid(self):
        """Test that creating a role auto-generates a UUID."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        role = self.service.create(
            name="UUID Test Role",
            description="Testing UUID generation",
            permission_data=permission_data,
            tenant=self.tenant,
        )

        self.assertIsNotNone(role.uuid)

    def test_create_role_sets_type_to_custom(self):
        """Test that created roles are always of type CUSTOM."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        role = self.service.create(
            name="Custom Type Role",
            description="Should be custom",
            permission_data=permission_data,
            tenant=self.tenant,
        )

        self.assertEqual(role.type, RoleV2.Types.CUSTOM)

    # ==========================================================================
    # Tests for replication
    # ==========================================================================

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    def test_create_role_replicates_permission_tuples(self):
        """Test that creating a role replicates permission tuples to SpiceDB."""
        # Set up in-memory replicator (stub, not mock!)
        tuples = InMemoryTuples()
        replicator = InMemoryRelationReplicator(tuples)
        service = RoleV2Service(tenant=self.tenant, replicator=replicator)

        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
            {"application": "inventory", "resource_type": "hosts", "operation": "write"},
        ]

        # When: Create a role
        role = service.create(
            name="Replication Test Role",
            description="A test role for replication",
            permission_data=permission_data,
            tenant=self.tenant,
        )

        # Then: Permission tuples are replicated
        role_uuid = str(role.uuid)

        # Should have 2 permission tuples (one per permission)
        self.assertEqual(len(tuples), 2)

        # Verify the read permission tuple exists
        read_tuples = tuples.find_tuples(
            all_of(
                resource("rbac", "role", role_uuid),
                relation("inventory_hosts_read"),
                subject("rbac", "principal", "*"),
            )
        )
        self.assertEqual(len(read_tuples), 1, "Expected 1 read permission tuple")

        # Verify the write permission tuple exists
        write_tuples = tuples.find_tuples(
            all_of(
                resource("rbac", "role", role_uuid),
                relation("inventory_hosts_write"),
                subject("rbac", "principal", "*"),
            )
        )
        self.assertEqual(len(write_tuples), 1, "Expected 1 write permission tuple")

    def test_update_role_with_empty_description_raises_error(self):
        """Test that updating a role with empty description raises RequiredFieldError."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        role = self.service.create(
            name="Test Role",
            description="Original description",
            permission_data=permission_data,
            tenant=self.tenant,
        )

        with self.assertRaises(RequiredFieldError) as context:
            self.service.update(
                role_uuid=str(role.uuid),
                name="Test Role",
                description="",
                permission_data=permission_data,
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field_name, "description")

    def test_update_role_with_empty_permissions_raises_error(self):
        """Test that updating a role with empty permissions raises RequiredFieldError."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        role = self.service.create(
            name="Test Role",
            description="A test role",
            permission_data=permission_data,
            tenant=self.tenant,
        )

        with self.assertRaises(RequiredFieldError) as context:
            self.service.update(
                role_uuid=str(role.uuid),
                name="Test Role",
                description="A test role",
                permission_data=[],
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field_name, "permissions")

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    def test_update_role_replicates_permission_tuples(self):
        """Test that updating a role replicates old and new permission tuples to SpiceDB."""
        # Set up in-memory replicator
        tuples = InMemoryTuples()
        replicator = InMemoryRelationReplicator(tuples)
        service = RoleV2Service(tenant=self.tenant, replicator=replicator)

        # Create initial role with read and write permissions
        initial_permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
            {"application": "inventory", "resource_type": "hosts", "operation": "write"},
        ]

        role = service.create(
            name="Update Replication Test Role",
            description="Initial description",
            permission_data=initial_permission_data,
            tenant=self.tenant,
        )

        # Don't clear - we need the initial state for delta computation to work correctly
        # The delta will remove {write} and add {cost}, resulting in {read, cost}
        role_uuid = str(role.uuid)

        # Update the role to have different permissions (read and cost:reports:read)
        updated_permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
            {"application": "cost", "resource_type": "reports", "operation": "read"},
        ]

        updated_role = service.update(
            role_uuid=role_uuid,
            name="Updated Replication Test Role",
            description="Updated description",
            permission_data=updated_permission_data,
            tenant=self.tenant,
        )

        # Then: Verify the update produced the correct replication events
        # The replicator uses delta computation, so it should have:
        # - Removed: {write} (only permissions no longer in the role)
        # - Added: {cost:reports:read} (only new permissions)
        # - Kept: {read} (unchanged, so not touched by delta)

        # The InMemoryTuples tracks the final state after all operations
        # After update, we should have exactly 2 tuples (the new permissions)
        self.assertEqual(len(tuples), 2)

        # Verify the read permission tuple still exists (it was in both old and new)
        read_tuples = tuples.find_tuples(
            all_of(
                resource("rbac", "role", role_uuid),
                relation("inventory_hosts_read"),
                subject("rbac", "principal", "*"),
            )
        )
        self.assertEqual(len(read_tuples), 1, "Expected 1 read permission tuple")

        # Verify the write permission tuple was removed (not in new permissions)
        write_tuples = tuples.find_tuples(
            all_of(
                resource("rbac", "role", role_uuid),
                relation("inventory_hosts_write"),
                subject("rbac", "principal", "*"),
            )
        )
        self.assertEqual(len(write_tuples), 0, "Write permission should be removed")

        # Verify the cost:reports:read permission tuple was added
        cost_tuples = tuples.find_tuples(
            all_of(
                resource("rbac", "role", role_uuid),
                relation("cost_reports_read"),
                subject("rbac", "principal", "*"),
            )
        )
        self.assertEqual(len(cost_tuples), 1, "Expected 1 cost:reports:read permission tuple")


@override_settings(ATOMIC_RETRY_DISABLED=True)
class RoleV2ServiceListTests(IdentityRequest):
    """Test the RoleV2Service.list() method."""

    def setUp(self):
        """Set up the RoleV2Service list tests."""
        super().setUp()
        self.service = RoleV2Service(tenant=self.tenant)

        # Create test permissions
        self.permission1 = Permission.objects.create(permission="inventory:hosts:read", tenant=self.tenant)
        self.permission2 = Permission.objects.create(permission="inventory:hosts:write", tenant=self.tenant)

        # Create test roles
        self.role1 = RoleV2.objects.create(name="role_one", description="First role", tenant=self.tenant)
        self.role1.permissions.add(self.permission1)

        self.role2 = RoleV2.objects.create(name="role_two", description="Second role", tenant=self.tenant)
        self.role2.permissions.add(self.permission1, self.permission2)

    def tearDown(self):
        """Tear down RoleV2Service list tests."""
        from management.utils import PRINCIPAL_CACHE

        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

        PRINCIPAL_CACHE.delete_all_principals_for_tenant(self.tenant.org_id)
        super().tearDown()

    # ==========================================================================
    # Tests for list()
    # ==========================================================================

    def test_list_returns_roles_for_tenant(self):
        """Test that list() returns all roles belonging to the tenant."""
        queryset = self.service.list({"resource_type": "workspace"})

        self.assertEqual(queryset.count(), 2)
        names = set(queryset.values_list("name", flat=True))
        self.assertEqual(names, {"role_one", "role_two"})

    def test_list_filters_by_exact_name(self):
        """Test that name param filters using case-sensitive exact match."""
        queryset = self.service.list({"resource_type": "workspace", "name": "role_one"})

        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.first().name, "role_one")

    def test_list_name_filter_no_match_returns_empty(self):
        """Test that a name filter matching nothing returns an empty queryset."""
        queryset = self.service.list({"resource_type": "workspace", "name": "nonexistent_role"})

        self.assertEqual(queryset.count(), 0)

    def test_list_without_name_returns_all(self):
        """Test that omitting the name param returns all roles for the tenant."""
        RoleV2.objects.create(name="role_other", description="Other role", tenant=self.tenant)

        queryset = self.service.list({"resource_type": "workspace"})

        self.assertEqual(queryset.count(), 3)

    def test_list_annotates_permissions_count(self):
        """Test that queryset has permissions_count_annotation when fields includes permissions_count."""
        queryset = self.service.list({"resource_type": "workspace", "fields": {"permissions_count"}})

        for role in queryset:
            self.assertTrue(hasattr(role, "permissions_count_annotation"))

        role_one = queryset.get(name="role_one")
        role_two = queryset.get(name="role_two")
        self.assertEqual(role_one.permissions_count_annotation, 1)
        self.assertEqual(role_two.permissions_count_annotation, 2)


@override_settings(
    ATOMIC_RETRY_DISABLED=True,
    TENANT_SCOPE_PERMISSIONS="tenant_app:*:*",
    ROOT_SCOPE_PERMISSIONS="root_app:*:*",
)
class RoleV2ServiceListResourceTypeTests(IdentityRequest):
    """Test the RoleV2Service.list() resource_type filtering."""

    def setUp(self):
        """Set up resource_type filter tests."""
        super().setUp()
        self.service = RoleV2Service(tenant=self.tenant)

        self.default_perm = Permission.objects.create(permission="default_app:resource:read", tenant=self.tenant)
        self.root_perm = Permission.objects.create(permission="root_app:resource:read", tenant=self.tenant)
        self.tenant_perm = Permission.objects.create(permission="tenant_app:resource:read", tenant=self.tenant)

        self.default_role = RoleV2.objects.create(
            name="default_role", description="Default scoped", tenant=self.tenant
        )
        self.default_role.permissions.add(self.default_perm)

        self.root_role = RoleV2.objects.create(name="root_role", description="Root scoped", tenant=self.tenant)
        self.root_role.permissions.add(self.root_perm)

        self.tenant_role = RoleV2.objects.create(
            name="tenant_role", description="Tenant scoped", tenant=self.tenant
        )
        self.tenant_role.permissions.add(self.tenant_perm)

        self.mixed_role = RoleV2.objects.create(
            name="mixed_role", description="Has both default and tenant perms", tenant=self.tenant
        )
        self.mixed_role.permissions.add(self.default_perm, self.tenant_perm)

    def tearDown(self):
        """Tear down resource_type filter tests."""
        from management.utils import PRINCIPAL_CACHE

        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()
        PRINCIPAL_CACHE.delete_all_principals_for_tenant(self.tenant.org_id)
        super().tearDown()

    def test_list_resource_type_tenant_returns_tenant_scoped_roles(self):
        """Roles whose highest scope is TENANT should be returned for resource_type=tenant."""
        queryset = self.service.list({"resource_type": "tenant"})
        names = set(queryset.values_list("name", flat=True))
        self.assertEqual(names, {"tenant_role", "mixed_role"})

    def test_list_resource_type_workspace_returns_workspace_scoped_roles(self):
        """Roles whose highest scope is DEFAULT or ROOT should be returned for resource_type=workspace."""
        queryset = self.service.list({"resource_type": "workspace"})
        names = set(queryset.values_list("name", flat=True))
        self.assertEqual(names, {"default_role", "root_role"})

    def test_list_resource_type_workspace_excludes_mixed_role(self):
        """A role with both default and tenant permissions has highest scope TENANT and should not appear for workspace."""
        queryset = self.service.list({"resource_type": "workspace"})
        names = set(queryset.values_list("name", flat=True))
        self.assertNotIn("mixed_role", names)

    def test_list_without_resource_type_raises_error(self):
        """Omitting resource_type raises RequiredFieldError."""
        with self.assertRaises(RequiredFieldError) as ctx:
            self.service.list({})
        self.assertEqual(ctx.exception.field_name, "resource_type")

    def test_list_unknown_resource_type_returns_empty(self):
        """An unknown resource_type returns an empty queryset."""
        queryset = self.service.list({"resource_type": "unknown"})
        self.assertEqual(queryset.count(), 0)

    def test_list_resource_type_combined_with_name_filter(self):
        """resource_type and name filters can be combined."""
        queryset = self.service.list({"resource_type": "tenant", "name": "tenant_role"})
        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.first().name, "tenant_role")

    def test_list_resource_type_combined_with_name_filter_no_match(self):
        """Combined filters that contradict each other return empty."""
        queryset = self.service.list({"resource_type": "workspace", "name": "tenant_role"})
        self.assertEqual(queryset.count(), 0)
