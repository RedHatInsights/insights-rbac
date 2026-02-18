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
"""Test the RoleV2Service domain service."""

import uuid

from django.test import override_settings
from management.exceptions import RequiredFieldError
from management.models import Permission
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.role.definer import seed_roles
from management.role.v2_exceptions import RoleAlreadyExistsError, RoleNotFoundError, CustomRoleRequiredError
from management.role.v2_model import CustomRoleV2, RoleV2, SeededRoleV2, PlatformRoleV2
from management.role.v2_service import RoleV2Service
from management.tenant_service import V2TenantBootstrapService
from tests.identity_request import IdentityRequest

from api.models import Tenant


@override_settings(ATOMIC_RETRY_DISABLED=True)
class RoleV2ServiceTests(IdentityRequest):
    """Test the RoleV2Service domain service."""

    def setUp(self):
        """Set up the RoleV2Service tests."""
        super().setUp()
        self.service = RoleV2Service()

        # Create test permissions
        self.permission1 = Permission.objects.create(permission="inventory:hosts:read", tenant=self.tenant)
        self.permission2 = Permission.objects.create(permission="inventory:hosts:write", tenant=self.tenant)
        self.permission3 = Permission.objects.create(permission="cost:reports:read", tenant=self.tenant)

        self.permission1_data = {"application": "inventory", "resource_type": "hosts", "operation": "read"}

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

    def test_delete_roles_across_tenants(self):
        """Test that custom roles can be deleted."""
        tenant2 = V2TenantBootstrapService(OutboxReplicator()).new_bootstrapped_tenant("t2").tenant

        r1 = self.service.create("r1", "r1", [self.permission1_data], self.tenant)
        r2 = self.service.create("r2", "r2", [self.permission1_data], tenant2)

        self.service.bulk_delete([str(r1.uuid), str(r2.uuid)])

        self.assertFalse(RoleV2.objects.filter(pk=r1.pk).exists())
        self.assertFalse(RoleV2.objects.filter(pk=r2.pk).exists())

    def test_delete_roles_within_tenant(self):
        """Test that multiple custom roles within a tenant can be deleted."""
        r1 = self.service.create("r1", "r1", [self.permission1_data], self.tenant)
        r2 = self.service.create("r2", "r2", [self.permission1_data], self.tenant)

        self.service.bulk_delete([str(r1.uuid), str(r2.uuid)], from_tenant=self.tenant)

        self.assertFalse(RoleV2.objects.filter(pk=r1.pk).exists())
        self.assertFalse(RoleV2.objects.filter(pk=r2.pk).exists())

    def test_delete_role_without_tenant(self):
        """Test that custom roles cannot be deleted outside the provided tenant."""
        tenant2 = V2TenantBootstrapService(OutboxReplicator()).new_bootstrapped_tenant("t2").tenant

        r1 = self.service.create("r1", "r1", [self.permission1_data], self.tenant)
        r2 = self.service.create("r2", "r2", [self.permission1_data], tenant2)

        with self.assertRaises(RoleNotFoundError) as context:
            self.service.bulk_delete([str(r1.uuid), str(r2.uuid)], from_tenant=self.tenant)

        self.assertIn(str(r2.uuid), str(context.exception))

    def test_delete_nonexistent(self):
        """Test that a nonexistent role cannot be deleted."""
        fake_id = str(uuid.uuid4())

        with self.assertRaises(RoleNotFoundError) as context:
            self.service.bulk_delete([fake_id])

        self.assertIn(str(fake_id), str(context.exception))

    def test_delete_seeded_role(self):
        """Test that a seeded role cannot be deleted."""
        # Create some seeded roles.
        seed_roles()

        system_role = SeededRoleV2.objects.first()
        custom_role = self.service.create("custom", "custom", [self.permission1_data], self.tenant)

        self.assertIsNotNone(system_role)

        with self.assertRaises(CustomRoleRequiredError) as context:
            self.service.bulk_delete([str(system_role.uuid), str(custom_role.uuid)])

        self.assertIn(str(system_role.uuid), str(context.exception))

    def test_delete_platform_role(self):
        """Test that a platform role cannot be deleted."""
        # Create platform roles.
        seed_roles()

        platform_role = PlatformRoleV2.objects.first()
        custom_role = self.service.create("custom", "custom", [self.permission1_data], self.tenant)

        self.assertIsNotNone(platform_role)

        with self.assertRaises(CustomRoleRequiredError) as context:
            self.service.bulk_delete([str(platform_role.uuid), str(custom_role.uuid)])

        self.assertIn(str(platform_role.uuid), str(context.exception))

    def test_delete_duplicate_ids(self):
        """Test that a role is deleted if its ID is provided multiple times."""
        role = self.service.create("role", "role", [self.permission1_data], self.tenant)
        self.service.bulk_delete([role.uuid, str(role.uuid), str(role.uuid)])

        self.assertFalse(RoleV2.objects.filter(pk=role.pk).exists())


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
        queryset = self.service.list({})

        self.assertEqual(queryset.count(), 2)
        names = set(queryset.values_list("name", flat=True))
        self.assertEqual(names, {"role_one", "role_two"})

    def test_list_filters_by_exact_name(self):
        """Test that name param filters using case-sensitive exact match."""
        queryset = self.service.list({"name": "role_one"})

        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.first().name, "role_one")

    def test_list_name_filter_no_match_returns_empty(self):
        """Test that a name filter matching nothing returns an empty queryset."""
        queryset = self.service.list({"name": "nonexistent_role"})

        self.assertEqual(queryset.count(), 0)

    def test_list_without_name_returns_all(self):
        """Test that omitting the name param returns all roles for the tenant."""
        RoleV2.objects.create(name="role_other", description="Other role", tenant=self.tenant)

        queryset = self.service.list({})

        self.assertEqual(queryset.count(), 3)

    def test_list_annotates_permissions_count(self):
        """Test that queryset has permissions_count_annotation when fields includes permissions_count."""
        queryset = self.service.list({"fields": {"permissions_count"}})

        for role in queryset:
            self.assertTrue(hasattr(role, "permissions_count_annotation"))

        role_one = queryset.get(name="role_one")
        role_two = queryset.get(name="role_two")
        self.assertEqual(role_one.permissions_count_annotation, 1)
        self.assertEqual(role_two.permissions_count_annotation, 2)
