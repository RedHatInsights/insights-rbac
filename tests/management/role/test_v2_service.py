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

from django.test import override_settings
from management.exceptions import AlreadyExistsError, InvalidFieldError, MissingRequiredFieldError
from management.models import Permission
from management.role.v2_model import CustomRoleV2, RoleV2
from management.role.v2_service import RoleV2Service
from tests.identity_request import IdentityRequest


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
        """Test that creating a role with empty description raises MissingRequiredFieldError."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        with self.assertRaises(MissingRequiredFieldError) as context:
            self.service.create(
                name="No Description Role",
                description="",
                permission_data=permission_data,
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field, "description")
        self.assertEqual(context.exception.operation_context, "Create Role")

    def test_create_role_with_whitespace_only_description_raises_error(self):
        """Test that whitespace-only description raises MissingRequiredFieldError."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        with self.assertRaises(MissingRequiredFieldError) as context:
            self.service.create(
                name="Whitespace Description Role",
                description="   ",
                permission_data=permission_data,
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field, "description")

    def test_create_role_with_empty_permissions_raises_error(self):
        """Test that creating a role with empty permissions raises MissingRequiredFieldError."""
        with self.assertRaises(MissingRequiredFieldError) as context:
            self.service.create(
                name="Empty Permissions Role",
                description="Valid description",
                permission_data=[],
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field, "permissions")
        self.assertEqual(context.exception.operation_context, "Create Role")

    def test_create_role_with_permission_missing_required_field_raises_error(self):
        """Test that permission missing a required field raises InvalidFieldError."""
        permission_data = [
            {"resource_type": "hosts", "operation": "read"},  # Missing 'application'
        ]

        with self.assertRaises(InvalidFieldError) as context:
            self.service.create(
                name="Missing App Permission Role",
                description="Valid description",
                permission_data=permission_data,
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field, "permissions")
        self.assertIn("application", str(context.exception))
        self.assertEqual(context.exception.operation_context, "Create Role")

    def test_create_role_with_missing_name_raises_error(self):
        """Test that creating a role with blank name raises error from model validation."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        # Empty name is caught by Django model validation (blank=False)
        with self.assertRaises(Exception):
            self.service.create(
                name="",
                description="Valid description",
                permission_data=permission_data,
                tenant=self.tenant,
            )

    def test_create_role_with_duplicate_name_raises_error(self):
        """Test that creating a role with a duplicate name raises AlreadyExistsError."""
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
        with self.assertRaises(AlreadyExistsError) as cm:
            self.service.create(
                name="Duplicate Name",
                description="Second role",
                permission_data=permission_data2,
                tenant=self.tenant,
            )

        self.assertIn("Duplicate Name", str(cm.exception))
        self.assertEqual(cm.exception.resource_type, "role")
        self.assertEqual(cm.exception.identifier, "Duplicate Name")
        self.assertEqual(cm.exception.operation_context, "Create Role")

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

    def test_create_role_with_nonexistent_permission_raises_error(self):
        """Test that creating a role with nonexistent permissions raises InvalidFieldError."""
        permission_data = [
            {"application": "nonexistent", "resource_type": "resource", "operation": "action"},
        ]

        with self.assertRaises(InvalidFieldError) as context:
            self.service.create(
                name="Nonexistent Permission Role",
                description="Valid description",
                permission_data=permission_data,
                tenant=self.tenant,
            )

        self.assertEqual(context.exception.field, "permissions")
        self.assertIn("do not exist", str(context.exception))
