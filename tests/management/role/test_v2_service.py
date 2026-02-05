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

import uuid

from django.test import TestCase

from api.models import Tenant
from management.models import Permission
from management.role.v2_exceptions import RoleNotFoundError
from management.role.v2_model import CustomRoleV2, PlatformRoleV2, RoleV2
from management.role.v2_service import RoleV2Service


class RoleV2ServiceGetRoleTest(TestCase):
    """Test the RoleV2Service.get_role method."""

    def setUp(self):
        """Set up test data."""
        # Create tenant
        self.tenant = Tenant.objects.create(
            tenant_name="test_tenant",
            account_id="123456",
            org_id="123456",
            ready=True,
        )

        # Create another tenant for isolation tests
        self.other_tenant = Tenant.objects.create(
            tenant_name="other_tenant",
            account_id="999999",
            org_id="999999",
            ready=True,
        )

        # Create permissions
        self.permission1 = Permission.objects.create(
            permission="inventory:hosts:read",
            tenant=self.tenant,
        )
        self.permission2 = Permission.objects.create(
            permission="inventory:hosts:write",
            tenant=self.tenant,
        )

        # Create a custom role
        self.custom_role = CustomRoleV2.objects.create(
            name="Test Custom Role",
            description="A test custom role",
            tenant=self.tenant,
        )
        self.custom_role.permissions.add(self.permission1, self.permission2)

        # Create a platform role
        self.platform_role = PlatformRoleV2.objects.create(
            name="Test Platform Role",
            description="A test platform role",
            tenant=self.tenant,
        )
        self.platform_role.permissions.add(self.permission1)

        # Create a role in other tenant
        self.other_tenant_role = CustomRoleV2.objects.create(
            name="Other Tenant Role",
            description="Role in another tenant",
            tenant=self.other_tenant,
        )

    def tearDown(self):
        """Clean up test data."""
        RoleV2.objects.all().delete()
        Permission.objects.all().delete()
        self.tenant.delete()
        self.other_tenant.delete()

    def test_get_role_success_custom_role(self):
        """Test successfully retrieving a custom role."""
        service = RoleV2Service(tenant=self.tenant)

        role = service.get_role(self.custom_role.uuid)

        self.assertEqual(role.uuid, self.custom_role.uuid)
        self.assertEqual(role.name, "Test Custom Role")
        self.assertEqual(role.description, "A test custom role")
        self.assertEqual(role.tenant, self.tenant)

    def test_get_role_success_platform_role(self):
        """Test successfully retrieving a platform role."""
        service = RoleV2Service(tenant=self.tenant)

        role = service.get_role(self.platform_role.uuid)

        self.assertEqual(role.uuid, self.platform_role.uuid)
        self.assertEqual(role.name, "Test Platform Role")
        self.assertEqual(role.type, RoleV2.Types.PLATFORM)

    def test_get_role_permissions_prefetched(self):
        """Test that permissions are prefetched."""
        service = RoleV2Service(tenant=self.tenant)

        role = service.get_role(self.custom_role.uuid)

        # Accessing permissions should not trigger additional queries
        # if prefetch_related worked correctly
        with self.assertNumQueries(0):
            permissions = list(role.permissions.all())
            self.assertEqual(len(permissions), 2)

    def test_get_role_not_found(self):
        """Test retrieving a non-existent role raises RoleNotFoundError."""
        service = RoleV2Service(tenant=self.tenant)
        non_existent_uuid = uuid.uuid4()

        with self.assertRaises(RoleNotFoundError) as context:
            service.get_role(non_existent_uuid)

        self.assertEqual(context.exception.uuid, non_existent_uuid)
        self.assertIn(str(non_existent_uuid), str(context.exception))

    def test_get_role_tenant_isolation(self):
        """Test that roles from other tenants cannot be accessed."""
        service = RoleV2Service(tenant=self.tenant)

        # Try to access a role from another tenant
        with self.assertRaises(RoleNotFoundError):
            service.get_role(self.other_tenant_role.uuid)

    def test_service_init_requires_tenant(self):
        """Test that RoleV2Service requires tenant parameter."""
        with self.assertRaises(TypeError):
            RoleV2Service()  # No tenant provided

    def test_get_role_returns_correct_type(self):
        """Test that get_role returns RoleV2 instance."""
        service = RoleV2Service(tenant=self.tenant)

        role = service.get_role(self.custom_role.uuid)

        self.assertIsInstance(role, RoleV2)
        # Verify it's a custom role by checking the type field
        self.assertEqual(role.type, RoleV2.Types.CUSTOM)

    def test_get_role_with_no_permissions(self):
        """Test retrieving a role with no permissions."""
        empty_role = CustomRoleV2.objects.create(
            name="Empty Role",
            description="Role with no permissions",
            tenant=self.tenant,
        )

        service = RoleV2Service(tenant=self.tenant)
        role = service.get_role(empty_role.uuid)

        self.assertEqual(role.permissions.count(), 0)

        empty_role.delete()

    def test_get_role_exception_details(self):
        """Test that RoleNotFoundError contains proper details."""
        service = RoleV2Service(tenant=self.tenant)
        non_existent_uuid = uuid.uuid4()

        try:
            service.get_role(non_existent_uuid)
            self.fail("Should have raised RoleNotFoundError")
        except RoleNotFoundError as e:
            # Exception should have uuid attribute
            self.assertEqual(e.uuid, non_existent_uuid)
            # Exception message should contain the UUID
            self.assertIn(str(non_existent_uuid), str(e))
            # Exception should be a RoleV2Error
            from management.role.v2_exceptions import RoleV2Error

            self.assertIsInstance(e, RoleV2Error)

    def test_service_reusable_across_calls(self):
        """Test that service instance can be reused for multiple calls."""
        service = RoleV2Service(tenant=self.tenant)

        # First call
        role1 = service.get_role(self.custom_role.uuid)
        self.assertEqual(role1.uuid, self.custom_role.uuid)

        # Second call with different role
        role2 = service.get_role(self.platform_role.uuid)
        self.assertEqual(role2.uuid, self.platform_role.uuid)

        # Verify different roles were returned
        self.assertNotEqual(role1.uuid, role2.uuid)

    def test_get_role_with_special_characters_in_name(self):
        """Test retrieving a role with special characters in name."""
        special_role = CustomRoleV2.objects.create(
            name="Role with Special Chars: @#$%",
            description="Description with 'quotes'",
            tenant=self.tenant,
        )

        service = RoleV2Service(tenant=self.tenant)
        role = service.get_role(special_role.uuid)

        self.assertEqual(role.name, "Role with Special Chars: @#$%")

        special_role.delete()
