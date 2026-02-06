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
"""Test the RoleV2ViewSet."""

from importlib import reload

from django.test import override_settings
from django.urls import clear_url_caches, reverse
from rest_framework import status
from rest_framework.test import APIClient

from management import v2_urls
from management.models import Permission
from management.role.model import CustomRoleV2, RoleV2
from rbac import urls
from tests.identity_request import IdentityRequest


@override_settings(V2_APIS_ENABLED=True, ATOMIC_RETRY_DISABLED=True)
class RoleV2ViewSetTests(IdentityRequest):
    """Test the RoleV2ViewSet."""

    def setUp(self):
        """Set up the RoleV2ViewSet tests."""
        # Reload URLs to pick up v2 management routes
        reload(v2_urls)
        reload(urls)
        clear_url_caches()

        super().setUp()
        self.client = APIClient()
        self.client.credentials(HTTP_X_RH_IDENTITY=self.headers.get("HTTP_X_RH_IDENTITY"))

        # Create test permissions
        self.permission1 = Permission.objects.create(permission="inventory:hosts:read", tenant=self.tenant)
        self.permission2 = Permission.objects.create(permission="inventory:hosts:write", tenant=self.tenant)
        self.permission3 = Permission.objects.create(permission="cost:reports:read", tenant=self.tenant)

        # URL for roles endpoint
        self.url = reverse("v2_management:roles-list")

    def tearDown(self):
        """Tear down RoleV2ViewSet tests."""
        from management.utils import PRINCIPAL_CACHE

        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

        # Clear principal cache to avoid test isolation issues
        PRINCIPAL_CACHE.delete_all_principals_for_tenant(self.tenant.org_id)

        super().tearDown()

    # ==========================================================================
    # Tests for POST /api/v2/roles/ (create)
    # ==========================================================================

    def test_create_role_success(self):
        """Test creating a role via API returns 201"""
        data = {
            "name": "API Test Role",
            "description": "Created via API",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], "API Test Role")
        self.assertIn("id", response.data)

        # Verify permissions are returned in response
        self.assertEqual(
            response.data["permissions"],
            [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        )

    def test_create_role_multiple_permissions(self):
        """Test creating a role with multiple permissions returns all permissions."""
        data = {
            "name": "Multi Permission API Role",
            "description": "Has multiple permissions",
            "permissions": [
                {"application": "inventory", "resource_type": "hosts", "operation": "read"},
                {"application": "inventory", "resource_type": "hosts", "operation": "write"},
            ],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify permissions match (order-independent)
        self.assertCountEqual(
            response.data["permissions"],
            [
                {"application": "inventory", "resource_type": "hosts", "operation": "read"},
                {"application": "inventory", "resource_type": "hosts", "operation": "write"},
            ],
        )

    def test_create_role_preserves_permission_order(self):
        """Test that response permissions are returned in input order."""
        # Request permissions in specific order (cost first, then inventory)
        data = {
            "name": "Order Test Role",
            "description": "Testing permission order preservation",
            "permissions": [
                {"application": "cost", "resource_type": "reports", "operation": "read"},
                {"application": "inventory", "resource_type": "hosts", "operation": "write"},
                {"application": "inventory", "resource_type": "hosts", "operation": "read"},
            ],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify permissions are returned in the same order as input
        self.assertEqual(
            response.data["permissions"],
            [
                {"application": "cost", "resource_type": "reports", "operation": "read"},
                {"application": "inventory", "resource_type": "hosts", "operation": "write"},
                {"application": "inventory", "resource_type": "hosts", "operation": "read"},
            ],
        )

    def test_create_role_missing_name_returns_400(self):
        """Test that missing name returns 400."""
        data = {
            "description": "No name",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)
        self.assertIn("errors", response.data)
        self.assertTrue(any(e.get("field") == "name" for e in response.data["errors"]))

    def test_create_role_missing_permissions_returns_400(self):
        """Test that missing permissions returns 400."""
        data = {
            "name": "No Permissions Role",
            "description": "Missing permissions",
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)
        self.assertIn("errors", response.data)
        self.assertTrue(any(e.get("field") == "permissions" for e in response.data["errors"]))

    def test_create_role_empty_permissions_returns_400(self):
        """Test that empty permissions array returns 400."""
        data = {
            "name": "Empty Permissions Role",
            "description": "Has empty permissions",
            "permissions": [],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)

    def test_create_role_invalid_permission_returns_400(self):
        """Test that non-existent permission returns 400."""
        data = {
            "name": "Invalid Permission Role",
            "description": "Has invalid permission",
            "permissions": [{"application": "nonexistent", "resource_type": "resource", "operation": "action"}],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)

    def test_create_role_duplicate_name_returns_400(self):
        """Test that duplicate role name returns 400."""
        # Create first role
        CustomRoleV2.objects.create(
            name="Duplicate API Role",
            description="First role",
            tenant=self.tenant,
        )

        # Try to create via API
        data = {
            "name": "Duplicate API Role",
            "description": "Second role",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("status", response.data)
        self.assertIn("title", response.data)
        self.assertIn("detail", response.data)
        self.assertEqual(response.data["status"], 400)
        self.assertIn("already exists", response.data["detail"])

    def test_create_role_missing_permissions_returns_problem_details(self):
        """Test that missing permissions returns ProblemDetails format."""
        data = {
            "name": "No Permissions Role",
            "description": "Missing permissions",
            "permissions": [],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("status", response.data)
        self.assertIn("title", response.data)
        self.assertIn("detail", response.data)
        self.assertEqual(response.data["status"], 400)

    def test_create_role_invalid_permission_returns_problem_details(self):
        """Test that invalid permission returns ProblemDetails format."""
        data = {
            "name": "Invalid Permission Role",
            "description": "Invalid permission",
            "permissions": [{"application": "nonexistent", "resource_type": "foo", "operation": "bar"}],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("status", response.data)
        self.assertIn("title", response.data)
        self.assertIn("detail", response.data)
        self.assertEqual(response.data["status"], 400)
        self.assertIn("do not exist", response.data["detail"])

    def test_create_role_empty_body_returns_all_required_field_errors(self):
        """Test that empty request body returns errors array with all required fields."""
        response = self.client.post(self.url, {}, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("errors", response.data)

        error_fields = {e.get("field") for e in response.data["errors"]}
        self.assertIn("name", error_fields)
        self.assertIn("description", error_fields)
        self.assertIn("permissions", error_fields)

    def test_create_role_returns_response_format(self):
        """Test that create returns proper response format with all fields."""
        data = {
            "name": "Response Format Role",
            "description": "Testing response format",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("id", response.data)
        self.assertIn("name", response.data)
        self.assertIn("description", response.data)
        self.assertIn("permissions", response.data)
        self.assertIn("last_modified", response.data)
        # permissions_count not included until field masking is implemented
