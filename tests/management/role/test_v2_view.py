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
from management.role.v2_model import CustomRoleV2, PlatformRoleV2, RoleV2, SeededRoleV2
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
        """Test creating a role via API returns 201."""
        data = {
            "name": "API Test Role",
            "description": "Created via API",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], "API Test Role")
        self.assertIn("id", response.data)

    def test_create_role_multiple_permissions(self):
        """Test creating a role with multiple permissions."""
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
        self.assertEqual(response.data["permissions_count"], 2)

    def test_create_role_missing_name_returns_400(self):
        """Test that missing name returns 400."""
        data = {
            "description": "No name",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)

    def test_create_role_missing_permissions_returns_400(self):
        """Test that missing permissions returns 400."""
        data = {
            "name": "No Permissions Role",
            "description": "Missing permissions",
        }

        response = self.client.post(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("detail", response.data)

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
        # Error can be in 'name' field or 'detail' depending on error format
        self.assertTrue(
            "name" in response.data or "already exists" in str(response.data.get("detail", ""))
        )

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
        self.assertIn("permissions_count", response.data)

    # ==========================================================================
    # Tests for GET /api/v2/roles/ (list)
    # ==========================================================================

    def test_list_roles_empty(self):
        """Test listing roles when none exist."""
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 0)

    def test_list_roles_returns_all_types(self):
        """Test that list returns all role types (custom, seeded, platform)."""
        # Create different role types
        CustomRoleV2.objects.create(
            name="Custom Role",
            description="Custom",
            tenant=self.tenant,
        )
        SeededRoleV2.objects.create(
            name="Seeded Role",
            description="Seeded",
            tenant=self.tenant,
        )
        PlatformRoleV2.objects.create(
            name="Platform Role",
            description="Platform",
            tenant=self.tenant,
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 3)

        role_names = [r["name"] for r in response.data["data"]]
        self.assertIn("Custom Role", role_names)
        self.assertIn("Seeded Role", role_names)
        self.assertIn("Platform Role", role_names)

    # ==========================================================================
    # Tests for GET /api/v2/roles/{uuid}/ (retrieve)
    # ==========================================================================

    def test_retrieve_role_success(self):
        """Test retrieving a single role by UUID."""
        role = CustomRoleV2.objects.create(
            name="Retrieve Test",
            description="Test retrieve",
            tenant=self.tenant,
        )
        role.permissions.add(self.permission1)

        url = reverse("v2_management:roles-detail", args=[str(role.uuid)])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["name"], "Retrieve Test")
        self.assertEqual(str(role.uuid), response.data["id"])

    def test_retrieve_role_not_found(self):
        """Test retrieving a non-existent role returns 404."""
        url = reverse("v2_management:roles-detail", args=["00000000-0000-0000-0000-000000000000"])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
