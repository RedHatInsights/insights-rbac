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
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.test import APIClient

from management import v2_urls
from management.models import Permission
from management.role.v2_model import CustomRoleV2, RoleV2
from management.utils import PRINCIPAL_CACHE
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
        # URL for roles endpoint
        self.url = reverse("v2_management:roles-list")

        # Create test permissions
        self.permission1 = Permission.objects.create(permission="test:resource:read", tenant=self.tenant)
        self.permission2 = Permission.objects.create(permission="inventory:hosts:read", tenant=self.tenant)
        self.permission3 = Permission.objects.create(permission="inventory:hosts:write", tenant=self.tenant)
        self.permission4 = Permission.objects.create(permission="cost:reports:read", tenant=self.tenant)

        # Create a role for list tests
        self.role = RoleV2.objects.create(name="test_role", description="Test description", tenant=self.tenant)
        self.role.permissions.add(self.permission1)

    def tearDown(self):
        """Tear down RoleV2ViewSet tests."""
        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

        # Clear principal cache to avoid test isolation issues
        PRINCIPAL_CACHE.delete_all_principals_for_tenant(self.tenant.org_id)
        super().tearDown()

    # ==========================================================================
    # Tests for GET /api/v2/roles/ (list)
    # ==========================================================================

    def test_list_roles_returns_paginated_response(self):
        """Test that list endpoint returns paginated response."""
        response = self.client.get(self.url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("meta", response.data)
        self.assertIn("links", response.data)
        self.assertIn("data", response.data)

        self.assertIn("limit", response.data["meta"])
        self.assertIn("next", response.data["links"])
        self.assertIn("previous", response.data["links"])
        self.assertIsInstance(response.data["data"], list)

    def test_list_roles_returns_default_fields(self):
        """Test that roles return default fields when no fields parameter is provided."""
        response = self.client.get(self.url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)

        role_data = response.data["data"][0]
        expected_fields = {"id", "name", "description", "last_modified"}
        self.assertEqual(set(role_data.keys()), expected_fields)

        self.assertEqual(role_data["name"], "test_role")
        self.assertEqual(role_data["description"], "Test description")
        self.assertNotIn("permissions", role_data)
        self.assertNotIn("permissions_count", role_data)

    def test_list_roles_excludes_platform_roles(self):
        """Test that platform roles are excluded from list responses."""
        RoleV2.objects.create(
            name="platform_role",
            description="Platform description",
            type=RoleV2.Types.PLATFORM,
            tenant=self.tenant,
        )

        response = self.client.get(self.url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)
        self.assertEqual(response.data["data"][0]["name"], "test_role")

    def test_list_roles_with_custom_fields(self):
        """Test that fields parameter returns only requested fields."""
        url = f"{self.url}?fields=id,name,permissions_count"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)

        role_data = response.data["data"][0]
        self.assertEqual(set(role_data.keys()), {"id", "name", "permissions_count"})
        self.assertEqual(role_data["name"], "test_role")
        self.assertEqual(role_data["permissions_count"], 1)

    def test_list_roles_with_name_filter(self):
        """Test that name filter returns only matching roles."""
        RoleV2.objects.create(name="other_role", description="Other", tenant=self.tenant)

        response = self.client.get(self.url, **self.headers)
        self.assertEqual(len(response.data["data"]), 2)

        url = f"{self.url}?name=test_role"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)
        self.assertEqual(response.data["data"][0]["name"], "test_role")

    def test_list_roles_with_order_by_name(self):
        """Test that order_by parameter returns roles sorted by name."""
        RoleV2.objects.create(name="other_role", description="Other", tenant=self.tenant)
        RoleV2.objects.create(name="first_role", description="First", tenant=self.tenant)

        url = f"{self.url}?order_by=name"
        response = self.client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 3)
        self.assertEqual(response.data["data"][0]["name"], "first_role")
        self.assertEqual(response.data["data"][1]["name"], "other_role")
        self.assertEqual(response.data["data"][2]["name"], "test_role")
        # order by descending name
        url = f"{self.url}?order_by=-name"
        response = self.client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 3)
        self.assertEqual(response.data["data"][0]["name"], "test_role")
        self.assertEqual(response.data["data"][1]["name"], "other_role")
        self.assertEqual(response.data["data"][2]["name"], "first_role")

    def test_list_roles_with_order_by_last_modified(self):
        """Test that order_by parameter returns roles sorted by last_modified."""
        # last_modified field is added automatically by the model
        RoleV2.objects.create(name="first_role", description="First", tenant=self.tenant)
        RoleV2.objects.create(name="other_role", description="Other", tenant=self.tenant)

        # Ascending order
        url = f"{self.url}?order_by=last_modified"
        response = self.client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 3)

        data = response.data["data"]
        # Ensure we got the expected roles, regardless of order
        self.assertEqual(
            set(role["name"] for role in data),
            {"test_role", "first_role", "other_role"},
        )

        # Assert that last_modified is sorted ascending
        last_modified_values = [parse_datetime(role["last_modified"]) for role in data]
        self.assertEqual(last_modified_values, sorted(last_modified_values))

        # Descending order
        url = f"{self.url}?order_by=-last_modified"
        response = self.client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 3)

        data = response.data["data"]
        self.assertEqual(
            set(role["name"] for role in data),
            {"test_role", "first_role", "other_role"},
        )

        last_modified_values = [parse_datetime(role["last_modified"]) for role in data]
        self.assertEqual(last_modified_values, sorted(last_modified_values, reverse=True))

    def test_list_roles_with_name_filter_and_order_by(self):
        """Test that name filter and order_by can be combined."""
        RoleV2.objects.create(name="test_role_alpha", description="Alpha", tenant=self.tenant)
        RoleV2.objects.create(name="test_role_beta", description="Beta", tenant=self.tenant)
        RoleV2.objects.create(name="other_role", description="Other", tenant=self.tenant)

        # Filter by name containing "test_role" and order by last_modified descending
        url = f"{self.url}?name=test_role&order_by=-last_modified"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only return exact match "test_role" from setUp()
        self.assertEqual(len(response.data["data"]), 1)
        self.assertEqual(response.data["data"][0]["name"], "test_role")

    def test_list_roles_with_invalid_order_by(self):
        """Test that invalid order_by field returns 400 error."""
        url = f"{self.url}?order_by=foobar"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid ordering field", str(response.data["detail"]))

    def test_list_roles_with_invalid_order_by_permissions_count(self):
        """Test invalid but real field in ?order_by= returns 400 error."""
        url = f"{self.url}?order_by=permissions_count"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid ordering field", str(response.data["detail"]))

    def test_list_roles_with_limit_parameter(self):
        """Test that limit parameter restricts the number of returned roles."""
        # Create additional roles
        RoleV2.objects.create(name="role_2", description="Second", tenant=self.tenant)
        RoleV2.objects.create(name="role_3", description="Third", tenant=self.tenant)

        url = f"{self.url}?limit=2"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 2)
        self.assertEqual(response.data["meta"]["limit"], 2)

    def test_list_roles_meta_contains_correct_limit(self):
        """Test that meta.limit reflects the requested limit value."""
        url = f"{self.url}?limit=5"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["meta"]["limit"], 5)

    def test_list_roles_pagination_generates_next_link(self):
        """Test that links.next is non-null when there are more roles than limit."""
        # Create more roles than the limit
        for i in range(5):
            RoleV2.objects.create(name=f"extra_role_{i}", description=f"Extra {i}", tenant=self.tenant)

        url = f"{self.url}?limit=2"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 2)
        self.assertIsNotNone(response.data["links"]["next"])

    def test_list_roles_pagination_previous_link_null_on_first_page(self):
        """Test that links.previous is null on the first page."""
        response = self.client.get(self.url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data["links"]["previous"])

    def test_list_roles_with_empty_name_filter(self):
        """Test that empty name filter returns all roles."""
        RoleV2.objects.create(name="other_role", description="Other", tenant=self.tenant)

        url = f"{self.url}?name="
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 2)

    def test_list_roles_with_whitespace_name_filter(self):
        """Test that whitespace-only name filter is treated as empty."""
        RoleV2.objects.create(name="other_role", description="Other", tenant=self.tenant)

        url = f"{self.url}?name=%20"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 2)

    def test_list_roles_name_filter_is_case_sensitive(self):
        """Test that name filter is case sensitive exact match."""
        RoleV2.objects.create(name="Test_Role", description="Uppercase", tenant=self.tenant)

        # Should not match "test_role" (lowercase from setUp)
        url = f"{self.url}?name=Test_Role"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)
        self.assertEqual(response.data["data"][0]["name"], "Test_Role")

    def test_list_roles_with_permissions_field(self):
        """Test that requesting permissions field returns permissions array."""
        url = f"{self.url}?fields=id,name,permissions"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)

        role_data = response.data["data"][0]
        self.assertEqual(set(role_data.keys()), {"id", "name", "permissions"})
        self.assertIsInstance(role_data["permissions"], list)
        self.assertEqual(len(role_data["permissions"]), 1)

        perm = role_data["permissions"][0]
        self.assertEqual(perm["application"], "test")
        self.assertEqual(perm["resource_type"], "resource")
        self.assertEqual(perm["operation"], "read")

    def test_list_roles_with_all_available_fields(self):
        """Test that all available fields can be requested."""
        url = f"{self.url}?fields=id,name,description,permissions_count,permissions,last_modified"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        role_data = response.data["data"][0]

        expected = {"id", "name", "description", "permissions_count", "permissions", "last_modified"}
        self.assertEqual(set(role_data.keys()), expected)

    def test_list_roles_with_only_id_field(self):
        """Test minimal field request returns only id."""
        url = f"{self.url}?fields=id"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        role_data = response.data["data"][0]
        self.assertEqual(set(role_data.keys()), {"id"})

    def test_list_roles_with_invalid_fields_raises_validation_error(self):
        """Test that requesting only invalid fields raises a validation error."""
        url = f"{self.url}?fields=invalid_field,another_invalid"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Unknown field: 'invalid_field'", str(response.data["detail"]))
        self.assertIn("Unknown field: 'another_invalid'", str(response.data["detail"]))

    def test_list_roles_returns_empty_list_when_no_roles(self):
        """Test that empty list is returned when no roles exist for tenant."""
        # Delete the role created in setUp
        RoleV2.objects.filter(tenant=self.tenant).delete()

        response = self.client.get(self.url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"], [])
        self.assertIn("meta", response.data)
        self.assertIn("links", response.data)

    def test_list_roles_with_no_matching_name(self):
        """Test that empty list is returned when name filter matches nothing."""
        url = f"{self.url}?name=nonexistent_role"
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"], [])

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
