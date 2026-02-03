#
# Copyright 2025 Red Hat, Inc.
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
"""Test the RoleV2 viewset."""

from importlib import reload
from django.conf import settings
from django.test.utils import override_settings
from django.urls import clear_url_caches, reverse
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.test import APIClient

from management.models import Permission, RoleV2
from rbac import urls
from tests.identity_request import IdentityRequest


@override_settings(V2_APIS_ENABLED=True, MIDDLEWARE=settings.MIDDLEWARE)
class RoleV2ViewTests(IdentityRequest):
    """Test the RoleV2 viewset."""

    def setUp(self):
        """Set up the RoleV2 view tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()

        self.client = APIClient()
        self.url = reverse("v2_management:role-list")

        self.permission = Permission.objects.create(permission="test:resource:read", tenant=self.tenant)
        self.role = RoleV2.objects.create(name="test_role", description="Test description", tenant=self.tenant)
        self.role.permissions.add(self.permission)

    def tearDown(self):
        """Tear down the RoleV2 view tests."""
        super().tearDown()
        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

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
