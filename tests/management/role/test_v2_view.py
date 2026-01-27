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

        url = f"{self.url}?order_by=last_modified"
        response = self.client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 3)
        self.assertEqual(response.data["data"][0]["name"], "test_role")
        self.assertEqual(response.data["data"][1]["name"], "first_role")
        self.assertEqual(response.data["data"][2]["name"], "other_role")
        # order by descending last_modified
        url = f"{self.url}?order_by=-last_modified"
        response = self.client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 3)
        self.assertEqual(response.data["data"][0]["name"], "other_role")
        self.assertEqual(response.data["data"][1]["name"], "first_role")
        self.assertEqual(response.data["data"][2]["name"], "test_role")

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
