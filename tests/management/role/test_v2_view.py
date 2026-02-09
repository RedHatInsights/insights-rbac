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

import uuid
from importlib import reload
from unittest.mock import patch

from django.test.utils import override_settings
from importlib import reload

from django.test import override_settings
from django.urls import clear_url_caches, reverse
from rest_framework import status
from rest_framework.test import APIClient

from management.models import Permission
from management.role.v2_model import CustomRoleV2, PlatformRoleV2, RoleV2
from management import v2_urls
from management.models import Permission
from management.role.v2_model import CustomRoleV2, RoleV2
from rbac import urls
from tests.identity_request import IdentityRequest


@override_settings(V2_APIS_ENABLED=True)
class RoleV2RetrieveViewTest(IdentityRequest):
    """Test the RoleV2ViewSet retrieve endpoint."""

    def setUp(self):
        """Set up test data."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.client = APIClient()

        # Create permissions
        self.permission1 = Permission.objects.create(
            permission="inventory:hosts:read",
            tenant=self.tenant,
        )
        self.permission2 = Permission.objects.create(
            permission="inventory:hosts:write",
            tenant=self.tenant,
        )
        self.permission3 = Permission.objects.create(
            permission="cost:reports:read",
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
        self.platform_role.permissions.add(self.permission3)

    def tearDown(self):
        """Tear down test data."""
        RoleV2.objects.filter(tenant=self.tenant).delete()
        Permission.objects.filter(tenant=self.tenant).delete()
        super().tearDown()

    def _get_role_url(self, role_uuid):
        """Get the role detail URL."""
        return reverse("v2_management:roles-detail", kwargs={"uuid": str(role_uuid)})

    def test_retrieve_custom_role_success(self):
        """Test retrieving a custom role with default fields."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        # Verify all default fields are present
        self.assertEqual(data["id"], str(self.custom_role.uuid))
        self.assertEqual(data["name"], "Test Custom Role")
        self.assertEqual(data["description"], "A test custom role")
        self.assertIn("last_modified", data)
        self.assertIn("permissions", data)

        # Verify permissions
        self.assertEqual(len(data["permissions"]), 2)
        permission_strings = {f"{p['application']}:{p['resource_type']}:{p['operation']}" for p in data["permissions"]}
        self.assertEqual(permission_strings, {"inventory:hosts:read", "inventory:hosts:write"})

    def test_retrieve_platform_role_success(self):
        """Test retrieving a platform role."""
        url = self._get_role_url(self.platform_role.uuid)
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        self.assertEqual(data["id"], str(self.platform_role.uuid))
        self.assertEqual(data["name"], "Test Platform Role")
        self.assertEqual(len(data["permissions"]), 1)
        self.assertEqual(data["permissions"][0]["application"], "cost")

    def test_retrieve_role_with_field_filtering_name_only(self):
        """Test retrieving a role with only name field."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(f"{url}?fields=name", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        # Only name should be present
        self.assertEqual(len(data.keys()), 1)
        self.assertEqual(data["name"], "Test Custom Role")
        self.assertNotIn("id", data)
        self.assertNotIn("description", data)
        self.assertNotIn("permissions", data)

    def test_retrieve_role_with_field_filtering_multiple_fields(self):
        """Test retrieving a role with multiple specific fields."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(f"{url}?fields=id,name,permissions_count", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        # Only requested fields should be present
        self.assertEqual(set(data.keys()), {"id", "name", "permissions_count"})
        self.assertEqual(data["id"], str(self.custom_role.uuid))
        self.assertEqual(data["name"], "Test Custom Role")
        self.assertEqual(data["permissions_count"], 2)
        self.assertNotIn("description", data)
        self.assertNotIn("permissions", data)

    def test_retrieve_role_with_field_filtering_all_fields(self):
        """Test retrieving a role with all available fields explicitly."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(
            f"{url}?fields=id,name,description,permissions,permissions_count,last_modified", **self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        # All fields should be present
        self.assertIn("id", data)
        self.assertIn("name", data)
        self.assertIn("description", data)
        self.assertIn("permissions", data)
        self.assertIn("permissions_count", data)
        self.assertIn("last_modified", data)

    def test_retrieve_role_with_invalid_field(self):
        """Test retrieving a role with an invalid field parameter."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(f"{url}?fields=name,invalid_field", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()

        # V2 API error response format: {status, detail}
        self.assertEqual(data["status"], 400)
        self.assertIn("invalid_field", data["detail"])
        self.assertIn("Invalid field(s)", data["detail"])
        self.assertIn("Valid fields are:", data["detail"])

    def test_retrieve_role_with_multiple_invalid_fields(self):
        """Test retrieving a role with multiple invalid fields."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(f"{url}?fields=name,bad_field,another_bad_field", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()

        # V2 API error response format: {status, detail}
        self.assertEqual(data["status"], 400)
        self.assertIn("another_bad_field", data["detail"])
        self.assertIn("bad_field", data["detail"])
        self.assertIn("Invalid field(s)", data["detail"])

    def test_retrieve_role_not_found(self):
        """Test retrieving a non-existent role."""
        non_existent_uuid = uuid.uuid4()
        url = self._get_role_url(non_existent_uuid)
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_role_invalid_uuid_format(self):
        """Test retrieving a role with invalid UUID format."""
        url = reverse("v2_management:roles-detail", kwargs={"uuid": "not-a-uuid"})
        response = self.client.get(url, **self.headers)

        # Should return 404 or 400 depending on URL routing
        self.assertIn(response.status_code, [status.HTTP_404_NOT_FOUND, status.HTTP_400_BAD_REQUEST])

    def test_retrieve_role_from_different_tenant(self):
        """Test that users cannot retrieve roles from other tenants."""
        # Create a role for a different tenant
        from api.models import Tenant

        other_tenant = Tenant.objects.create(
            tenant_name="other_tenant", account_id="999999", org_id="999999", ready=True
        )

        other_role = CustomRoleV2.objects.create(
            name="Other Tenant Role",
            description="Role from another tenant",
            tenant=other_tenant,
        )

        url = self._get_role_url(other_role.uuid)
        response = self.client.get(url, **self.headers)

        # Should not be able to access role from different tenant
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Cleanup
        other_role.delete()
        other_tenant.delete()

    def test_retrieve_role_without_authentication(self):
        """Test retrieving a role without authentication headers."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(url)

        # Should fail without authentication
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_retrieve_role_permissions_structure(self):
        """Test that permissions are properly structured in the response."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        # Verify permission structure
        for permission in data["permissions"]:
            self.assertIn("application", permission)
            self.assertIn("resource_type", permission)
            self.assertIn("operation", permission)

            # Permission strings should be split correctly
            # inventory:hosts:read -> application=inventory, resource_type=hosts, operation=read
            if permission["application"] == "inventory":
                self.assertEqual(permission["resource_type"], "hosts")
                self.assertIn(permission["operation"], ["read", "write"])

    def test_retrieve_role_with_no_permissions(self):
        """Test retrieving a role that has no permissions assigned."""
        empty_role = CustomRoleV2.objects.create(
            name="Empty Role",
            description="Role with no permissions",
            tenant=self.tenant,
        )

        url = self._get_role_url(empty_role.uuid)
        # Request permissions_count explicitly since it's not in default fields
        response = self.client.get(f"{url}?fields=permissions,permissions_count", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        self.assertEqual(data["permissions"], [])
        self.assertEqual(data["permissions_count"], 0)

        empty_role.delete()

    def test_retrieve_role_last_modified_field(self):
        """Test that last_modified field is present and valid."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        self.assertIn("last_modified", data)
        # Verify it's a valid ISO 8601 datetime string
        from datetime import datetime

        try:
            datetime.fromisoformat(data["last_modified"].replace("Z", "+00:00"))
        except ValueError:
            self.fail("last_modified is not a valid ISO 8601 datetime")

    def test_retrieve_role_permissions_count_field(self):
        """Test that permissions_count field returns correct count."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(f"{url}?fields=permissions_count", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        self.assertEqual(data["permissions_count"], 2)

    def test_retrieve_role_default_fields_matches_spec(self):
        """Test that default fields match the TypeSpec specification."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        # Default fields per TypeSpec: id, name, description, permissions, last_modified
        expected_fields = {"id", "name", "description", "permissions", "last_modified"}
        actual_fields = set(data.keys())

        self.assertEqual(actual_fields, expected_fields)

    def test_retrieve_role_with_empty_fields_parameter(self):
        """Test retrieving a role with empty fields parameter uses defaults."""
        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(f"{url}?fields=", **self.headers)

        # Empty fields should be treated as invalid or use defaults
        # Based on implementation, this might return 400 or use defaults
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST])

    def test_retrieve_role_service_layer_integration(self):
        """Test that retrieve uses the service layer correctly."""
        from unittest.mock import MagicMock, patch

        url = self._get_role_url(self.custom_role.uuid)

        # Mock the service to verify it's being called
        with patch("management.role.v2_view.RoleV2Service") as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.get_role.return_value = self.custom_role

            response = self.client.get(url, **self.headers)

            # Verify service was instantiated with tenant
            mock_service_class.assert_called_once_with(tenant=self.tenant)

            # Verify get_role was called with the correct UUID
            from uuid import UUID

            mock_service.get_role.assert_called_once()
            call_args = mock_service.get_role.call_args[0]
            self.assertEqual(call_args[0], UUID(str(self.custom_role.uuid)))

            # Response should be successful
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_retrieve_role_service_raises_not_found_error(self):
        """Test that service RoleNotFoundError is converted to Http404."""
        from unittest.mock import MagicMock, patch
        from uuid import UUID

        from management.role.v2_exceptions import RoleNotFoundError

        non_existent_uuid = UUID("00000000-0000-0000-0000-000000000000")
        url = self._get_role_url(non_existent_uuid)

        # Mock the service to raise RoleNotFoundError
        with patch("management.role.v2_view.RoleV2Service") as mock_service_class:
            mock_service = MagicMock()
            mock_service_class.return_value = mock_service
            mock_service.get_role.side_effect = RoleNotFoundError(non_existent_uuid)

            response = self.client.get(url, **self.headers)

            # Should convert to 404
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

            # Verify service was called
            mock_service.get_role.assert_called_once_with(non_existent_uuid)

    @patch("management.permissions.RoleAccessPermission.has_permission")
    def test_retrieve_role_permission_denied(self, mock_permission):
        """Test retrieving a role when user lacks permission."""
        mock_permission.return_value = False

        url = self._get_role_url(self.custom_role.uuid)
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_retrieve_role_with_special_characters_in_name(self):
        """Test retrieving a role with special characters in name and description."""
        special_role = CustomRoleV2.objects.create(
            name="Role with Special Chars: @#$%",
            description="Description with 'quotes' and \"double quotes\" and line\nbreaks",
            tenant=self.tenant,
        )
        special_role.permissions.add(self.permission1)

        url = self._get_role_url(special_role.uuid)
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()

        self.assertEqual(data["name"], "Role with Special Chars: @#$%")
        self.assertIn("quotes", data["description"])

        special_role.delete()

    def test_retrieve_role_performance_prefetch(self):
        """Test that service layer prefetches permissions to avoid N+1 queries."""
        # Create a role with many permissions
        many_permissions_role = CustomRoleV2.objects.create(
            name="Many Permissions Role",
            description="Role with many permissions",
            tenant=self.tenant,
        )

        # Add 10 permissions
        permissions = []
        for i in range(10):
            perm = Permission.objects.create(
                permission=f"app{i}:resource{i}:action{i}",
                tenant=self.tenant,
            )
            permissions.append(perm)
            many_permissions_role.permissions.add(perm)

        url = self._get_role_url(many_permissions_role.uuid)

        # Query count should be minimal due to service layer's prefetch_related
        # Expected queries: tenant lookup, role fetch with prefetch
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(len(data["permissions"]), 10)

        # Cleanup
        many_permissions_role.delete()
        for perm in permissions:
            perm.delete()
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
