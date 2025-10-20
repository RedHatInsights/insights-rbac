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
"""Test the Role Binding View."""
from django.test.utils import override_settings
from django.urls import clear_url_caches, reverse
from importlib import reload
from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant
from management.models import Group, Workspace
from management.role.v2_model import RoleBinding, RoleBindingGroup, RoleV2
from rbac import urls
from tests.identity_request import IdentityRequest


@override_settings(V2_APIS_ENABLED=True)
class RoleBindingViewTests(IdentityRequest):
    """Test the Role Binding view."""

    def setUp(self):
        """Set up the role binding tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.tenant.save()

        # Create a workspace for testing
        self.root_workspace = Workspace.objects.create(
            name="Root Workspace",
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
        )
        self.default_workspace = Workspace.objects.create(
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            name="Default Workspace",
            description="Default Description",
            parent_id=self.root_workspace.id,
        )

        # Create a role
        self.role = RoleV2.objects.create(
            name="Test Role",
            description="Test role for bindings",
            tenant=self.tenant,
            type=RoleV2.Types.CUSTOM,
        )

        # Create a group
        self.group = Group.objects.create(
            name="Test Group",
            description="Test group",
            tenant=self.tenant,
        )

        # Create a role binding
        self.role_binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id=str(self.default_workspace.id),
            tenant=self.tenant,
        )

        # Link group to binding
        RoleBindingGroup.objects.create(
            group=self.group,
            binding=self.role_binding,
        )

    def tearDown(self):
        """Tear down role binding tests."""
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.all().delete()
        RoleV2.objects.all().delete()
        Group.objects.all().delete()
        Workspace.objects.update(parent=None)
        Workspace.objects.all().delete()

    def test_list_by_subject_success(self):
        """Test listing role bindings by subject with required parameters."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        # Call with required parameters
        params = {
            "resource_id": str(self.default_workspace.id),
            "resource_type": "workspace",
        }
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.get("content-type"), "application/json")

        # Check response structure
        data = response.data
        self.assertIn("meta", data)
        self.assertIn("links", data)
        self.assertIn("data", data)
        self.assertIsInstance(data["data"], list)

    def test_list_by_subject_missing_resource_id(self):
        """Test that missing resource_id returns validation error."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        params = {"resource_type": "workspace"}
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_list_by_subject_missing_resource_type(self):
        """Test that missing resource_type returns validation error."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        params = {"resource_id": str(self.default_workspace.id)}
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_list_by_subject_with_pagination(self):
        """Test pagination works correctly."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        params = {
            "resource_id": str(self.default_workspace.id),
            "resource_type": "workspace",
            "limit": 5,
        }
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data["meta"]["limit"], 5)
        self.assertIn("next", data["links"])
        self.assertIn("previous", data["links"])

    def test_list_by_subject_with_simple_field_filter(self):
        """Test filtering response fields with simple field list."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        params = {
            "resource_id": str(self.default_workspace.id),
            "resource_type": "workspace",
            "fields": "subject,roles",
        }
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]

        # Should have at least one result
        self.assertGreater(len(data), 0)

        # Check that only requested fields are present
        first_item = data[0]
        self.assertIn("subject", first_item)
        self.assertIn("roles", first_item)
        self.assertNotIn("resource", first_item)
        self.assertNotIn("last_modified", first_item)

    def test_list_by_subject_with_nested_field_filter(self):
        """Test filtering nested fields in response."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        params = {
            "resource_id": str(self.default_workspace.id),
            "resource_type": "workspace",
            "fields": "subject(id,type,group)",
        }
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]

        self.assertGreater(len(data), 0)
        first_item = data[0]

        # Check subject has only requested fields
        self.assertIn("subject", first_item)
        subject = first_item["subject"]
        self.assertIn("id", subject)
        self.assertIn("type", subject)
        self.assertIn("group", subject)
        # User should not be present
        self.assertNotIn("user", subject)

    def test_list_by_subject_with_deeply_nested_field_filter(self):
        """Test filtering deeply nested fields like group.name."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        params = {
            "resource_id": str(self.default_workspace.id),
            "resource_type": "workspace",
            "fields": "subject(group.name,group.description)",
        }
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]

        self.assertGreater(len(data), 0)
        first_item = data[0]

        # Check subject.group has only requested fields
        self.assertIn("subject", first_item)
        subject = first_item["subject"]
        self.assertIn("group", subject)
        group = subject["group"]
        self.assertIn("name", group)
        self.assertIn("description", group)
        # user_count should be filtered out
        self.assertNotIn("user_count", group)

    def test_list_by_subject_with_array_field_filter(self):
        """Test filtering fields in array (roles)."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        params = {
            "resource_id": str(self.default_workspace.id),
            "resource_type": "workspace",
            "fields": "roles(name)",
        }
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]

        self.assertGreater(len(data), 0)
        first_item = data[0]

        # Check roles array has only name field
        self.assertIn("roles", first_item)
        roles = first_item["roles"]
        self.assertGreater(len(roles), 0)
        first_role = roles[0]
        self.assertIn("name", first_role)
        # id should be filtered out
        self.assertNotIn("id", first_role)

    def test_list_by_subject_with_mixed_field_filter(self):
        """Test filtering with mixed simple and nested fields."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        params = {
            "resource_id": str(self.default_workspace.id),
            "resource_type": "workspace",
            "fields": "subject(id,group.name),roles(name),resource",
        }
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]

        self.assertGreater(len(data), 0)
        first_item = data[0]

        # Check subject
        self.assertIn("subject", first_item)
        subject = first_item["subject"]
        self.assertIn("id", subject)
        self.assertIn("group", subject)
        self.assertIn("name", subject["group"])
        # description should be filtered out
        self.assertNotIn("description", subject["group"])

        # Check roles
        self.assertIn("roles", first_item)
        self.assertIn("name", first_item["roles"][0])
        self.assertNotIn("id", first_item["roles"][0])

        # Check resource (full object since no nested filter)
        self.assertIn("resource", first_item)
        resource = first_item["resource"]
        self.assertIn("id", resource)
        self.assertIn("name", resource)
        self.assertIn("type", resource)

    def test_list_by_subject_with_all_fields(self):
        """Test response structure when all fields are included."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        params = {
            "resource_id": str(self.default_workspace.id),
            "resource_type": "workspace",
            "fields": "subject,roles,resource,last_modified",
        }
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]

        self.assertGreater(len(data), 0)
        first_item = data[0]

        # All top-level fields should be present
        self.assertIn("subject", first_item)
        self.assertIn("roles", first_item)
        self.assertIn("resource", first_item)
        self.assertIn("last_modified", first_item)

        # Check subject structure
        subject = first_item["subject"]
        self.assertIn("id", subject)
        self.assertIn("type", subject)
        self.assertEqual(subject["type"], "group")
        self.assertIn("group", subject)

        # Check group details
        group = subject["group"]
        self.assertIn("name", group)
        self.assertEqual(group["name"], "Test Group")
        self.assertIn("description", group)
        self.assertIn("user_count", group)

        # Check roles structure
        roles = first_item["roles"]
        self.assertIsInstance(roles, list)
        self.assertGreater(len(roles), 0)
        self.assertIn("id", roles[0])
        self.assertIn("name", roles[0])

        # Check resource structure
        resource = first_item["resource"]
        self.assertIn("id", resource)
        self.assertIn("name", resource)
        self.assertIn("type", resource)
        self.assertEqual(resource["type"], "workspace")

    def test_list_by_subject_without_field_filter(self):
        """Test that all fields are returned when no field filter is specified."""
        url = reverse("v2_management:role-bindings-by-subject")
        client = APIClient()

        params = {
            "resource_id": str(self.default_workspace.id),
            "resource_type": "workspace",
        }
        response = client.get(url, params, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]

        self.assertGreater(len(data), 0)
        first_item = data[0]

        # All fields should be present by default
        self.assertIn("subject", first_item)
        self.assertIn("roles", first_item)
        self.assertIn("resource", first_item)
        self.assertIn("last_modified", first_item)
