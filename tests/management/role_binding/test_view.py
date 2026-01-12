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
"""Test the RoleBindingViewSet."""
from importlib import reload
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.test.utils import override_settings
from django.urls import clear_url_caches, reverse
from rest_framework import status
from rest_framework.test import APIClient

from management.models import Group, Permission, Principal, Workspace
from management.role.v2_model import RoleBinding, RoleBindingGroup, RoleV2
from management.tenant_mapping.model import TenantMapping
from rbac import urls
from tests.identity_request import IdentityRequest


@override_settings(V2_APIS_ENABLED=True)
class RoleBindingViewSetTest(IdentityRequest):
    """Test the RoleBindingViewSet."""

    def setUp(self):
        """Set up test data."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.client = APIClient()

        # Create workspace hierarchy (root -> default -> standard)
        self.root_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.ROOT,
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
        )
        self.default_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.DEFAULT,
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            parent=self.root_workspace,
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            description="Test workspace description",
            tenant=self.tenant,
            type=Workspace.Types.STANDARD,
            parent=self.default_workspace,
        )

        # Create permission and role
        self.permission = Permission.objects.create(
            permission="app:resource:read",
            tenant=self.tenant,
        )

        self.role = RoleV2.objects.create(
            name="test_role",
            tenant=self.tenant,
        )
        self.role.permissions.add(self.permission)

        # Create multiple roles and bindings to test pagination
        self.groups = []
        self.bindings = []
        self.roles = [self.role]

        for i in range(15):
            # Create a unique role for each binding
            role = RoleV2.objects.create(
                name=f"test_role_{i}",
                tenant=self.tenant,
            )
            role.permissions.add(self.permission)
            self.roles.append(role)

            group = Group.objects.create(
                name=f"test_group_{i}",
                description=f"Test group {i} description",
                tenant=self.tenant,
            )
            self.groups.append(group)

            principal = Principal.objects.create(
                username=f"user_{i}",
                tenant=self.tenant,
                type=Principal.Types.USER,
            )
            group.principals.add(principal)

            binding = RoleBinding.objects.create(
                role=role,
                resource_type="workspace",
                resource_id=str(self.workspace.id),
                tenant=self.tenant,
            )
            self.bindings.append(binding)

            RoleBindingGroup.objects.create(
                group=group,
                binding=binding,
            )

    def tearDown(self):
        """Tear down test data."""
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.all().delete()
        for group in self.groups:
            group.principals.clear()
        Principal.objects.filter(tenant=self.tenant).delete()
        Group.objects.filter(tenant=self.tenant).delete()
        RoleV2.objects.filter(tenant=self.tenant).delete()
        Permission.objects.filter(tenant=self.tenant).delete()
        # Delete workspaces in correct order (children first)
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.STANDARD).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.DEFAULT).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.ROOT).delete()
        super().tearDown()

    def _get_by_subject_url(self):
        """Get the by-subject URL."""
        return reverse("v2_management:role-bindings-by-subject")

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_returns_paginated_response(self, mock_permission):
        """Test that by_subject returns a paginated response structure."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("meta", response.data)
        self.assertIn("links", response.data)
        self.assertIn("data", response.data)
        self.assertIn("limit", response.data["meta"])
        self.assertIn("next", response.data["links"])
        self.assertIn("previous", response.data["links"])

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_default_limit(self, mock_permission):
        """Test that default limit is 10."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["meta"]["limit"], 10)
        self.assertEqual(len(response.data["data"]), 10)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_custom_limit(self, mock_permission):
        """Test that custom limit is respected."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&limit=5",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["meta"]["limit"], 5)
        self.assertEqual(len(response.data["data"]), 5)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_cursor_pagination(self, mock_permission):
        """Test that cursor pagination works correctly."""
        url = self._get_by_subject_url()

        # Get first page
        response1 = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&limit=5",
            **self.headers,
        )
        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        page1_subjects = [item["subject"]["id"] for item in response1.data["data"]]

        # Get next page using cursor
        next_link = response1.data["links"]["next"]
        self.assertIsNotNone(next_link)

        parsed = urlparse(next_link)
        cursor = parse_qs(parsed.query).get("cursor", [None])[0]
        self.assertIsNotNone(cursor)

        response2 = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&limit=5&cursor={cursor}",
            **self.headers,
        )
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        page2_subjects = [item["subject"]["id"] for item in response2.data["data"]]

        # Pages should have different subjects
        self.assertEqual(len(set(page1_subjects) & set(page2_subjects)), 0)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_empty_results(self, mock_permission):
        """Test that empty results return valid structure."""
        url = self._get_by_subject_url()

        # Use a non-existent workspace ID
        response = self.client.get(
            f"{url}?resource_id=00000000-0000-0000-0000-000000000000&resource_type=workspace",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"], [])
        self.assertIsNone(response.data["links"]["next"])
        self.assertIsNone(response.data["links"]["previous"])

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_first_page_has_no_previous(self, mock_permission):
        """Test that first page has no previous link."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&limit=5",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data["links"]["previous"])
        self.assertIsNotNone(response.data["links"]["next"])

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_last_page_has_no_next(self, mock_permission):
        """Test that last page has no next link."""
        url = self._get_by_subject_url()

        # Request all items in one page
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data["links"]["next"])

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_requires_resource_id(self, mock_permission):
        """Test that resource_id is required."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_type=workspace",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_requires_resource_type(self, mock_permission):
        """Test that resource_type is required."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_data_structure(self, mock_permission):
        """Test that response data matches expected default structure.

        Default behavior returns only basic required fields:
        - subject: id, type (no group details)
        - roles: id only
        - resource: id only
        - no last_modified
        """
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&limit=1",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)

        item = response.data["data"][0]

        # Verify structure - no last_modified by default
        self.assertNotIn("last_modified", item)
        self.assertIn("subject", item)
        self.assertIn("roles", item)
        self.assertIn("resource", item)

        # Verify subject structure - only id and type by default
        subject = item["subject"]
        self.assertIn("id", subject)
        self.assertIn("type", subject)
        self.assertEqual(subject["type"], "group")
        self.assertNotIn("group", subject)

        # Verify roles structure - only id by default
        self.assertIsInstance(item["roles"], list)
        if item["roles"]:
            self.assertIn("id", item["roles"][0])
            self.assertNotIn("name", item["roles"][0])

        # Verify resource structure - only id by default
        resource = item["resource"]
        self.assertIn("id", resource)
        self.assertNotIn("name", resource)
        self.assertNotIn("type", resource)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_strips_nul_bytes_from_resource_id(self, mock_permission):
        """Test that NUL bytes are stripped from resource_id parameter."""
        url = self._get_by_subject_url()
        # Include NUL byte in resource_id - should be stripped and return empty results
        response = self.client.get(
            f"{url}?resource_id=\x00{self.workspace.id}\x00&resource_type=workspace",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_strips_nul_bytes_from_resource_type(self, mock_permission):
        """Test that NUL bytes are stripped from resource_type parameter."""
        url = self._get_by_subject_url()
        # Include NUL byte in resource_type - should be stripped
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=\x00workspace\x00",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_nul_only_resource_id_returns_error(self, mock_permission):
        """Test that resource_id with only NUL bytes returns validation error."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id=\x00&resource_type=workspace",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_nul_only_resource_type_returns_error(self, mock_permission):
        """Test that resource_type with only NUL bytes returns validation error."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=\x00",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    @patch("management.role_binding.service.read_tuples_from_kessel")
    def test_by_subject_includes_virtual_bindings(self, mock_read_tuples, mock_permission):
        """Test that virtual bindings are included in the API response."""
        # Create TenantMapping
        tenant_mapping = TenantMapping.objects.create(tenant=self.tenant)

        # Create platform default group (not custom)
        platform_group = Group.objects.create(
            name="Platform Default Group",
            tenant=self.tenant,
            platform_default=False,
        )

        # Create a role for virtual bindings
        virtual_role = RoleV2.objects.create(
            name="virtual_role",
            tenant=self.tenant,
        )

        binding_id = str(tenant_mapping.default_role_binding_uuid)
        group_id = str(platform_group.uuid)
        role_id = str(virtual_role.uuid)

        # Mock Relations API responses
        def read_tuples_fn(resource_type, resource_id, relation, subject_type, subject_id=""):
            if relation == "binding" and resource_type == "workspace":
                return [
                    {
                        "tuple": {
                            "resource": {
                                "type": {"namespace": "rbac", "name": "workspace"},
                                "id": str(self.default_workspace.id),
                            },
                            "relation": "binding",
                            "subject": {
                                "subject": {
                                    "type": {"namespace": "rbac", "name": "role_binding"},
                                    "id": binding_id,
                                },
                            },
                        }
                    }
                ]
            elif relation == "subject" and resource_type == "role_binding":
                return [
                    {
                        "tuple": {
                            "resource": {
                                "type": {"namespace": "rbac", "name": "role_binding"},
                                "id": binding_id,
                            },
                            "relation": "subject",
                            "subject": {
                                "subject": {
                                    "type": {"namespace": "rbac", "name": "group"},
                                    "id": group_id,
                                },
                            },
                        }
                    }
                ]
            elif relation == "role" and resource_type == "role_binding":
                return [
                    {
                        "tuple": {
                            "resource": {
                                "type": {"namespace": "rbac", "name": "role_binding"},
                                "id": binding_id,
                            },
                            "relation": "role",
                            "subject": {
                                "subject": {
                                    "type": {"namespace": "rbac", "name": "role"},
                                    "id": role_id,
                                },
                            },
                        }
                    }
                ]
            return []

        mock_read_tuples.side_effect = read_tuples_fn

        # Make API request
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.default_workspace.id}&resource_type=workspace",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("data", response.data)

        # Check that platform group is in results (even though it has no database bindings)
        group_ids = [item["subject"]["id"] for item in response.data["data"]]
        self.assertIn(platform_group.uuid, group_ids)

        # Find the group in results and check it has the virtual role
        platform_group_data = next(
            item for item in response.data["data"] if item["subject"]["id"] == platform_group.uuid
        )
        role_ids = [role["id"] for role in platform_group_data["roles"]]
        self.assertIn(virtual_role.uuid, role_ids)

        # Cleanup
        TenantMapping.objects.filter(tenant=self.tenant).delete()
        platform_group.delete()
        virtual_role.delete()
