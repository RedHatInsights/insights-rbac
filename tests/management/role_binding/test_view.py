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

    # Ordering tests using dot notation

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_group_name_ascending(self, mock_permission):
        """Test ordering by group.name ascending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=group.name&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract group names and verify ascending order
        group_uuids = [item["subject"]["id"] for item in data]
        groups = Group.objects.filter(uuid__in=group_uuids)
        group_name_map = {str(g.uuid): g.name for g in groups}
        names = [group_name_map[str(item["subject"]["id"])] for item in data]
        self.assertEqual(names, sorted(names))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_group_name_descending(self, mock_permission):
        """Test ordering by group.name descending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=-group.name&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract group names and verify descending order
        group_uuids = [item["subject"]["id"] for item in data]
        groups = Group.objects.filter(uuid__in=group_uuids)
        group_name_map = {str(g.uuid): g.name for g in groups}
        names = [group_name_map[str(item["subject"]["id"])] for item in data]
        self.assertEqual(names, sorted(names, reverse=True))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_role_name_ascending(self, mock_permission):
        """Test ordering by role.name ascending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=role.name&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract role UUIDs and look up names from database to verify ascending order
        role_uuids = [item["roles"][0]["id"] for item in data if item["roles"]]
        roles = RoleV2.objects.filter(uuid__in=role_uuids)
        role_name_map = {str(r.uuid): r.name for r in roles}
        role_names = [role_name_map[str(item["roles"][0]["id"])] for item in data if item["roles"]]
        self.assertEqual(role_names, sorted(role_names))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_role_name_descending(self, mock_permission):
        """Test ordering by role.name descending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=-role.name&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract role UUIDs and look up names from database to verify descending order
        role_uuids = [item["roles"][0]["id"] for item in data if item["roles"]]
        roles = RoleV2.objects.filter(uuid__in=role_uuids)
        role_name_map = {str(r.uuid): r.name for r in roles}
        role_names = [role_name_map[str(item["roles"][0]["id"])] for item in data if item["roles"]]
        self.assertEqual(role_names, sorted(role_names, reverse=True))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_group_modified(self, mock_permission):
        """Test ordering by group.modified descending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=-group.modified&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract group modified timestamps and verify descending order
        group_uuids = [item["subject"]["id"] for item in data]
        groups = Group.objects.filter(uuid__in=group_uuids)
        group_modified_map = {str(g.uuid): g.modified for g in groups}
        modified_times = [group_modified_map[str(item["subject"]["id"])] for item in data]
        self.assertEqual(modified_times, sorted(modified_times, reverse=True))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_group_created(self, mock_permission):
        """Test ordering by group.created ascending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=group.created&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract group created timestamps and verify ascending order
        group_uuids = [item["subject"]["id"] for item in data]
        groups = Group.objects.filter(uuid__in=group_uuids)
        group_created_map = {str(g.uuid): g.created for g in groups}
        created_times = [group_created_map[str(item["subject"]["id"])] for item in data]
        self.assertEqual(created_times, sorted(created_times))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_rejects_direct_field_name(self, mock_permission):
        """Test that ordering by direct field name (without dot notation) is rejected."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=name",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid ordering field", str(response.data))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_rejects_unknown_field(self, mock_permission):
        """Test that ordering by unknown dot notation field is rejected."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=foo.bar",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid ordering field", str(response.data))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_comma_separated_fields(self, mock_permission):
        """Test ordering by multiple comma-separated fields."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=group.name,-group.modified&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Verify primary ordering by group.name ascending
        group_uuids = [item["subject"]["id"] for item in data]
        groups = Group.objects.filter(uuid__in=group_uuids)
        group_name_map = {str(g.uuid): g.name for g in groups}
        names = [group_name_map[str(item["subject"]["id"])] for item in data]
        self.assertEqual(names, sorted(names))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_multiple_params(self, mock_permission):
        """Test ordering by multiple order_by parameters."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=group.name&order_by=-group.modified&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Verify primary ordering by group.name ascending
        group_uuids = [item["subject"]["id"] for item in data]
        groups = Group.objects.filter(uuid__in=group_uuids)
        group_name_map = {str(g.uuid): g.name for g in groups}
        names = [group_name_map[str(item["subject"]["id"])] for item in data]
        self.assertEqual(names, sorted(names))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_rejects_mixed_valid_invalid(self, mock_permission):
        """Test that ordering with mixed valid and invalid fields is rejected."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=group.name,invalid_field",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid ordering field", str(response.data))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_group_uuid(self, mock_permission):
        """Test ordering by group.uuid ascending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=group.uuid&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Verify uuid ordering (convert to strings for consistent comparison)
        uuids = [str(item["subject"]["id"]) for item in data]
        self.assertEqual(uuids, sorted(uuids))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_group_uuid_descending(self, mock_permission):
        """Test ordering by group.uuid descending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=-group.uuid&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Verify uuid ordering descending (convert to strings for consistent comparison)
        uuids = [str(item["subject"]["id"]) for item in data]
        self.assertEqual(uuids, sorted(uuids, reverse=True))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_role_uuid(self, mock_permission):
        """Test ordering by role.uuid ascending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=role.uuid&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract role UUIDs and verify ascending order
        role_uuids = [str(item["roles"][0]["id"]) for item in data if item["roles"]]
        self.assertEqual(role_uuids, sorted(role_uuids))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_role_modified(self, mock_permission):
        """Test ordering by role.modified descending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=-role.modified&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract role UUIDs and verify modified times are in descending order
        role_uuids = [item["roles"][0]["id"] for item in data if item["roles"]]
        roles = RoleV2.objects.filter(uuid__in=role_uuids)
        role_modified_map = {str(r.uuid): r.modified for r in roles}
        modified_times = [role_modified_map[str(item["roles"][0]["id"])] for item in data if item["roles"]]
        self.assertEqual(modified_times, sorted(modified_times, reverse=True))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_order_by_role_created(self, mock_permission):
        """Test ordering by role.created ascending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&order_by=role.created&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract role UUIDs and verify created times are in ascending order
        role_uuids = [item["roles"][0]["id"] for item in data if item["roles"]]
        roles = RoleV2.objects.filter(uuid__in=role_uuids)
        role_created_map = {str(r.uuid): r.created for r in roles}
        created_times = [role_created_map[str(item["roles"][0]["id"])] for item in data if item["roles"]]
        self.assertEqual(created_times, sorted(created_times))

    # User subject type tests

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_user_type_returns_users(self, mock_permission):
        """Test that subject_type=user returns users (principals)."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=user&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]

        # Should return users (we have 15 groups with 1 user each)
        self.assertEqual(len(data), 15)

        # Verify all subjects are type="user"
        for item in data:
            self.assertEqual(item["subject"]["type"], "user")

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_user_type_data_structure(self, mock_permission):
        """Test that user subject type response has correct structure."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=user&limit=1",
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

        # Verify subject structure - id and type, no user details by default
        subject = item["subject"]
        self.assertIn("id", subject)
        self.assertIn("type", subject)
        self.assertEqual(subject["type"], "user")
        self.assertNotIn("user", subject)

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
    def test_by_subject_user_type_with_fields_parameter(self, mock_permission):
        """Test that user subject type works with fields parameter."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=user"
            "&fields=subject(user.username),role(name),resource(type)&limit=1",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)

        item = response.data["data"][0]

        # Verify subject includes user.username
        subject = item["subject"]
        self.assertEqual(subject["type"], "user")
        self.assertIn("user", subject)
        self.assertIn("username", subject["user"])

        # Verify roles include name
        if item["roles"]:
            self.assertIn("name", item["roles"][0])

        # Verify resource includes type
        self.assertIn("type", item["resource"])

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_user_type_pagination(self, mock_permission):
        """Test that user subject type supports pagination."""
        url = self._get_by_subject_url()

        # Get first page
        response1 = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=user&limit=5",
            **self.headers,
        )
        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response1.data["data"]), 5)
        page1_subjects = [item["subject"]["id"] for item in response1.data["data"]]

        # Get next page
        next_link = response1.data["links"]["next"]
        self.assertIsNotNone(next_link)

        parsed = urlparse(next_link)
        cursor = parse_qs(parsed.query).get("cursor", [None])[0]
        self.assertIsNotNone(cursor)

        response2 = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=user&limit=5&cursor={cursor}",
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
    def test_by_subject_user_type_order_by_username(self, mock_permission):
        """Test ordering by user.username ascending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=user"
            "&order_by=user.username&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract usernames and verify ascending order
        user_uuids = [item["subject"]["id"] for item in data]
        principals = Principal.objects.filter(uuid__in=user_uuids)
        username_map = {str(p.uuid): p.username for p in principals}
        usernames = [username_map[str(item["subject"]["id"])] for item in data]
        self.assertEqual(usernames, sorted(usernames))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_user_type_order_by_username_descending(self, mock_permission):
        """Test ordering by user.username descending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=user"
            "&order_by=-user.username&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Extract usernames and verify descending order
        user_uuids = [item["subject"]["id"] for item in data]
        principals = Principal.objects.filter(uuid__in=user_uuids)
        username_map = {str(p.uuid): p.username for p in principals}
        usernames = [username_map[str(item["subject"]["id"])] for item in data]
        self.assertEqual(usernames, sorted(usernames, reverse=True))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_user_type_rejects_group_ordering_fields(self, mock_permission):
        """Test that group ordering fields are rejected for user subject type."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=user" "&order_by=group.name",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid ordering field", str(response.data))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_group_type_rejects_user_ordering_fields(self, mock_permission):
        """Test that user ordering fields are rejected for group subject type."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=group"
            "&order_by=user.username",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid ordering field", str(response.data))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_user_type_order_by_user_uuid(self, mock_permission):
        """Test ordering by user.uuid ascending."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=user"
            "&order_by=user.uuid&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data["data"]
        self.assertGreater(len(data), 1)

        # Verify uuid ordering
        uuids = [str(item["subject"]["id"]) for item in data]
        self.assertEqual(uuids, sorted(uuids))

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_user_type_empty_results(self, mock_permission):
        """Test that non-existent resource returns empty results for user type."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id=00000000-0000-0000-0000-000000000000&resource_type=workspace&subject_type=user",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"], [])

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_user_type_filter_by_subject_id(self, mock_permission):
        """Test filtering by subject_id with user type."""
        # Get a specific user's UUID
        first_principal = Principal.objects.filter(
            tenant=self.tenant,
            type=Principal.Types.USER,
            username__startswith="user_",
        ).first()

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&subject_type=user"
            f"&subject_id={first_principal.uuid}",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)
        self.assertEqual(str(response.data["data"][0]["subject"]["id"]), str(first_principal.uuid))
