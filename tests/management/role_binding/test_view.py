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

import base64
import json
import uuid
from importlib import reload
from unittest import skip
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.test import TestCase
from django.test.utils import override_settings
from django.urls import clear_url_caches, reverse
from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant
from management.group.definer import seed_group
from management.group.platform import GlobalPolicyIdService
from management.models import Group, Permission, Principal, Workspace
from management.permission.scope_service import Scope
from management.role.definer import seed_roles
from management.role.platform import platform_v2_role_uuid_for
from management.role.v2_model import PlatformRoleV2, RoleBinding, RoleBindingGroup, RoleBindingPrincipal, RoleV2
from management.role_binding.service import RoleBindingService
from management.tenant_mapping.model import DefaultAccessType, TenantMapping
from management.tenant_service.v2 import V2TenantBootstrapService
from migration_tool.in_memory_tuples import InMemoryRelationReplicator
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

            # Create RoleBindingPrincipal for user-type queries
            RoleBindingPrincipal.objects.create(
                principal=principal,
                binding=binding,
                source="test",
            )

    def tearDown(self):
        """Tear down test data."""
        RoleBindingPrincipal.objects.all().delete()
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

    # Parent role bindings tests

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_parent_role_bindings_false_returns_direct_only(self, mock_permission):
        """Test that parent_role_bindings=false returns only direct bindings."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&parent_role_bindings=false&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should return direct bindings for the workspace
        self.assertEqual(len(response.data["data"]), 15)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_without_parent_role_bindings_returns_direct_only(self, mock_permission):
        """Test that omitting parent_role_bindings returns only direct bindings (default)."""
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should return direct bindings for the workspace
        self.assertEqual(len(response.data["data"]), 15)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    @patch("management.role_binding.service.settings")
    def test_by_subject_parent_role_bindings_true_without_relations_server(self, mock_settings, mock_permission):
        """Test that parent_role_bindings=true without RELATION_API_SERVER falls back to direct only."""
        mock_settings.RELATION_API_SERVER = None

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&parent_role_bindings=true&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should still return direct bindings when Relations API is not configured
        self.assertEqual(len(response.data["data"]), 15)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    @patch("management.role_binding.service.RoleBindingService._lookup_binding_uuids_via_relations")
    def test_by_subject_parent_role_bindings_true_includes_inherited(self, mock_lookup, mock_permission):
        """Test that parent_role_bindings=true includes inherited bindings from Relations API."""
        # Create a binding on parent workspace
        parent_role = RoleV2.objects.create(
            name="parent_role",
            tenant=self.tenant,
        )
        parent_group = Group.objects.create(
            name="parent_group",
            tenant=self.tenant,
        )
        parent_binding = RoleBinding.objects.create(
            role=parent_role,
            resource_type="workspace",
            resource_id=str(self.default_workspace.id),
            tenant=self.tenant,
        )
        RoleBindingGroup.objects.create(
            group=parent_group,
            binding=parent_binding,
        )

        # Mock Relations API to return the parent binding UUID
        mock_lookup.return_value = [str(parent_binding.uuid)]

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&parent_role_bindings=true&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should include 15 direct bindings + 1 inherited binding
        self.assertEqual(len(response.data["data"]), 16)

        # Verify parent_group is in the response
        subject_ids = [item["subject"]["id"] for item in response.data["data"]]
        self.assertIn(str(parent_group.uuid), [str(sid) for sid in subject_ids])

        # Cleanup
        RoleBindingGroup.objects.filter(binding=parent_binding).delete()
        parent_binding.delete()
        parent_group.delete()
        parent_role.delete()

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    @patch("management.role_binding.service.RoleBindingService._lookup_binding_uuids_via_relations")
    def test_by_subject_parent_role_bindings_true_with_empty_inherited(self, mock_lookup, mock_permission):
        """Test that parent_role_bindings=true with no inherited bindings returns direct only."""
        # Mock Relations API to return empty list
        mock_lookup.return_value = []

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&parent_role_bindings=true&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should return only direct bindings
        self.assertEqual(len(response.data["data"]), 15)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    @patch("management.role_binding.service.RoleBindingService._lookup_binding_uuids_via_relations")
    def test_by_subject_parent_role_bindings_true_with_relations_error(self, mock_lookup, mock_permission):
        """Test that parent_role_bindings=true gracefully handles Relations API errors."""
        # Mock Relations API to return None (error case)
        mock_lookup.return_value = None

        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&parent_role_bindings=true&limit=100",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should fall back to direct bindings only
        self.assertEqual(len(response.data["data"]), 15)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_by_subject_parent_role_bindings_accepts_boolean_string(self, mock_permission):
        """Test that parent_role_bindings accepts 'true' and 'false' strings."""
        url = self._get_by_subject_url()

        # Test with 'true' string
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&parent_role_bindings=true",
            **self.headers,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test with 'false' string
        response = self.client.get(
            f"{url}?resource_id={self.workspace.id}&resource_type=workspace&parent_role_bindings=false",
            **self.headers,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)


@override_settings(V2_APIS_ENABLED=True)
class DefaultBindingsAPITests(TestCase):
    """Test lazy creation of default role bindings via API calls."""

    def setUp(self):
        """Set up test data for each test."""
        super().setUp()
        reload(urls)
        clear_url_caches()

        # Clear caches to ensure fresh state - other tests might have modified these
        GlobalPolicyIdService.clear_shared()
        Tenant._public_tenant = None  # Clear the public tenant cache

        # Seed platform roles and default groups (required for default bindings)
        # Moved to setUp() instead of setUpClass() to avoid race conditions in parallel test execution
        seed_roles()
        seed_group()

        # Use V2 bootstrap to create tenant with TenantMapping
        # Use a unique org_id to avoid conflicts when running tests in parallel
        unique_org_id = f"test-default-bindings-api-{uuid.uuid4().hex[:8]}"

        self.replicator = InMemoryRelationReplicator()
        self.bootstrap_service = V2TenantBootstrapService(self.replicator)
        bootstrapped = self.bootstrap_service.new_bootstrapped_tenant(unique_org_id)
        self.tenant = bootstrapped.tenant
        self.mapping = bootstrapped.mapping
        self.default_workspace = bootstrapped.default_workspace

        # Set up API client with proper headers
        self.client = APIClient()
        self.headers = {
            "HTTP_X_RH_IDENTITY": self._create_identity_header(),
        }

        self.service = RoleBindingService(tenant=self.tenant)

    def _create_identity_header(self):
        """Create an identity header for API requests."""
        identity = {
            "identity": {
                "account_number": "12345",
                "org_id": self.tenant.org_id,
                "type": "User",
                "user": {
                    "username": "test_user",
                    "email": "test@example.com",
                    "is_org_admin": True,
                    "is_internal": False,
                    "user_id": "123456",
                },
                "internal": {"org_id": self.tenant.org_id},
            }
        }
        return base64.b64encode(json.dumps(identity).encode()).decode()

    def tearDown(self):
        """Clean up test data."""
        # Clean up in reverse dependency order
        RoleBindingGroup.objects.filter(binding__tenant=self.tenant).delete()
        RoleBinding.objects.filter(tenant=self.tenant).delete()
        Group.objects.filter(tenant=self.tenant).delete()
        # Delete workspaces in order: standard, default, root (child to parent)
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.STANDARD).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.DEFAULT).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.ROOT).delete()
        TenantMapping.objects.filter(tenant=self.tenant).delete()
        self.tenant.delete()

    def _get_by_subject_url(self):
        """Get the by-subject URL."""
        return reverse("v2_management:role-bindings-by-subject")

    def _count_default_bindings(self, access_type: DefaultAccessType) -> int:
        """Count existing default bindings for the given access type."""
        binding_uuids = [self.mapping.default_role_binding_uuid_for(access_type, s) for s in Scope]
        return RoleBinding.objects.filter(uuid__in=binding_uuids).count()

    @skip("Flaky: fails intermittently in CI when tests run in parallel due to test isolation issues")
    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_default_bindings_created_on_api_call(self, mock_permission):
        """Test that default bindings are created when API is called.

        Also verifies that platform roles return their children (seeded roles)
        instead of the platform role itself in the API response.
        """
        # Initially, no default bindings should exist
        self.assertEqual(self._count_default_bindings(DefaultAccessType.USER), 0)
        self.assertEqual(self._count_default_bindings(DefaultAccessType.ADMIN), 0)

        # Call the API
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.default_workspace.id}&resource_type=workspace",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Now all 6 default bindings should exist (3 USER + 3 ADMIN for each scope)
        self.assertEqual(self._count_default_bindings(DefaultAccessType.USER), 3)
        self.assertEqual(self._count_default_bindings(DefaultAccessType.ADMIN), 3)

        # Verify that platform roles return their children, not the platform role itself
        data = response.data["data"]
        public_tenant = Tenant.objects.get(tenant_name="public")

        # Get platform default groups (used for default bindings)
        platform_default_group = Group.objects.get(platform_default=True, tenant=public_tenant)
        admin_default_group = Group.objects.get(admin_default=True, tenant=public_tenant)

        # Find these groups in the response
        platform_group_data = None
        admin_group_data = None
        for item in data:
            if str(item["subject"]["id"]) == str(platform_default_group.uuid):
                platform_group_data = item
            if str(item["subject"]["id"]) == str(admin_default_group.uuid):
                admin_group_data = item

        # Assert that both groups are present before verifying their roles
        self.assertIsNotNone(
            platform_group_data,
            f"Platform default group {platform_default_group.uuid} should be in response",
        )
        self.assertIsNotNone(
            admin_group_data,
            f"Admin default group {admin_default_group.uuid} should be in response",
        )

        # Get the platform roles used in default bindings
        policy_service = GlobalPolicyIdService.shared()

        # Verify platform default group returns children
        role_ids = [str(role["id"]) for role in platform_group_data["roles"]]
        platform_role_uuid = platform_v2_role_uuid_for(DefaultAccessType.USER, Scope.DEFAULT, policy_service)
        platform_role = PlatformRoleV2.objects.get(uuid=platform_role_uuid)

        # Platform role should NOT be in response
        self.assertNotIn(str(platform_role.uuid), role_ids, "Platform role should not be returned")

        # Children should be in response
        child_uuids = [str(child.uuid) for child in platform_role.children.all()]
        for child_uuid in child_uuids:
            self.assertIn(child_uuid, role_ids, f"Child role {child_uuid} should be returned")

        # Verify admin default group returns children
        role_ids = [str(role["id"]) for role in admin_group_data["roles"]]
        admin_role_uuid = platform_v2_role_uuid_for(DefaultAccessType.ADMIN, Scope.DEFAULT, policy_service)
        admin_role = PlatformRoleV2.objects.get(uuid=admin_role_uuid)

        # Platform role should NOT be in response
        self.assertNotIn(str(admin_role.uuid), role_ids, "Admin platform role should not be returned")

        # Children should be in response
        child_uuids = [str(child.uuid) for child in admin_role.children.all()]
        for child_uuid in child_uuids:
            self.assertIn(child_uuid, role_ids, f"Admin child role {child_uuid} should be returned")

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_user_bindings_skipped_with_custom_default_group(self, mock_permission):
        """Test that USER bindings are skipped when tenant has a custom default group."""
        # Create a custom default group for this tenant
        custom_group = Group.objects.create(
            name="Custom default access",
            tenant=self.tenant,
            platform_default=True,
            system=False,
        )

        # Initially no bindings
        self.assertEqual(self._count_default_bindings(DefaultAccessType.USER), 0)
        self.assertEqual(self._count_default_bindings(DefaultAccessType.ADMIN), 0)

        # Call the API
        url = self._get_by_subject_url()
        response = self.client.get(
            f"{url}?resource_id={self.default_workspace.id}&resource_type=workspace",
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # USER bindings should NOT be created (custom group exists)
        self.assertEqual(self._count_default_bindings(DefaultAccessType.USER), 0)
        # ADMIN bindings should still be created
        self.assertEqual(self._count_default_bindings(DefaultAccessType.ADMIN), 3)

        # Cleanup
        custom_group.delete()

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_delete_user_default_bindings(self, mock_permission):
        """Test that delete_user_default_bindings removes USER bindings."""
        # First create the default bindings via API
        url = self._get_by_subject_url()
        self.client.get(
            f"{url}?resource_id={self.default_workspace.id}&resource_type=workspace",
            **self.headers,
        )

        # Verify bindings exist
        self.assertEqual(self._count_default_bindings(DefaultAccessType.USER), 3)
        self.assertEqual(self._count_default_bindings(DefaultAccessType.ADMIN), 3)

        # Delete USER bindings using the service (simulating custom group creation)
        self.service.delete_user_default_bindings()

        # USER bindings should be deleted, ADMIN bindings should remain
        self.assertEqual(self._count_default_bindings(DefaultAccessType.USER), 0)
        self.assertEqual(self._count_default_bindings(DefaultAccessType.ADMIN), 3)

    @patch(
        "management.permissions.role_binding_access.RoleBindingKesselAccessPermission.has_permission",
        return_value=True,
    )
    def test_restore_user_default_bindings(self, mock_permission):
        """Test that restore_user_default_bindings recreates USER bindings."""
        # First create all default bindings via API
        url = self._get_by_subject_url()
        self.client.get(
            f"{url}?resource_id={self.default_workspace.id}&resource_type=workspace",
            **self.headers,
        )

        # Delete USER bindings (simulating custom group creation)
        self.service.delete_user_default_bindings()
        self.assertEqual(self._count_default_bindings(DefaultAccessType.USER), 0)

        # Restore USER bindings (simulating custom group deletion)
        self.service.restore_user_default_bindings()

        # USER bindings should be restored
        self.assertEqual(self._count_default_bindings(DefaultAccessType.USER), 3)
        self.assertEqual(self._count_default_bindings(DefaultAccessType.ADMIN), 3)
