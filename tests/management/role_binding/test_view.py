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
"""Tests for the V2 role binding viewset."""

from uuid import uuid4

from django.test.utils import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant
from management.group.model import Group
from management.principal.model import Principal
from management.role.v2_model import RoleV2, RoleBinding, RoleBindingGroup
from management.workspace.model import Workspace
from tests.identity_request import IdentityRequest
from unittest.mock import patch


@override_settings(V2_APIS_ENABLED=True)
class RoleBindingViewsetTests(IdentityRequest):
    """Test the v2 role binding by-subject endpoint."""

    def setUp(self):
        """Set up a tenant, workspace, group, principal and role bindings."""
        super().setUp()
        self.client = APIClient()

        # Ensure tenant exists in DB (IdentityRequest already created one, but we want the persisted instance)
        self.tenant = Tenant.objects.get(id=self.tenant.id)

        # Create a simple workspace hierarchy: parent (root) -> child (standard)
        self.parent_workspace = Workspace.objects.create(
            id=uuid4(),
            name="Parent Workspace",
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
        )
        self.child_workspace = Workspace.objects.create(
            id=uuid4(),
            name="Child Workspace",
            tenant=self.tenant,
            type=Workspace.Types.STANDARD,
            parent=self.parent_workspace,
        )

        # Subject group and principal
        self.group = Group.objects.create(tenant=self.tenant, name="Test Group")
        self.principal = Principal.objects.create(tenant=self.tenant, username="user@example.com")
        self.group.principals.add(self.principal)

        # V2 role and bindings
        self.role_v2 = RoleV2.objects.create(tenant=self.tenant, name="Workspace Admin")

        # Direct binding on child workspace
        self.direct_binding = RoleBinding.objects.create(
            tenant=self.tenant,
            role=self.role_v2,
            resource_type="workspace",
            resource_id=str(self.child_workspace.id),
        )
        RoleBindingGroup.objects.create(group=self.group, binding=self.direct_binding)

        # Inherited binding on parent workspace
        self.parent_binding = RoleBinding.objects.create(
            tenant=self.tenant,
            role=self.role_v2,
            resource_type="workspace",
            resource_id=str(self.parent_workspace.id),
        )
        RoleBindingGroup.objects.create(group=self.group, binding=self.parent_binding)

    def test_by_subject_direct_bindings_only(self):
        """When parent_role_bindings is false, only direct bindings are considered."""
        url = reverse("v2_management:role-bindings-by-subject")
        response = self.client.get(
            url,
            {
                "resource_type": "workspace",
                "resource_id": str(self.child_workspace.id),
                "subject_type": "group",
                "subject_id": str(self.group.uuid),
            },
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Using cursor pagination: DRF returns results list
        self.assertIn("results", response.data)
        self.assertEqual(len(response.data["results"]), 1)

        record = response.data["results"][0]
        self.assertIn("subject", record)
        self.assertEqual(record["subject"]["type"], "group")
        self.assertEqual(record["subject"]["group"]["id"], str(self.group.uuid))
        self.assertIn("roles", record)
        role_ids = {r["id"] for r in record["roles"]}
        self.assertIn(str(self.role_v2.uuid), role_ids)
        self.assertIn("resource", record)
        self.assertEqual(record["resource"]["id"], str(self.child_workspace.id))
        # No inherited_from section for direct-only queries
        self.assertIsNone(record.get("inherited_from"))

    @override_settings(RELATION_API_SERVER="localhost:9001")
    @patch("management.role_binding.view.RoleBindingViewSet._lookup_binding_uuids_via_relations")
    def test_by_subject_includes_inherited_from_relations(self, mock_lookup):
        """When parent_role_bindings is true, bindings returned from Relations are used."""
        # Simulate Relations returning both direct and parent binding UUIDs
        mock_lookup.return_value = [str(self.direct_binding.uuid), str(self.parent_binding.uuid)]

        url = reverse("v2_management:role-bindings-by-subject")
        response = self.client.get(
            url,
            {
                "resource_type": "workspace",
                "resource_id": str(self.child_workspace.id),
                "subject_type": "group",
                "subject_id": str(self.group.uuid),
                "parent_role_bindings": "true",
            },
            **self.headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertEqual(len(response.data["results"]), 1)

        record = response.data["results"][0]
        self.assertIn("roles", record)
        role_ids = {r["id"] for r in record["roles"]}
        self.assertIn(str(self.role_v2.uuid), role_ids)

        # The resource in the response should be the child workspace
        self.assertEqual(record["resource"]["id"], str(self.child_workspace.id))

        # inherited_from should include the parent workspace when Relations is used
        inherited = record.get("inherited_from")
        self.assertIsNotNone(inherited)
        parent_ids = {p["id"] for p in inherited}
        self.assertIn(str(self.parent_workspace.id), parent_ids)
