#
# Copyright 2024 Red Hat, Inc.
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
"""Test the Audit Logs Model."""
import json
import random
import string
from unittest import skip
from uuid import uuid4

from django.conf import settings
from django.test.utils import override_settings
from django.urls import clear_url_caches
from importlib import reload
from unittest.mock import patch
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant
from management.models import Access, Group, Permission, Policy, Principal, ResourceDefinition, Role, Workspace
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.workspace.serializer import WorkspaceEventSerializer
from management.workspace.service import WorkspaceService
from migration_tool.in_memory_tuples import (
    all_of,
    InMemoryRelationReplicator,
    InMemoryTuples,
    relation,
    resource,
    subject,
)
from migration_tool.utils import create_relationship
from rbac import urls
from tests.identity_request import IdentityRequest, TransactionalIdentityRequest


class BasicWorkspaceViewTests:
    def _get_random_name(self, length=10):
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def _setup_access_for_principal(self, username, permission, workspace_id=None, platform_default=False):
        group = Group(name=self._get_random_name(), platform_default=platform_default, tenant=self.tenant)
        group.save()
        role = Role.objects.create(
            name="".join(random.choices(string.ascii_letters + string.digits, k=5)),
            description="A role for a group.",
            tenant=self.tenant,
        )
        public_tenant, _ = Tenant.objects.get_or_create(tenant_name="public")
        permission, _ = Permission.objects.get_or_create(permission=permission, tenant=public_tenant)
        access = Access.objects.create(permission=permission, role=role, tenant=self.tenant)
        if workspace_id:
            operation = "in" if isinstance(workspace_id, list) else "equal"
            ResourceDefinition.objects.create(
                attributeFilter={
                    "key": "group.id",
                    "operation": operation,
                    "value": workspace_id,
                },
                access=access,
                tenant=self.tenant,
            )

        policy = Policy.objects.create(name=self._get_random_name(), group=group, tenant=self.tenant)
        policy.roles.add(role)
        policy.save()
        group.policies.add(policy)
        group.save()
        if not platform_default:
            principal, _ = Principal.objects.get_or_create(username=username, tenant=self.tenant)
            group.principals.add(principal)


class WorkspaceViewTests(IdentityRequest, BasicWorkspaceViewTests):
    """Test the Workspace view."""

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=10)
    def setUp(self):
        """Set up the workspace model tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.tenant.save()

        self.service = WorkspaceService()
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
        self.ungrouped_workspace = Workspace.objects.create(
            name="Ungrouped Hosts Workspace",
            description="Ungrouped Hosts Workspace - description",
            tenant=self.tenant,
            parent=self.default_workspace,
            type=Workspace.Types.UNGROUPED_HOSTS,
        )
        validated_data_standard_ws = {
            "name": "Standard Workspace",
            "description": "Standard Workspace - description",
            "parent_id": self.default_workspace.id,
        }
        self.standard_workspace = self.service.create(validated_data_standard_ws, self.tenant)
        validated_data_standard_sub_ws = {
            "name": "Standard Sub-workspace",
            "description": "Standard Workspace with another standard workspace parent.",
            "parent_id": self.standard_workspace.id,
        }
        self.standard_sub_workspace = self.service.create(validated_data_standard_sub_ws, self.tenant)

    def tearDown(self):
        """Tear down group model tests."""
        Workspace.objects.update(parent=None)
        Workspace.objects.all().delete()


class TransactionalWorkspaceViewTests(TransactionalIdentityRequest, BasicWorkspaceViewTests):
    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=10)
    def setUp(self):
        """Set up the workspace model tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.tenant.save()

        self.service = WorkspaceService()
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
        self.ungrouped_workspace = Workspace.objects.create(
            name="Ungrouped Hosts Workspace",
            description="Ungrouped Hosts Workspace - description",
            tenant=self.tenant,
            parent=self.default_workspace,
            type=Workspace.Types.UNGROUPED_HOSTS,
        )
        validated_data_standard_ws = {
            "name": "Standard Workspace",
            "description": "Standard Workspace - description",
            "parent_id": self.default_workspace.id,
        }
        self.standard_workspace = self.service.create(validated_data_standard_ws, self.tenant)
        validated_data_standard_sub_ws = {
            "name": "Standard Sub-workspace",
            "description": "Standard Workspace with another standard workspace parent.",
            "parent_id": self.standard_workspace.id,
        }
        self.standard_sub_workspace = self.service.create(validated_data_standard_sub_ws, self.tenant)


@override_settings(V2_APIS_ENABLED=True, WORKSPACE_HIERARCHY_DEPTH_LIMIT=100, WORKSPACE_RESTRICT_DEFAULT_PEERS=False)
class WorkspaceTestsCreateUpdateDelete(WorkspaceViewTests):
    """Tests for create/update/delete workspaces."""

    def setUp(self):
        super().setUp()
        self.tuples = InMemoryTuples()
        self.in_memory_replicator = InMemoryRelationReplicator(self.tuples)

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate_workspace")
    def test_create_workspace(self, replicate_workspace, replicate):
        """Test for creating a workspace."""
        replicate.side_effect = self.in_memory_replicator.replicate
        workspace = {"name": "New Workspace", "description": "Workspace", "parent_id": self.default_workspace.id}

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        data = response.data
        self.assertEqual(data.get("name"), "New Workspace")
        self.assertNotEqual(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEqual(data.get("created"), "")
        self.assertNotEqual(data.get("modified"), "")
        self.assertEqual(data.get("description"), "Workspace")
        self.assertEqual(data.get("type"), "standard")
        self.assertEqual(response.get("content-type"), "application/json")
        tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", data.get("id")),
                relation("parent"),
                subject("rbac", "workspace", str(self.default_workspace.id)),
            )
        )
        self.assertEqual(len(tuples), 1)
        workspace_event = replicate_workspace.call_args[0][0]
        self.assertEqual(workspace_event.account_number, self.tenant.account_id)
        self.assertEqual(workspace_event.org_id, self.tenant.org_id)
        self.assertEqual(workspace_event.event_type, ReplicationEventType.CREATE_WORKSPACE)
        data.pop("description")
        data.pop("parent_id")
        self.assertEqual(workspace_event.workspace, data)

    def test_create_workspace_against_root(self):
        """Test for creating a workspace against the root."""
        workspace = {"name": "Root Peer", "description": "Workspace", "parent_id": self.root_workspace.id}

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        data = response.data
        self.assertEqual(data.get("name"), "Root Peer")
        self.assertNotEqual(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEqual(data.get("created"), "")
        self.assertNotEqual(data.get("modified"), "")
        self.assertEqual(data.get("description"), "Workspace")
        self.assertEqual(data.get("type"), "standard")
        self.assertEqual(response.get("content-type"), "application/json")

    def test_create_workspace_assign_parent_id(self):
        """Test for creating a workspace without parent id."""
        workspace = {
            "name": "New Workspace",
            "description": "Workspace",
        }

        url = reverse("v2_management:workspace-list")
        client = APIClient()

        response = client.post(url, workspace, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        data = response.data

        self.assertEqual(data.get("name"), "New Workspace")
        self.assertNotEqual(data.get("id"), "")
        self.assertNotEqual(data.get("parent_id"), data.get("id"))
        self.assertIsNotNone(data.get("id"))
        self.assertNotEqual(data.get("created"), "")
        self.assertNotEqual(data.get("modified"), "")
        self.assertEqual(data.get("description"), "Workspace")
        self.assertEqual(data.get("type"), "standard")
        self.assertEqual(response.get("content-type"), "application/json")

    def test_create_workspace_empty_body(self):
        """Test for creating a workspace."""
        workspace = {}

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        status_code = response.data.get("status")
        detail = response.data.get("detail")
        self.assertIsNotNone(detail)
        self.assertEqual(detail, "This field is required.")

        self.assertEqual(status_code, 400)
        self.assertEqual(response.get("content-type"), "application/problem+json")

    def test_create_workspace_unauthorized(self):
        """Test for creating a workspace."""
        workspace = {}

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        status_code = response.data.get("status")
        detail = response.data.get("detail")
        self.assertEqual(detail, "You do not have permission to perform this action.")
        self.assertEqual(status_code, 403)
        self.assertEqual(response.get("content-type"), "application/problem+json")

    def test_create_workspace_authorized_through_custom_role(self):
        """Test for creating a workspace."""
        workspace = {
            "name": "New Workspace",
            "description": "Workspace",
        }

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META
        self._setup_access_for_principal(self.user_data["username"], "inventory:groups:read")

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self._setup_access_for_principal(self.user_data["username"], "inventory:groups:write")
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], workspace["name"])

    def test_create_workspace_authorized_through_platform_default_access(self):
        """Test for creating a workspace."""
        workspace = {
            "name": "New Workspace",
            "description": "Workspace",
        }

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META
        self._setup_access_for_principal(self.user_data["username"], "inventory:groups:read", platform_default=True)

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self._setup_access_for_principal(self.user_data["username"], "inventory:groups:write", platform_default=True)
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], workspace["name"])

    def test_create_workspace_authorized_through_platform_default_access_with_wildcard(self):
        """Test for creating a workspace."""
        workspace = {
            "name": "New Workspace",
            "description": "Workspace",
        }

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META

        self._setup_access_for_principal(self.user_data["username"], "inventory:*:write", platform_default=True)
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], workspace["name"])

        # Make sure "inventory:*:*" also works
        Group.objects.get(platform_default=True).delete()
        Workspace.objects.get(id=response.data["id"]).delete()
        response = client.post(url, workspace, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self._setup_access_for_principal(self.user_data["username"], "inventory:*:*", platform_default=True)
        response = client.post(url, workspace, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], workspace["name"])

    def test_create_workspace_authorized_with_default_workspace_permission_only(self):
        """Test for creating a workspace with only Default Workspace permission."""
        workspace = {
            "name": "New Workspace Default Only",
            "description": "Workspace created with Default Workspace permission only",
        }

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META

        # Set up access for Default Workspace only (not Root Workspace)
        self._setup_access_for_principal(
            self.user_data["username"], "inventory:groups:write", workspace_id=str(self.default_workspace.id)
        )

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **headers)

        # This should now succeed with our permission fix
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], workspace["name"])
        self.assertEqual(response.data["parent_id"], str(self.default_workspace.id))

    def test_create_workspace_authorized_with_default_workspace_read_only_fails(self):
        """Test that creating a workspace with only Default Workspace read permission fails."""
        workspace = {
            "name": "New Workspace Read Only",
            "description": "Workspace creation should fail with read-only permission",
        }

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META

        # Set up read-only access for Default Workspace
        self._setup_access_for_principal(
            self.user_data["username"], "inventory:groups:read", workspace_id=str(self.default_workspace.id)
        )

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **headers)

        # This should still fail because we only have read permission
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_workspace_authorized_with_root_and_default_workspace_permissions(self):
        """Test for creating a workspace with both Root and Default Workspace permissions."""
        workspace = {
            "name": "New Workspace Both Permissions",
            "description": "Workspace created with both Root and Default permissions",
        }

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META

        # Set up access for both Root and Default Workspace
        self._setup_access_for_principal(
            self.user_data["username"],
            "inventory:groups:write",
            workspace_id=[str(self.root_workspace.id), str(self.default_workspace.id)],
        )

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **headers)

        # This should continue to work as before
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], workspace["name"])
        self.assertEqual(response.data["parent_id"], str(self.default_workspace.id))

    def test_duplicate_create_workspace(self):
        """Test that creating a duplicate workspace within same parent is not allowed."""
        workspace_data = {
            "name": "New Workspace",
            "description": "New Workspace - description",
            "tenant_id": self.tenant.id,
            "parent_id": self.standard_workspace.id,
        }

        Workspace.objects.create(**workspace_data)

        test_data = {"name": "New Workspace", "parent_id": self.standard_workspace.id}

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_body = json.loads(response.content.decode())
        self.assertEqual(resp_body.get("detail"), "Can't create workspace with same name within same parent workspace")

    @override_settings(WORKSPACE_ORG_CREATION_LIMIT=4)
    def test_create_workspaces_exceed_limit(self):
        """
        Test that when creating workspaces if the limit exceeds the organisations workspace limit
        the correct response is returned.
        """
        workspace_names = ["Workspace A", "Workspace B", "Workspace C", "Workspace D"]

        for name in workspace_names:
            workspace_data = {
                "name": name,
                "description": "New Workspace - description",
                "tenant_id": self.tenant.id,
                "parent_id": self.standard_workspace.id,
            }

            Workspace.objects.create(**workspace_data)

        test_data = {"name": "New Workspace", "parent_id": self.standard_workspace.id}

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_body = json.loads(response.content.decode())
        self.assertEqual(
            resp_body.get("detail"), "The total number of workspaces allowed for this organisation has been exceeded."
        )

    @override_settings(WORKSPACE_ORG_CREATION_LIMIT=9)
    def test_create_workspaces_not_exceed_limit(self):
        """
        Test that when creating workspaces if the limit does not exceed the organisations workspace limit
        the correct response is returned.
        """
        workspace_names = ["Workspace A", "Workspace B", "Workspace C", "Workspace D"]

        for name in workspace_names:
            workspace_data = {
                "name": name,
                "description": "New Workspace - description",
                "tenant_id": self.tenant.id,
                "parent_id": self.standard_workspace.id,
            }

            Workspace.objects.create(**workspace_data)

        test_data = {"name": "New Workspace", "parent_id": self.standard_workspace.id}

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], test_data["name"])

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=5)
    def test_create_workspaces_exceed_hierarchy_depth_limit(self):
        """
        Test that creating workspaces succeeds when within the hierarchy depth limit.

        Current hierarchy: root (0) -> default (1) -> standard (2) -> standard_sub (3)
        Creating at depth 4 should succeed with limit of 5.
        """
        workspace_data = {
            "name": "Level 4 Workspace",
            "description": "Workspace created at depth 4 within the limit.",
            "parent_id": self.standard_sub_workspace.id,
        }
        client = APIClient()
        url = reverse("v2_management:workspace-list")
        response = client.post(url, workspace_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        data = response.data
        self.assertEqual(data.get("name"), "Level 4 Workspace")
        self.assertEqual(data.get("type"), "standard")
        self.assertEqual(data.get("parent_id"), str(self.standard_sub_workspace.id))

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=3)
    def test_create_workspace_fails_when_exceeding_hierarchy_depth_limit(self):
        """
        Test that creating workspaces fails when the hierarchy depth limit is exceeded.

        Current hierarchy: root (0) -> default (1) -> standard (2) -> standard_sub (3)
        Attempting to create at depth 4 should fail with limit of 3.
        """
        workspace_data = {
            "name": "Too Deep Workspace",
            "description": "Workspace that exceeds the hierarchy depth limit.",
            "parent_id": self.standard_sub_workspace.id,
        }
        client = APIClient()
        url = reverse("v2_management:workspace-list")
        response = client.post(url, workspace_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        resp_body = json.loads(response.content.decode())
        self.assertEqual(resp_body.get("detail"), "Workspaces may only nest 3 levels deep.")

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=5, WORKSPACE_RESTRICT_DEFAULT_PEERS=False)
    def test_create_deep_workspace_chain_under_root(self):
        """
        Test creating a deep chain of standard workspaces under root workspace.
        Expected hierarchy:
        root (0) -> standard1 (1) -> standard2 (2) -> standard3 (3) -> standard4 (4) -> standard5 (5)
        """
        client = APIClient()
        url = reverse("v2_management:workspace-list")

        # Create the chain of workspaces
        current_parent_id = self.root_workspace.id
        workspace_ids = []

        for i in range(1, 6):  # Create 5 standard workspaces (depth 1-5)
            workspace_data = {
                "name": f"Standard Workspace Level {i}",
                "description": f"Standard workspace at depth level {i}",
                "parent_id": current_parent_id,
            }

            response = client.post(url, workspace_data, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

            data = response.data
            self.assertEqual(data.get("name"), f"Standard Workspace Level {i}")
            self.assertEqual(data.get("type"), "standard")
            self.assertEqual(data.get("parent_id"), str(current_parent_id))
            self.assertIsNotNone(data.get("id"))

            # Store workspace ID and set it as parent for next iteration
            workspace_id = data.get("id")
            workspace_ids.append(workspace_id)
            current_parent_id = workspace_id

        # Verify all 5 workspaces were created successfully
        self.assertEqual(len(workspace_ids), 5)

        # Verify the hierarchy structure by checking each workspace's parent
        for i, workspace_id in enumerate(workspace_ids):
            workspace = Workspace.objects.get(id=workspace_id)
            self.assertEqual(workspace.type, Workspace.Types.STANDARD)
            self.assertEqual(workspace.name, f"Standard Workspace Level {i + 1}")

            if i == 0:
                # First workspace should have root as parent
                self.assertEqual(workspace.parent_id, self.root_workspace.id)
            else:
                # Each subsequent workspace should have the previous one as parent
                self.assertEqual(str(workspace.parent_id), workspace_ids[i - 1])

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=5, WORKSPACE_RESTRICT_DEFAULT_PEERS=False)
    def test_create_standard_chain_under_default_workspace(self):
        """
        Test creating a chain of standard workspaces under existing default workspace.
        Expected hierarchy:
        root (0) -> default (1) -> standard1 (2) -> standard2 (3) -> standard3 (4) -> standard4 (5)
        """
        client = APIClient()
        url = reverse("v2_management:workspace-list")

        # Create the chain of workspaces
        current_parent_id = self.default_workspace.id
        workspace_ids = []

        for i in range(1, 5):  # Create 4 standard workspaces (depth 2-5)
            workspace_data = {
                "name": f"Standard Chain {i}",
                "description": f"Standard workspace #{i} in chain under default",
                "parent_id": current_parent_id,
            }

            response = client.post(url, workspace_data, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

            data = response.data
            self.assertEqual(data.get("name"), f"Standard Chain {i}")
            self.assertEqual(data.get("type"), "standard")
            self.assertEqual(data.get("parent_id"), str(current_parent_id))

            # Store the created workspace ID for next iteration
            workspace_id = data.get("id")
            workspace_ids.append(workspace_id)
            current_parent_id = workspace_id

        # Verify the complete chain exists and has correct hierarchy
        for i, workspace_id in enumerate(workspace_ids):
            workspace = Workspace.objects.get(id=workspace_id)
            self.assertEqual(workspace.name, f"Standard Chain {i + 1}")
            self.assertEqual(workspace.type, "standard")

            if i == 0:
                # First workspace should have default as parent
                self.assertEqual(workspace.parent_id, self.default_workspace.id)
            else:
                # Each subsequent workspace should have the previous one as parent
                self.assertEqual(str(workspace.parent_id), workspace_ids[i - 1])

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=5, WORKSPACE_RESTRICT_DEFAULT_PEERS=False)
    def test_create_standard_chain_under_ungrouped_workspace(self):
        """
        Test creating a chain of standard workspaces under existing ungrouped workspace.
        Expected hierarchy:
        root (0) -> default (1) -> ungrouped (2) -> standard1 (3) -> standard2 (4) -> standard3 (5)
        """
        client = APIClient()
        url = reverse("v2_management:workspace-list")

        # Create the chain of workspaces
        current_parent_id = self.ungrouped_workspace.id
        workspace_ids = []

        for i in range(1, 4):  # Create 3 standard workspaces (depth 3-5)
            workspace_data = {
                "name": f"Standard Under Ungrouped {i}",
                "description": f"Standard workspace #{i} in chain under ungrouped",
                "parent_id": current_parent_id,
            }

            response = client.post(url, workspace_data, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

            data = response.data
            self.assertEqual(data.get("name"), f"Standard Under Ungrouped {i}")
            self.assertEqual(data.get("type"), "standard")
            self.assertEqual(data.get("parent_id"), str(current_parent_id))

            # Store the created workspace ID for next iteration
            workspace_id = data.get("id")
            workspace_ids.append(workspace_id)
            current_parent_id = workspace_id

        # Verify the complete chain exists and has correct hierarchy
        for i, workspace_id in enumerate(workspace_ids):
            workspace = Workspace.objects.get(id=workspace_id)
            self.assertEqual(workspace.name, f"Standard Under Ungrouped {i + 1}")
            self.assertEqual(workspace.type, "standard")

            if i == 0:
                # First workspace should have ungrouped as parent
                self.assertEqual(workspace.parent_id, self.ungrouped_workspace.id)
            else:
                # Each subsequent workspace should have the previous one as parent
                self.assertEqual(str(workspace.parent_id), workspace_ids[i - 1])

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate_workspace")
    def test_update_workspace(self, replicate_workspace, replicate):
        """Test for updating a workspace."""
        replicate.side_effect = self.in_memory_replicator.replicate
        workspace_data = {
            "name": "New Workspace",
            "description": "New Workspace - description",
            "tenant_id": self.tenant.id,
            "parent_id": self.standard_workspace.id,
        }

        workspace = Workspace.objects.create(**workspace_data)

        url = reverse("v2_management:workspace-detail", kwargs={"pk": workspace.id})
        client = APIClient()

        workspace_data["name"] = "Updated name"
        workspace_data["description"] = "Updated description"
        workspace_data["parent_id"] = workspace.parent_id
        response = client.put(url, workspace_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data.get("name"), "Updated name")
        self.assertNotEqual(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEqual(data.get("created"), "")
        self.assertNotEqual(data.get("modified"), "")
        self.assertEqual(data.get("type"), "standard")
        self.assertEqual(data.get("description"), "Updated description")

        update_workspace = Workspace.objects.filter(id=workspace.id).first()
        self.assertEqual(update_workspace.name, "Updated name")
        self.assertEqual(update_workspace.description, "Updated description")
        self.assertEqual(response.get("content-type"), "application/json")

        self.assertEqual(len(self.tuples), 0)
        self.in_memory_replicator = InMemoryRelationReplicator(self.tuples)
        workspace_event = replicate_workspace.call_args[0][0]
        self.assertEqual(workspace_event.account_number, self.tenant.account_id)
        self.assertEqual(workspace_event.org_id, self.tenant.org_id)
        self.assertEqual(workspace_event.event_type, ReplicationEventType.UPDATE_WORKSPACE)
        data.pop("description")
        data.pop("parent_id")
        self.assertEqual(workspace_event.workspace, data)

    def test_partial_update_workspace_with_put_method(self):
        """Test for updating a workspace."""
        workspace_data = {
            "name": "New Workspace",
            "description": "New Workspace - description",
            "tenant_id": self.tenant.id,
            "parent_id": self.standard_workspace.id,
        }

        workspace = Workspace.objects.create(**workspace_data)

        url = reverse("v2_management:workspace-detail", kwargs={"pk": workspace.id})
        client = APIClient()

        workspace_request_data = {"name": "Newer Workspace"}

        response = client.put(url, workspace_request_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        status_code = data.get("status")
        self.assertEqual(data.get("name"), "Newer Workspace")
        self.assertEqual(data.get("description"), workspace_data["description"])
        self.assertEqual(data.get("parent_id"), str(workspace_data["parent_id"]))

    def test_partial_update_empty(self):
        """Test for updating a workspace with empty body."""
        workspace_data = {
            "name": "New Workspace",
            "description": "New Workspace - description",
            "tenant_id": self.tenant.id,
            "parent_id": self.root_workspace.id,
        }

        workspace = Workspace.objects.create(**workspace_data)

        url = reverse("v2_management:workspace-detail", kwargs={"pk": workspace.id})
        client = APIClient()
        response = client.patch(url, {}, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.get("content-type"), "application/json")
        data = response.data
        self.assertEqual(data.get("name"), "New Workspace")
        self.assertEqual(data.get("description"), "New Workspace - description")
        self.assertEqual(data.get("id"), str(workspace.id))
        self.assertNotEqual(data.get("created"), "")
        self.assertNotEqual(data.get("modified"), "")
        self.assertEqual(data.get("type"), "standard")

        update_workspace = Workspace.objects.filter(id=workspace.id).first()
        self.assertEqual(update_workspace.name, "New Workspace")

    def test_update_workspace_update_parent_id(self):
        """Test for updating a workspace's parent_id."""
        workspace_data = {
            "name": "New Workspace",
            "description": "New Workspace - description",
            "tenant_id": self.tenant.id,
            "parent_id": self.standard_workspace.id,
        }

        workspace = Workspace.objects.create(**workspace_data)

        url = reverse("v2_management:workspace-detail", kwargs={"pk": workspace.id})
        client = APIClient()

        workspace_request_data = {"name": "New Workspace", "parent_id": self.default_workspace.id}

        response = client.put(url, workspace_request_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        status_code = response.data.get("status")
        detail = response.data.get("detail")
        self.assertIsNotNone(detail)
        self.assertEqual(detail, "Can't update the 'parent_id' on a workspace directly")
        self.assertEqual(status_code, 400)
        self.assertEqual(response.get("content-type"), "application/problem+json")

    def test_partial_update_workspace(self):
        """Test for updating a workspace."""
        workspace_data = {
            "name": "New Workspace",
            "description": "New Workspace - description",
            "tenant_id": self.tenant.id,
            "parent_id": self.root_workspace.id,
        }

        workspace = Workspace.objects.create(**workspace_data)

        url = reverse("v2_management:workspace-detail", kwargs={"pk": workspace.id})
        client = APIClient()

        workspace_data = {"name": "Updated name"}
        response = client.patch(url, workspace_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data.get("name"), "Updated name")
        self.assertNotEqual(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEqual(data.get("created"), "")
        self.assertNotEqual(data.get("modified"), "")
        self.assertEqual(data.get("type"), "standard")

        update_workspace = Workspace.objects.filter(id=workspace.id).first()
        self.assertEqual(update_workspace.name, "Updated name")
        self.assertEqual(response.get("content-type"), "application/json")

    def test_partial_update_workspace_same_tenant_parent_id(self):
        """Test for updating a workspace with a parent that's the same as the original object."""
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()

        workspace_data = {"parent_id": self.standard_workspace.parent_id}
        response = client.patch(url, workspace_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_partial_update_workspace_wrong_tenant_parent_id(self):
        """Test for updating a workspace with a parent not the same as the original object."""
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()

        workspace_data = {"parent_id": self.root_workspace.id}
        response = client.patch(url, workspace_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["detail"], "Can't update the 'parent_id' on a workspace directly")

    def test_update_workspace_empty_body(self):
        """Test for updating a workspace with empty body"""
        workspace = {}

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        response = client.put(url, workspace, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        status_code = response.data.get("status")
        detail = response.data.get("detail")
        instance = response.data.get("instance")
        self.assertIsNotNone(detail)
        self.assertEqual(detail, "This field is required.")
        self.assertEqual(status_code, 400)
        self.assertEqual(instance, url)
        self.assertEqual(response.get("content-type"), "application/problem+json")

    def test_update_duplicate_workspace(self):
        workspace_data_for_update = {
            "name": "New Duplicate Workspace for Update",
            "description": "New Duplicate Workspace - description",
            "tenant_id": self.tenant.id,
            "parent_id": self.standard_workspace.id,
        }

        workspace_for_update = Workspace.objects.create(**workspace_data_for_update)

        url = reverse("v2_management:workspace-detail", kwargs={"pk": workspace_for_update.id})
        client = APIClient()

        workspace_data_for_put = {
            "name": "New Duplicate Workspace",
            "description": "New Duplicate Workspace - description",
            "parent_id": self.standard_workspace.id,
        }

        response = client.put(url, workspace_data_for_put, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.get("content-type"), "application/json")

    def test_update_workspace_unauthorized(self):
        workspace = {}

        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        response = client.put(url, workspace, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        status_code = response.data.get("status")
        detail = response.data.get("detail")

        self.assertEqual(detail, "You do not have permission to perform this action.")
        self.assertEqual(status_code, 403)
        self.assertEqual(response.get("content-type"), "application/problem+json")

    def test_update_root_workspace_parent_id_fail(self):
        """Test we cannot update parent id for root workspace."""
        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.root_workspace.id})

        # Test with not existing uuid, with root workspace's own id, with existing workspace id
        invalid_id = "a5b82afe-a74a-4d4d-98e5-f49ea78e5910"
        root_id = self.root_workspace.id
        workspace_data = {
            "name": "Workspace name",
            "description": "Workspace description",
            "tenant_id": self.tenant.id,
            "parent_id": self.standard_workspace.id,
        }
        standard_workspace = Workspace.objects.create(**workspace_data)
        standard_id = standard_workspace.id

        for ws_id in invalid_id, root_id, standard_id:
            test_data = {"name": "New Workspace Name", "parent_id": ws_id}
            response = client.put(url, test_data, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            resp_body = json.loads(response.content.decode())
            self.assertEqual(resp_body.get("detail"), "The root workspace cannot be updated.")

    def test_update_root_workspace_name_description_fail(self):
        """Test we cannot update name and/or description for root workspace."""
        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.root_workspace.id})

        # Test data cases:
        #    - name and description update,
        #    - only name update
        #    - only description update (name without change but must be present because the field is required)
        test_data_cases = [
            {"name": "New name", "description": "New description"},
            {"name": "New name"},
            {"name": self.root_workspace.name, "description": "New description"},
        ]

        for test_data in test_data_cases:
            for method in ("put", "patch"):  # try to update via PUT and PATCH endpoint
                response = getattr(client, method)(url, test_data, format="json", **self.headers)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                resp_body = json.loads(response.content.decode())
                self.assertEqual(resp_body.get("detail"), "The root workspace cannot be updated.")

    def test_update_ungrouped_workspace_parent_id_fail(self):
        """Test we cannot update parent id for ungrouped workspace."""
        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.ungrouped_workspace.id})

        # Test with not existing uuid, with ungrouped workspace's own id, with existing workspace id
        invalid_id = "a5b82afe-a74a-4d4d-98e5-f49ea78e5910"
        ungrouped_id = self.ungrouped_workspace.id
        workspace_data = {
            "name": "Workspace name",
            "description": "Workspace description",
            "tenant_id": self.tenant.id,
            "parent_id": self.standard_workspace.id,
        }
        standard_workspace = Workspace.objects.create(**workspace_data)
        standard_id = standard_workspace.id

        for ws_id in invalid_id, ungrouped_id, standard_id:
            test_data = {"name": "New Workspace Name", "parent_id": ws_id}
            response = client.put(url, test_data, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            resp_body = json.loads(response.content.decode())
            self.assertEqual(resp_body.get("detail"), "The ungrouped-hosts workspace cannot be updated.")

    def test_update_ungrouped_workspace_name_description_fail(self):
        """Test we cannot update name and/or description for ungrouped workspace."""
        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.ungrouped_workspace.id})

        # Test data cases:
        #    - name and description update,
        #    - only name update
        #    - only description update (name without change but must be present because the field is required)
        test_data_cases = [
            {"name": "New name", "description": "New description"},
            {"name": "New name"},
            {"name": self.root_workspace.name, "description": "New description"},
        ]

        for test_data in test_data_cases:
            for method in ("put", "patch"):  # try to update via PUT and PATCH endpoint
                response = getattr(client, method)(url, test_data, format="json", **self.headers)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                resp_body = json.loads(response.content.decode())
                self.assertEqual(resp_body.get("detail"), "The ungrouped-hosts workspace cannot be updated.")

    def test_update_default_workspace_parent_id_fail(self):
        """Test we cannot update parent id for default workspace."""
        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.default_workspace.id})

        # Test with not existing uuid, default workspace's id, existing workspace id
        invalid_id = "a5b82afe-a74a-4d4d-98e5-f49ea78e5910"
        default_id = self.default_workspace.id
        workspace_data = {
            "name": "Workspace name",
            "description": "Workspace description",
            "tenant_id": self.tenant.id,
            "parent_id": self.standard_workspace.id,
        }
        standard_workspace = Workspace.objects.create(**workspace_data)
        standard_id = standard_workspace.id

        for ws_id in invalid_id, default_id, standard_id:
            test_data = {"name": "New Workspace Name", "parent_id": ws_id}
            response = client.put(url, test_data, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            resp_body = json.loads(response.content.decode())
            self.assertEqual(resp_body.get("detail"), "Can't update the 'parent_id' on a workspace directly")

    def test_update_default_workspace_name_description(self):
        """Test we can update name and/or description for default workspace."""
        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.default_workspace.id})

        # Test data cases:
        #    - name and description update,
        #    - only name update
        #    - only description update (name without change but must be present because the field is required)
        test_data_cases = [
            {"name": "New name", "description": "New description"},
            {"name": "New name", "description": self.default_workspace.description},
            {"name": self.default_workspace.name, "description": "New description"},
        ]

        for test_data in test_data_cases:
            for method in ("put", "patch"):  # try to update via PUT and PATCH endpoint
                response = getattr(client, method)(url, test_data, format="json", **self.headers)
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                resp_body = response.json()
                self.assertEqual(resp_body.get("id"), str(self.default_workspace.id))
                self.assertEqual(resp_body.get("name"), test_data["name"])
                self.assertEqual(resp_body.get("description"), test_data["description"])
                self.assertEqual(resp_body.get("type"), Workspace.Types.DEFAULT)
                self.assertEqual(resp_body.get("parent_id"), str(self.default_workspace.parent_id))

                # After test set the default values back
                self.default_workspace.name = "Default"
                self.default_workspace.description = "Default description"

    def test_update_workspace_existing_name_fail(self):
        """Test the workspace name update (PUT) fail for already existing "name" under same parent."""
        wsA = Workspace.objects.create(
            name="Workspace A", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=self.default_workspace
        )
        wsB = Workspace.objects.create(
            name="Workspace B", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=self.default_workspace
        )

        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": wsA.id})
        workspace_request_data = {"name": wsB.name}

        response = client.put(url, workspace_request_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_message = response.json()

        self.assertEqual(response_message.get("status"), status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response_message.get("detail"), f"A workspace with the name '{wsB.name}' already exists under same parent."
        )
        self.assertEqual(response_message.get("instance"), f"/api/rbac/v2/workspaces/{wsA.id}/")

    def test_partial_update_workspace_existing_name_fail(self):
        """Test the workspace name update (PATCH) fail for already existing "name" under same parent."""
        wsA = Workspace.objects.create(
            name="Workspace A", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=self.default_workspace
        )
        wsB = Workspace.objects.create(
            name="Workspace B", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=self.default_workspace
        )

        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": wsA.id})
        workspace_request_data = {"name": wsB.name}

        response = client.patch(url, workspace_request_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_message = response.json()

        self.assertEqual(response_message.get("status"), status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response_message.get("detail"), f"A workspace with the name '{wsB.name}' already exists under same parent."
        )
        self.assertEqual(response_message.get("instance"), f"/api/rbac/v2/workspaces/{wsA.id}/")

    def test_update_workspace_existing_name_success(self):
        """
        Test the workspace name update (PUT) success for already existing "name"
        under same tenant but with different parent.
        """

        # workspaces structure:
        # self.default_workspace (default) -> Workspace A (standard) -> Workspace AA (standard)
        #                                  -> Workspace B (standard)
        wsA = Workspace.objects.create(
            name="Workspace A", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=self.default_workspace
        )
        wsAA = Workspace.objects.create(
            name="Workspace AA", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=wsA
        )
        wsB = Workspace.objects.create(
            name="Workspace B", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=self.default_workspace
        )

        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": wsAA.id})
        workspace_request_data = {"name": wsB.name}
        # expected structure after update:
        # self.default_workspace (default) -> Workspace A (standard) -> Workspace B (standard)
        #                                  -> Workspace B (standard)

        response = client.put(url, workspace_request_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_message = response.json()
        self.assertEqual(response_message.get("name"), wsB.name)
        self.assertEqual(response_message.get("parent_id"), str(wsA.id))

    def test_partial_update_workspace_existing_name_success(self):
        """
        Test the workspace name update (PATCH) success for already existing "name"
        under same tenant but with different parent.
        """

        # workspaces structure:
        # self.default_workspace (default) -> Workspace A (standard) -> Workspace AA (standard)
        #                                  -> Workspace B (standard)
        wsA = Workspace.objects.create(
            name="Workspace A", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=self.default_workspace
        )
        wsAA = Workspace.objects.create(
            name="Workspace AA", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=wsA
        )
        wsB = Workspace.objects.create(
            name="Workspace B", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=self.default_workspace
        )

        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": wsAA.id})
        workspace_request_data = {"name": wsB.name}
        # expected structure after update:
        # self.default_workspace (default) -> Workspace A (standard) -> Workspace B (standard)
        #                                  -> Workspace B (standard)

        response = client.patch(url, workspace_request_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_message = response.json()
        self.assertEqual(response_message.get("name"), wsB.name)
        self.assertEqual(response_message.get("parent_id"), str(wsA.id))

    @override_settings(WORKSPACE_RESTRICT_DEFAULT_PEERS=False)
    def test_edit_workspace_disregard_type(self):
        """Test for creating a workspace."""
        root = Workspace.objects.get(tenant=self.tenant, type=Workspace.Types.ROOT)

        workspace = {
            "name": "New Workspace",
            "description": "Workspace",
            "parent_id": str(root.id),
            "type": Workspace.Types.UNGROUPED_HOSTS,
        }

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        # Create disregards 'type'
        response = client.post(url, workspace, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data.get("type"), Workspace.Types.STANDARD)

        workspace["type"] = Workspace.Types.DEFAULT
        workspace["name"] = "New Workspace 2"
        response = client.post(url, workspace, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data.get("type"), Workspace.Types.STANDARD)

        # Update disregards 'type'
        workspace["type"] = Workspace.Types.STANDARD
        workspace["name"] = "New Workspace 3"
        created_workspace = Workspace.objects.create(**workspace, tenant=self.tenant)
        url = reverse("v2_management:workspace-detail", kwargs={"pk": created_workspace.id})
        client = APIClient()
        workspace["type"] = Workspace.Types.UNGROUPED_HOSTS
        response = client.put(url, workspace, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("type"), Workspace.Types.STANDARD)

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate_workspace")
    def test_delete_workspace(self, replicate_workspace, replicate):
        replicate.side_effect = self.in_memory_replicator.replicate
        workspace_data = {
            "name": "Workspace for delete",
            "description": "Workspace for delete - description",
            "tenant_id": self.tenant.id,
            "parent_id": self.root_workspace.id,
        }
        workspace = Workspace.objects.create(**workspace_data)
        relationship = create_relationship(
            ("rbac", "workspace"),
            str(workspace.id),
            ("rbac", "workspace"),
            str(self.root_workspace.id),
            "parent",
        )
        self.tuples.write([relationship], [])
        url = reverse("v2_management:workspace-detail", kwargs={"pk": workspace.id})
        client = APIClient()
        test_headers = self.headers.copy()
        test_headers["HTTP_ACCEPT"] = "application/problem+json"
        response = client.delete(url, None, format="json", **test_headers)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.headers.get("content-type"), None)
        deleted_workspace = Workspace.objects.filter(id=workspace.id).first()
        self.assertIsNone(deleted_workspace)

        self.assertEqual(len(self.tuples), 0)
        self.in_memory_replicator = InMemoryRelationReplicator(self.tuples)
        workspace_event = replicate_workspace.call_args[0][0]
        self.assertEqual(workspace_event.account_number, self.tenant.account_id)
        self.assertEqual(workspace_event.org_id, self.tenant.org_id)
        self.assertEqual(workspace_event.event_type, ReplicationEventType.DELETE_WORKSPACE)
        deleted_workspace = WorkspaceEventSerializer(workspace).data
        self.assertEqual(workspace_event.workspace["id"], deleted_workspace["id"])

    def test_delete_workspace_not_found(self):
        url = reverse("v2_management:workspace-detail", kwargs={"pk": "XXXX"})
        client = APIClient()
        response = client.delete(url, None, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        status_code = response.data.get("status")
        detail = response.data.get("detail")
        self.assertEqual(detail, "Not found.")
        self.assertEqual(status_code, 404)
        self.assertEqual(response.get("content-type"), "application/problem+json")

    def test_delete_workspace_unauthorized(self):
        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        response = client.delete(url, None, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        status_code = response.data.get("status")
        detail = response.data.get("detail")
        self.assertEqual(detail, "You do not have permission to perform this action.")
        self.assertEqual(status_code, 403)
        self.assertEqual(response.get("content-type"), "application/problem+json")

    def test_delete_workspace_with_dependencies(self):
        workspace_data = {
            "name": "Workspace for delete",
            "description": "Workspace for delete - description",
            "tenant_id": self.tenant.id,
            "parent_id": self.root_workspace.id,
        }
        workspace = Workspace.objects.create(**workspace_data)
        dependent = Workspace.objects.create(
            name="Dependent Workspace",
            tenant=self.tenant,
            type="standard",
            parent_id=workspace.id,
        )
        url = reverse("v2_management:workspace-detail", kwargs={"pk": workspace.id})
        client = APIClient()
        test_headers = self.headers.copy()
        test_headers["HTTP_ACCEPT"] = "application/problem+json"
        response = client.delete(url, None, format="json", **test_headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        detail = response.data.get("detail")
        self.assertEqual(detail, "Unable to delete due to workspace dependencies")

    def test_delete_workspace_with_non_standard_types(self):
        """Test the non-standard (root, default, ungrouped-hosts) workspaces cannot be deleted."""
        client = APIClient()
        # Root workspace can't be deleted
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.root_workspace.id})
        test_headers = self.headers.copy()
        test_headers["HTTP_ACCEPT"] = "application/problem+json"
        response = client.delete(url, None, format="json", **test_headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        detail = response.data.get("detail")
        self.assertEqual(detail, "Unable to delete root workspace")

        # Default workspace can't be deleted
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.default_workspace.id})
        response = client.delete(url, None, format="json", **test_headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        detail = response.data.get("detail")
        self.assertEqual(detail, "Unable to delete default workspace")

        # Ungrouped workspace can't be deleted
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.ungrouped_workspace.id})
        response = client.delete(url, None, format="json", **test_headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        detail = response.data.get("detail")
        self.assertEqual(detail, "Unable to delete ungrouped-hosts workspace")


@override_settings(V2_APIS_ENABLED=True, WORKSPACE_HIERARCHY_DEPTH_LIMIT=5)
class WorkspaceMove(TransactionalWorkspaceViewTests):
    """Tests for move workspace."""

    def setUp(self):
        """Set up workspace access check tests."""
        super().setUp()
        self.tuples = InMemoryTuples()
        self.in_memory_replicator = InMemoryRelationReplicator(self.tuples)

        # Create a unique test workspace that won't conflict with existing names
        self.test_workspace = Workspace.objects.create(
            name="Test Workspace for Move",
            description="Test workspace for move operations",
            tenant=self.tenant,
            parent=self.standard_workspace,
            type=Workspace.Types.STANDARD,
        )

        # Create test users
        self.user_with_access = {"username": "user_with_access", "email": "user_with_access@example.com"}
        self.user_without_access = {"username": "user_without_access", "email": "user_without_access@example.com"}

        # Set up access for user_with_access to have write permissions on default_workspace
        self._setup_access_for_principal(
            self.user_with_access["username"], "inventory:groups:write", str(self.default_workspace.id)
        )

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_success_move_workspace(self, replicate):
        replicate.side_effect = self.in_memory_replicator.replicate

        validated_data_source_ws = {
            "name": "Workspace Source",
            "parent_id": self.default_workspace.id,
        }
        source_workspace = self.service.create(validated_data_source_ws, self.tenant)

        validated_data_target_ws = {
            "name": "Workspace Target",
            "parent_id": self.default_workspace.id,
        }
        target_workspace = self.service.create(validated_data_target_ws, self.tenant)

        tuples_source_to_default = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(source_workspace.id)),
                relation("parent"),
                subject("rbac", "workspace", str(self.default_workspace.id)),
            )
        )
        self.assertEqual(len(tuples_source_to_default), 1)

        tuples_target_to_default = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(target_workspace.id)),
                relation("parent"),
                subject("rbac", "workspace", str(self.default_workspace.id)),
            )
        )
        self.assertEqual(len(tuples_target_to_default), 1)

        url = reverse("v2_management:workspace-move", kwargs={"pk": source_workspace.id})

        client = APIClient()

        workspace_data_for_move = {
            "parent_id": target_workspace.id,
        }

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.get("content-type"), "application/json")
        self.assertEqual(response.data.get("id"), str(source_workspace.id))
        self.assertEqual(response.data.get("parent_id"), str(target_workspace.id))

        tuples_source_to_target = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(source_workspace.id)),
                relation("parent"),
                subject("rbac", "workspace", str(target_workspace.id)),
            )
        )
        self.assertEqual(len(tuples_source_to_target), 1)

        tuples_source_to_default = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(source_workspace.id)),
                relation("parent"),
                subject("rbac", "workspace", str(self.default_workspace.id)),
            )
        )
        self.assertEqual(len(tuples_source_to_default), 0)

    def test_move_not_existing_workspace(self):
        """Test you cannot move not existing workspace."""
        url = reverse("v2_management:workspace-move", kwargs={"pk": str(uuid4())})
        client = APIClient()
        workspace_data_for_move = {"parent_id": self.standard_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        response_body = response.json()
        self.assertEqual(response_body.get("detail"), "No Workspace matches the given query.")

    def test_move_with_invalid_uuid_parent_id(self):
        """Test you cannot move a workspace when invalid uuid is provided as a parent id."""
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        invalid_uuid = "invalid_uuid"
        workspace_data_for_move = {"parent_id": invalid_uuid}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_body = response.json()
        self.assertEqual(response_body.get("detail"), f"{invalid_uuid} is not a valid UUID.")

    def test_move_under_itself(self):
        """Test you cannot move a workspace under itself."""
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        workspace_data_for_move = {"parent_id": self.standard_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_body = response.json()
        self.assertEqual(response_body.get("detail"), "The parent_id and id values must not be the same.")

    def test_move_root_workspace(self):
        """Test you cannot move a root workspace."""
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.root_workspace.id})
        client = APIClient()
        workspace_data_for_move = {"parent_id": self.standard_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_body = response.json()
        self.assertEqual(response_body.get("detail"), "Cannot move non-standard workspace.")

    def test_move_default_workspace(self):
        """Test you cannot move a default workspace."""
        standard_workspace_1 = self.service.create(
            {"name": "W-1", "parent_id": self.default_workspace.id}, self.tenant
        )
        standard_workspace_1_1 = self.service.create(
            {"name": "W-1-1", "parent_id": standard_workspace_1.id}, self.tenant
        )
        standard_workspace_1_1_1 = self.service.create(
            {"name": "W-1-1-1", "parent_id": standard_workspace_1_1.id}, self.tenant
        )
        standard_workspace_1_2 = self.service.create(
            {"name": "W-1-2", "parent_id": standard_workspace_1.id}, self.tenant
        )

        # move ws 1_1_1 under 1_2
        url = reverse("v2_management:workspace-move", kwargs={"pk": standard_workspace_1_1_1.id})
        client = APIClient()
        workspace_data_for_move = {"parent_id": standard_workspace_1_2.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = response.json()

        self.assertEqual(response_body["id"], str(standard_workspace_1_1_1.id))
        self.assertEqual(response_body["parent_id"], str(standard_workspace_1_2.id))
        self.assertEqual(
            response_body["parent_id"], str(Workspace.objects.get(id=standard_workspace_1_1_1.id).parent_id)
        )

    def test_move_ungrouped_workspace(self):
        """Test you cannot move a ungrouped workspace."""
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.ungrouped_workspace.id})
        client = APIClient()
        workspace_data_for_move = {"parent_id": self.standard_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_body = response.json()
        self.assertEqual(response_body.get("detail"), "Cannot move non-standard workspace.")

    def test_move_parent_id_not_exists(self):
        """Test you cannot move a workspace under not existing parent."""
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        parent_id = str(uuid4())
        workspace_data_for_move = {"parent_id": parent_id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        response_body = response.json()
        self.assertEqual(response_body.get("detail"), "You do not have write access to the target workspace.")

    def test_move_parent_with_empty_parent_id(self):
        """Test you cannot move a workspace when empty string is provided as a parent id."""
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        workspace_data_for_move = {"parent_id": ""}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_body = response.json()
        self.assertEqual(response_body.get("detail"), "The 'parent_id' field is required.")

    def test_move_parent_without_request_body(self):
        """Test you cannot move a workspace without request body (without parent_id)."""
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()

        response = client.post(url, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_body = response.json()
        self.assertEqual(response_body.get("detail"), "The 'parent_id' field is required.")

    @override_settings(WORKSPACE_RESTRICT_DEFAULT_PEERS=True)
    def test_move_under_root_workspace_fail(self):
        """Test you cannot move a workspace under a root workspace with WORKSPACE_RESTRICT_DEFAULT_PEERS=True."""
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        workspace_data_for_move = {"parent_id": self.root_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.json().get("detail"), "Sub-workspaces may only be created under the default workspace."
        )

    @override_settings(WORKSPACE_RESTRICT_DEFAULT_PEERS=False)
    def test_move_under_root_workspace_success(self):
        """Test you can move a workspace under a root workspace with WORKSPACE_RESTRICT_DEFAULT_PEERS=False."""
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        workspace_data_for_move = {"parent_id": self.root_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("id"), str(self.standard_workspace.id))
        self.assertEqual(response.data.get("parent_id"), str(self.root_workspace.id))

    def test_move_under_default_workspace(self):
        """Test you can move a workspace under a default workspace."""
        # The test workspace belongs under another standard workspace
        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_sub_workspace.id})
        response = client.get(url, format="json", **self.headers)
        parent_id = response.data.get("parent_id")
        parent_workspace = Workspace.objects.get(id=parent_id)
        self.assertEqual(parent_workspace.type, Workspace.Types.STANDARD)

        # Move the workspace under default workspace
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.standard_sub_workspace.id})
        workspace_data_for_move = {"parent_id": self.default_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("id"), str(self.standard_sub_workspace.id))
        self.assertEqual(response.data.get("parent_id"), str(self.default_workspace.id))

    def test_move_under_ungrouped_workspace(self):
        """Test you can move a workspace under an ungrouped workspace."""
        # The test workspace belongs under another standard workspace
        client = APIClient()
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_sub_workspace.id})
        response = client.get(url, format="json", **self.headers)
        parent_id = response.data.get("parent_id")
        parent_workspace = Workspace.objects.get(id=parent_id)
        self.assertEqual(parent_workspace.type, Workspace.Types.STANDARD)

        # Move the workspace under ungrouped workspace
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.standard_sub_workspace.id})
        workspace_data_for_move = {"parent_id": self.ungrouped_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("id"), str(self.standard_sub_workspace.id))
        self.assertEqual(response.data.get("parent_id"), str(self.ungrouped_workspace.id))

    def test_move_under_standard_workspace(self):
        """Test you can move a workspace under a standard workspace."""
        # Create new workspace under default workspace
        validated_data = {"name": "New Workspace", "description": "Workspace"}
        workspace = self.service.create(validated_data, self.tenant)
        parent_workspace = Workspace.objects.get(id=workspace.parent_id)
        self.assertEqual(parent_workspace.type, Workspace.Types.DEFAULT)

        # Move the workspace under 'self.standard_workspace'
        client = APIClient()
        url = reverse("v2_management:workspace-move", kwargs={"pk": workspace.id})
        workspace_data_for_move = {"parent_id": self.standard_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("id"), str(workspace.id))
        self.assertEqual(response.data.get("parent_id"), str(self.standard_workspace.id))

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=3)
    def test_move_enforce_hierarchy_depth(self):
        """
        Test to enforce the hierarchy depth for moving workspace.

        Initial workspace hierarchy from setUp() method
        root -> default -> standard -> standard
                        -> ungrouped

        Test adds new standard workspace under default workspace and then
        tries to move it under most right standard workspace

        Desired workspace hierarchy
        root -> default -> standard -> standard -> standard
                        -> ungrouped

        It is expected that the move will be declined due to exceeding the maximum allowed hierarchy depth.
        """
        # Create new workspace under default workspace
        validated_data = {"name": "New Workspace", "description": "Workspace"}
        workspace = self.service.create(validated_data, self.tenant)
        parent_workspace = Workspace.objects.get(id=workspace.parent_id)
        self.assertEqual(parent_workspace.type, Workspace.Types.DEFAULT)

        # Move the workspace
        client = APIClient()
        url = reverse("v2_management:workspace-move", kwargs={"pk": workspace.id})
        workspace_data_for_move = {"parent_id": self.standard_sub_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json().get("detail"), "Workspaces may only nest 3 levels deep.")

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=5)
    def test_move_enforce_hierarchy_depth_with_descendants_success(self):
        """
        Test to enforce the hierarchy depth for workspace descendants.

        Initial workspace hierarchy from setUp() method
        root -> default -> standard A -> standard B
                        -> ungrouped

        Test adds new standard workspace with one child under default workspace and then
        tries to move it under standard A workspace

        Desired workspace hierarchy
        root -> default -> standard A -> standard B
                                      -> new standard C -> new standard D
                        -> ungrouped

        It is expected that the move will be successful.
        """
        # Create new workspace under default workspace
        validated_data_ws_C = {"name": "New Workspace C", "description": "Workspace C"}
        workspace_C = self.service.create(validated_data_ws_C, self.tenant)
        parent_workspace = Workspace.objects.get(id=workspace_C.parent_id)
        self.assertEqual(parent_workspace.type, Workspace.Types.DEFAULT)

        # Create a child workspace
        validated_data_ws_D = {"name": "New Workspace D", "description": "Workspace D", "parent_id": workspace_C.id}
        workspace_D = self.service.create(validated_data_ws_D, self.tenant)
        parent_workspace = Workspace.objects.get(id=workspace_D.parent_id)
        self.assertEqual(parent_workspace.type, Workspace.Types.STANDARD)

        # Move the workspace with descendant
        client = APIClient()
        url = reverse("v2_management:workspace-move", kwargs={"pk": workspace_C.id})
        workspace_data_for_move = {"parent_id": self.standard_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json().get("id"), str(workspace_C.id))
        self.assertEqual(response.json().get("parent_id"), str(self.standard_workspace.id))

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=3)
    def test_move_enforce_hierarchy_depth_with_descendants_fail(self):
        """
        Test to enforce the hierarchy depth for workspace descendants.

        Initial workspace hierarchy from setUp() method
        root -> default -> standard A -> standard B
                        -> ungrouped

        Test adds new standard workspace with one child under default workspace and then
        tries to move it under standard A workspace

        Desired workspace hierarchy
        root -> default -> standard A -> standard B
                                      -> new standard C -> new standard D
                        -> ungrouped

        It is expected that the move will be declined due to exceeding the maximum allowed hierarchy depth.
        """
        # Create new workspace under default workspace
        validated_data_ws_C = {"name": "New Workspace C", "description": "Workspace C"}
        workspace_C = self.service.create(validated_data_ws_C, self.tenant)
        parent_workspace = Workspace.objects.get(id=workspace_C.parent_id)
        self.assertEqual(parent_workspace.type, Workspace.Types.DEFAULT)

        # Create a child workspace
        validated_data_ws_D = {"name": "New Workspace D", "description": "Workspace D", "parent_id": workspace_C.id}
        workspace_D = self.service.create(validated_data_ws_D, self.tenant)
        parent_workspace = Workspace.objects.get(id=workspace_D.parent_id)
        self.assertEqual(parent_workspace.type, Workspace.Types.STANDARD)

        # Move the workspace with descendant
        client = APIClient()
        url = reverse("v2_management:workspace-move", kwargs={"pk": workspace_C.id})
        workspace_data_for_move = {"parent_id": self.standard_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.json().get("detail"), "Cannot move workspace: resulting hierarchy depth (4) exceeds limit (3)."
        )

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=100)
    def test_move_under_descendant(self):
        """Test you cannot move a workspace under own descendant."""
        # Create tree of 5 standard workspaces under the default workspace
        parent_id = None
        workspaces = {}

        for name in "ABCDE":
            validated_data = {
                "name": f"Workspace {name}",
                "description": f"Workspace {name}",
            }
            if parent_id:
                validated_data["parent_id"] = parent_id
            workspace = self.service.create(validated_data, self.tenant)
            workspaces[name] = workspace
            parent_id = workspace.id

        # Check that 4 descendants were created
        descendants = workspaces["A"].descendants()
        self.assertEqual(len(descendants), 4)
        self.assertEqual(workspaces["A"].get_max_descendant_depth(), 4)

        # Try to move the top workspace under all its descendants
        client = APIClient()
        for descendant in descendants:
            url = reverse("v2_management:workspace-move", kwargs={"pk": workspaces["A"].id})
            workspace_data_for_move = {"parent_id": descendant.id}

            response = client.post(url, workspace_data_for_move, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            response_body = response.json()
            self.assertEqual(response_body.get("detail"), "Cannot move workspace under one of its own descendants.")

    def test_move_with_duplicate_name_under_target_parent(self):
        """
        Test that a workspace cannot be moved under a parent
        if another workspace with the same name already exists there.
        """
        # Create workspace structure
        # root -> default -> Standard Workspace -> Test Workspace
        #                 -> Test Workspace
        name = "Test Workspace"
        self.standard_sub_workspace.name = name
        self.standard_sub_workspace.save()

        validated_data = {"name": name, "description": f"{name} description"}
        test_workspace = self.service.create(validated_data, self.tenant)

        # Try to move the 'Test Workspace' under the 'Standard Workspace'
        client = APIClient()
        url = reverse("v2_management:workspace-move", kwargs={"pk": test_workspace.id})
        workspace_data_for_move = {"parent_id": self.standard_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_body = response.json()
        self.assertEqual(
            response_body.get("detail"), "A workspace with the same name already exists under the target parent."
        )

    def test_move_under_target_parent_with_same_name(self):
        """
        Test that a workspace can be moved under parent with same name."""
        # Create workspace structure
        # root -> default -> Standard Workspace -> Test Workspace
        #                 -> Test Workspace
        name = "Test Workspace"
        self.standard_sub_workspace.name = name
        self.standard_sub_workspace.save()

        validated_data = {"name": name, "description": f"{name} description"}
        test_workspace = self.service.create(validated_data, self.tenant)

        # Try to move the 'Test Workspace' under the 'Test Workspace'
        client = APIClient()
        url = reverse("v2_management:workspace-move", kwargs={"pk": test_workspace.id})
        workspace_data_for_move = {"parent_id": self.standard_sub_workspace.id}

        response = client.post(url, workspace_data_for_move, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("id"), str(test_workspace.id))
        self.assertEqual(response.data.get("parent_id"), str(self.standard_sub_workspace.id))

    def test_move_with_write_access_allowed(self):
        """Test that move succeeds when user has write access to target workspace."""
        # Create request context for user with access
        request_context = self._create_request_context(self.customer_data, self.user_with_access, is_org_admin=False)
        headers = request_context["request"].META

        # Execute
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.test_workspace.id})
        client = APIClient()
        data = {"parent_id": str(self.default_workspace.id)}
        response = client.post(url, data, format="json", **headers)

        # Verify
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.data
        self.assertEqual(response_data["id"], str(self.test_workspace.id))
        self.assertEqual(response_data["parent_id"], str(self.default_workspace.id))

    def test_move_with_write_access_denied(self):
        """Test that move fails when user lacks write access to target workspace."""
        # Create request context for user without access
        request_context = self._create_request_context(
            self.customer_data, self.user_without_access, is_org_admin=False
        )
        headers = request_context["request"].META

        # Execute
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.test_workspace.id})
        client = APIClient()
        data = {"parent_id": str(self.default_workspace.id)}
        response = client.post(url, data, format="json", **headers)

        # Verify - Should get 403 from WorkspaceAccessPermission class
        # before our custom validation can return 400
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("You do not have permission to perform this action", str(response.data))

    def test_move_with_admin_access(self):
        """Test that move succeeds when user is org admin (bypasses access check)."""
        # Execute
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.test_workspace.id})
        client = APIClient()
        data = {"parent_id": str(self.default_workspace.id)}
        response = client.post(url, data, format="json", **self.headers)

        # Verify
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.data
        self.assertEqual(response_data["id"], str(self.test_workspace.id))
        self.assertEqual(response_data["parent_id"], str(self.default_workspace.id))

    def test_move_missing_parent_id(self):
        """Test that move fails when parent_id is missing."""
        request_context = self._create_request_context(self.customer_data, self.user_with_access, is_org_admin=False)
        headers = request_context["request"].META

        url = reverse("v2_management:workspace-move", kwargs={"pk": self.test_workspace.id})
        client = APIClient()
        data = {}
        response = client.post(url, data, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("The 'parent_id' field is required", str(response.data))

    def test_move_invalid_parent_id_uuid(self):
        """Test that move fails when parent_id is not a valid UUID."""
        request_context = self._create_request_context(self.customer_data, self.user_with_access, is_org_admin=False)
        headers = request_context["request"].META

        url = reverse("v2_management:workspace-move", kwargs={"pk": self.test_workspace.id})
        client = APIClient()
        data = {"parent_id": "invalid-uuid"}
        response = client.post(url, data, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("not a valid UUID", str(response.data))

    def test_move_with_read_only_access(self):
        """Test that move fails when user only has read access to target workspace."""
        # Create user with only read access
        read_only_user = {"username": "read_only_user", "email": "read_only@example.com"}
        self._setup_access_for_principal(
            read_only_user["username"],
            "inventory:groups:read",  # Only read permission, not write
            str(self.default_workspace.id),
        )

        request_context = self._create_request_context(self.customer_data, read_only_user, is_org_admin=False)
        headers = request_context["request"].META

        # Execute
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.test_workspace.id})
        client = APIClient()
        data = {"parent_id": str(self.default_workspace.id)}
        response = client.post(url, data, format="json", **headers)

        # Verify - Should get 403 from WorkspaceAccessPermission class
        # since user only has read access but move requires write
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("You do not have permission to perform this action", str(response.data))

    def test_move_with_wildcard_permission(self):
        """Test that move succeeds when user has wildcard (*) permission on target workspace."""
        # Create user with wildcard permission
        wildcard_user = {"username": "wildcard_user", "email": "wildcard@example.com"}
        self._setup_access_for_principal(
            wildcard_user["username"],
            "inventory:groups:*",  # Wildcard permission includes write
            str(self.default_workspace.id),
        )

        request_context = self._create_request_context(self.customer_data, wildcard_user, is_org_admin=False)
        headers = request_context["request"].META

        # Execute
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.test_workspace.id})
        client = APIClient()
        data = {"parent_id": str(self.default_workspace.id)}
        response = client.post(url, data, format="json", **headers)

        # Verify
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.data
        self.assertEqual(response_data["id"], str(self.test_workspace.id))
        self.assertEqual(response_data["parent_id"], str(self.default_workspace.id))

    def test_move_with_source_access_but_no_target_access_unique(self):
        """Test that move fails with PermissionDenied when user has write access to source workspace but not target workspace.

        This specifically tests our inner _check_target_workspace_write_access method.
        """
        # Create a user with access to the source workspace but not target
        source_access_user = {"username": "source_access_user", "email": "source_access_user@example.com"}
        # Give this user write access to the source workspace's parent (standard_workspace)
        self._setup_access_for_principal(
            source_access_user["username"], "inventory:groups:write", str(self.standard_workspace.id)
        )

        # Create a unique target workspace that the user doesn't have access to
        unique_suffix = str(uuid4())[:8]
        target_workspace = Workspace.objects.create(
            name=f"Target Workspace No Access {unique_suffix}",
            description="Target workspace user has no access to",
            tenant=self.tenant,
            parent=self.default_workspace,  # Put target under default_workspace (no access for source_access_user)
            type=Workspace.Types.STANDARD,
        )

        # Use the user who has access to source but not target
        request_context = self._create_request_context(self.customer_data, source_access_user, is_org_admin=False)
        headers = request_context["request"].META

        # Execute: try to move test_workspace to target_workspace (user has no access to target)
        url = reverse("v2_management:workspace-move", kwargs={"pk": self.test_workspace.id})
        client = APIClient()
        data = {"parent_id": str(target_workspace.id)}
        response = client.post(url, data, format="json", **headers)

        # Verify - Should get 403 from our inner _check_target_workspace_write_access method
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        # The error message should come from our PermissionDenied exception
        self.assertIn("You do not have write access to the target workspace", str(response.data))


@override_settings(V2_APIS_ENABLED=True)
class WorkspaceTestsList(WorkspaceViewTests):
    """Tests for listing workspaces."""

    def assertSuccessfulList(self, response, payload):
        """Common list success assertions."""
        self.assertIsInstance(payload.get("data"), list)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.get("content-type"), "application/json")
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, payload)
        for keyname in ["name", "id", "parent_id", "description", "type"]:
            self.assertIn(keyname, payload.get("data")[0])

    def assertType(self, payload, expected_type):
        """Ensure the correct type on data."""
        for ws in payload.get("data"):
            self.assertEqual(ws["type"], expected_type)

    def test_workspace_list_unfiltered(self):
        """List workspaces unfiltered."""
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.get(url, None, format="json", **self.headers)
        payload = response.data

        self.assertSuccessfulList(response, payload)
        self.assertEqual(payload.get("meta").get("count"), Workspace.objects.count())

    def test_workspace_list_all(self):
        """List workspaces type=all."""
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.get(f"{url}?type=all", None, format="json", **self.headers)
        payload = response.data

        self.assertSuccessfulList(response, payload)
        self.assertEqual(payload.get("meta").get("count"), Workspace.objects.count())

    def test_workspace_list_standard(self):
        """List workspaces type=standard."""
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.get(f"{url}?type=standard", None, format="json", **self.headers)
        payload = response.data

        self.assertSuccessfulList(response, payload)
        self.assertNotEqual(Workspace.objects.count(), Workspace.objects.filter(type="standard").count())
        self.assertEqual(payload.get("meta").get("count"), Workspace.objects.filter(type="standard").count())
        self.assertType(payload, "standard")

    def test_workspace_list_root(self):
        """List workspaces type=root."""
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.get(f"{url}?type=root", None, format="json", **self.headers)
        payload = response.data

        self.assertSuccessfulList(response, payload)
        self.assertEqual(payload.get("meta").get("count"), 1)
        self.assertEqual(payload.get("data")[0]["id"], str(self.root_workspace.id))
        self.assertType(payload, "root")

    def test_workspace_list_default(self):
        """List workspaces type=default."""
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.get(f"{url}?type=default", None, format="json", **self.headers)
        payload = response.data

        self.assertSuccessfulList(response, payload)
        self.assertEqual(payload.get("meta").get("count"), 1)
        self.assertEqual(payload.get("data")[0]["id"], str(self.default_workspace.id))
        self.assertType(payload, "default")

    def test_workspace_list_queryset_by_tenant(self):
        """List workspaces only for the request tenant."""
        tenant = Tenant.objects.create(tenant_name="Tenant 2")
        t2_root_workspace = Workspace.objects.create(name="Tenant 2 Root", type="root", tenant=tenant)

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.get(f"{url}?type=root", None, format="json", **self.headers)
        payload = response.data

        self.assertSuccessfulList(response, payload)
        self.assertEqual(payload.get("meta").get("count"), 1)
        self.assertEqual(payload.get("data")[0]["id"], str(self.root_workspace.id))
        self.assertType(payload, "root")

    def test_workspace_list_filter_by_name(self):
        """List workspaces filtered by name."""
        ws_name_1 = "Workspace for filter 1"
        ws_name_2 = "Workspace for filter 2"
        workspaces = Workspace.objects.bulk_create(
            [
                Workspace(
                    name=ws_name_2,
                    tenant=self.tenant,
                    type="standard",
                    parent_id=self.default_workspace.id,
                ),
                Workspace(
                    name=ws_name_1.upper(),
                    tenant=self.tenant,
                    type="standard",
                    parent_id=self.default_workspace.id,
                ),
            ]
        )

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.get(f"{url}?name={ws_name_1}", None, format="json", **self.headers)
        payload = response.data

        self.assertSuccessfulList(response, payload)
        self.assertEqual(payload.get("meta").get("count"), 1)
        self.assertType(payload, "standard")
        assert payload.get("data")[0]["name"] == ws_name_1.upper()

    def test_workspace_list_authorization_platform_default(self):
        """List workspaces authorization."""
        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        request = request_context["request"]
        headers = request.META

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.get(f"{url}?type=all", None, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self._setup_access_for_principal(self.user_data["username"], "inventory:groups:read", platform_default=True)
        response = client.get(f"{url}?type=all", None, format="json", **headers)
        payload = response.data

        self.assertSuccessfulList(response, payload)
        self.assertEqual(payload.get("meta").get("count"), Workspace.objects.count())

    def test_workspace_list_authorization_platform_default_with_wildcard(self):
        """List workspaces authorization with wildcard permission."""
        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        request = request_context["request"]
        headers = request.META

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.get(f"{url}?type=all", None, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self._setup_access_for_principal(self.user_data["username"], "inventory:*:read", platform_default=True)
        response = client.get(f"{url}?type=all", None, format="json", **headers)
        payload = response.data

        self.assertSuccessfulList(response, payload)
        self.assertEqual(payload.get("meta").get("count"), Workspace.objects.count())

        # Make sure "inventory:*:*" also works
        Group.objects.get(platform_default=True).delete()
        response = client.get(f"{url}?type=all", None, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self._setup_access_for_principal(self.user_data["username"], "inventory:*:*", platform_default=True)
        response = client.get(f"{url}?type=all", None, format="json", **headers)

    def test_workspace_list_authorization_custom_role(self):
        """List workspaces authorization."""
        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)
        request = request_context["request"]
        headers = request.META
        Workspace.objects.create(
            name="Another Standard Workspace",
            tenant=self.tenant,
            type="standard",
            parent_id=self.default_workspace.id,
        )

        url = reverse("v2_management:workspace-list")
        client = APIClient()

        self._setup_access_for_principal(
            self.user_data["username"], "inventory:groups:read", workspace_id=str(uuid4())
        )
        response = client.get(f"{url}?type=all", None, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Will include ancestors of the workspace: root->default->standard_workspace, but not the another standard ws
        self._setup_access_for_principal(
            self.user_data["username"], "inventory:groups:read", workspace_id=str(self.standard_workspace.id)
        )
        response = client.get(f"{url}?type=all", None, format="json", **headers)
        payload = response.data
        self.assertSuccessfulList(response, payload)
        self.assertEqual(len(payload.get("data")), 4)

        # Account for ungrouped and new standard workspace not having access
        self.assertEqual(payload.get("meta").get("count"), Workspace.objects.count() - 2)


@override_settings(V2_APIS_ENABLED=True)
class WorkspaceTestsDetail(WorkspaceViewTests):
    """Tests for get workspace detail."""

    def test_get_workspace(self):
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data.get("name"), "Standard Workspace")
        self.assertEqual(data.get("description"), "Standard Workspace - description")
        self.assertNotEqual(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEqual(data.get("created"), "")
        self.assertNotEqual(data.get("modified"), "")
        self.assertEqual(response.get("content-type"), "application/json")
        self.assertEqual(data.get("ancestry"), None)
        self.assertEqual(data.get("type"), "standard")
        self.assertEqual(response.get("content-type"), "application/json")

    def test_get_workspace_with_ancestry(self):
        base_url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        url = f"{base_url}?include_ancestry=true"
        client = APIClient()
        response = client.get(url, None, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data.get("name"), "Standard Workspace")
        self.assertEqual(data.get("description"), "Standard Workspace - description")
        self.assertNotEqual(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEqual(data.get("created"), "")
        self.assertNotEqual(data.get("modified"), "")
        self.assertCountEqual(
            data.get("ancestry"),
            [
                {"name": self.root_workspace.name, "id": str(self.root_workspace.id), "parent_id": None},
                {
                    "name": self.default_workspace.name,
                    "id": str(self.default_workspace.id),
                    "parent_id": str(self.root_workspace.id),
                },
            ],
        )
        self.assertEqual(data.get("type"), "standard")
        self.assertEqual(response.get("content-type"), "application/json")

    def test_get_workspace_not_found(self):
        url = reverse("v2_management:workspace-detail", kwargs={"pk": "XXXX"})
        client = APIClient()
        response = client.get(url, None, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        status_code = response.data.get("status")
        detail = response.data.get("detail")

        self.assertEqual(detail, "Not found.")
        self.assertEqual(status_code, 404)
        self.assertEqual(response.get("content-type"), "application/problem+json")

    def test_get_workspace_unauthorized(self):
        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        status_code = response.data.get("status")
        detail = response.data.get("detail")

        self.assertEqual(detail, "You do not have permission to perform this action.")
        self.assertEqual(status_code, 403)
        self.assertEqual(response.get("content-type"), "application/problem+json")

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.root_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_workspace_authorized_through_custom_role(self):
        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META
        self._setup_access_for_principal(self.user_data["username"], "inventory:groups:read")

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Can also get the ancestor
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.root_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_workspace_authorized_through_custom_role_with_resourcedef(self):
        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META
        # Assign permission of non target workspace
        self._setup_access_for_principal(
            self.user_data["username"], "inventory:groups:read", workspace_id=str(uuid4())
        )

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Assign permission of target workspace
        self._setup_access_for_principal(
            self.user_data["username"], "inventory:groups:read", workspace_id=[str(self.standard_workspace.id)]
        )
        response = client.get(url, None, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Can also get the ancestor
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.root_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Can't access another workspace within the same ancestor
        another_ws = Workspace.objects.create(
            name="Another Standard Workspace",
            tenant=self.tenant,
            type="standard",
            parent_id=self.default_workspace.id,
        )
        url = reverse("v2_management:workspace-detail", kwargs={"pk": another_ws.id})
        client = APIClient()
        response = client.get(url, None, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_workspace_authorized_through_platform_default_access(self):
        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META
        self._setup_access_for_principal(self.user_data["username"], "inventory:groups:read", platform_default=True)

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.root_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


class WorkspaceViewTestsV2Disabled(WorkspaceViewTests):
    def test_get_workspace_list(self):
        """Test for accessing v2 APIs which should be disabled by default."""
        url = "/api/rbac/v2/workspaces/"
        client = APIClient()
        response = client.get(url, None, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


@override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=2, V2_APIS_ENABLED=True)
class WorkspaceViewTestsWithHierarchyLimit(WorkspaceViewTests):
    """Test workspace hierarchy limits."""

    def test_create_nested_workspace_valid(self):
        """Test creating a workspace with valid depth."""
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        workspace = {"name": "New Workspace", "description": "Workspace", "parent_id": self.default_workspace.id}
        response = client.post(url, workspace, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_nested_workspace_invalid(self):
        """Test creating a workspace with invalid depth."""
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        workspace = {"name": "New Workspace", "description": "Workspace", "parent_id": self.standard_workspace.id}
        response = client.post(url, workspace, format="json", **self.headers)

        status_code = response.data.get("status")
        detail = response.data.get("detail")
        self.assertEqual(detail, f"Workspaces may only nest {settings.WORKSPACE_HIERARCHY_DEPTH_LIMIT} levels deep.")

        self.assertEqual(status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.get("content-type"), "application/problem+json")


@override_settings(WORKSPACE_RESTRICT_DEFAULT_PEERS=True, V2_APIS_ENABLED=True)
class WorkspaceViewTestsWithPeerRestrictions(WorkspaceViewTests):
    """Test workspace peer restrictions."""

    def test_create_nested_workspace_against_root(self):
        """Test creating a workspace with root as the parent."""
        url = reverse("v2_management:workspace-list")
        client = APIClient()
        workspace = {"name": "New Workspace", "description": "Workspace", "parent_id": self.root_workspace.id}
        response = client.post(url, workspace, format="json", **self.headers)

        status_code = response.data.get("status")
        detail = response.data.get("detail")
        self.assertEqual(detail, "Sub-workspaces may only be created under the default workspace.")

        self.assertEqual(status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.get("content-type"), "application/problem+json")
