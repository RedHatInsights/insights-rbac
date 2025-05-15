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
from tests.identity_request import IdentityRequest


@override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=100, WORKSPACE_RESTRICT_DEFAULT_PEERS=False)
class WorkspaceViewTests(IdentityRequest):
    """Test the Workspace view."""

    def setUp(self):
        """Set up the workspace model tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()

    def tearDown(self):
        """Tear down group model tests."""
        Workspace.objects.update(parent=None)
        Workspace.objects.all().delete()

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


@override_settings(V2_APIS_ENABLED=True)
class WorkspaceTestsCreateUpdateDelete(WorkspaceViewTests):
    """Tests for create/update/delete workspaces."""

    def setUp(self):
        super().setUp()
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
        self.standard_workspace = Workspace.objects.create(
            name="Standard Workspace",
            description="Standard Workspace - description",
            tenant=self.tenant,
            parent=self.default_workspace,
            type=Workspace.Types.STANDARD,
        )
        self.ungrouped_workspace = Workspace.objects.create(
            name="Ungrouped Hosts Workspace",
            description="Ungrouped Hosts Workspace - description",
            tenant=self.tenant,
            parent=self.default_workspace,
            type=Workspace.Types.UNGROUPED_HOSTS,
        )
        self.tuples = InMemoryTuples()
        self.in_memory_replicator = InMemoryRelationReplicator(self.tuples)


@override_settings(V2_APIS_ENABLED=True)
class WorkspaceViewTestsV2Enabled(WorkspaceViewTests):

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate_workspace")
    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    def test_create_workspace(self, replicate_workspace, replicate):
        """Test for creating a workspace."""
        replicate.side_effect = self.in_memory_replicator.replicate
        workspace_data = {
            "name": "New Workspace parent",
            "description": "New Workspace - description",
            "tenant_id": self.tenant.id,
            "parent_id": self.standard_workspace.id,
        }
        parent_workspace = Workspace.objects.create(**workspace_data)
        workspace = {"name": "New Workspace", "description": "Workspace", "parent_id": parent_workspace.id}

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        data = response.data
        self.assertEqual(data.get("name"), "New Workspace")
        self.assertNotEquals(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEquals(data.get("created"), "")
        self.assertNotEquals(data.get("modified"), "")
        self.assertEquals(data.get("description"), "Workspace")
        self.assertEquals(data.get("type"), "standard")
        self.assertEqual(response.get("content-type"), "application/json")
        tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", data.get("id")),
                relation("parent"),
                subject("rbac", "workspace", str(parent_workspace.id)),
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
        self.assertNotEquals(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEquals(data.get("created"), "")
        self.assertNotEquals(data.get("modified"), "")
        self.assertEquals(data.get("description"), "Workspace")
        self.assertEquals(data.get("type"), "standard")
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
        self.assertNotEquals(data.get("id"), "")
        self.assertNotEquals(data.get("parent_id"), data.get("id"))
        self.assertIsNotNone(data.get("id"))
        self.assertNotEquals(data.get("created"), "")
        self.assertNotEquals(data.get("modified"), "")
        self.assertEquals(data.get("description"), "Workspace")
        self.assertEquals(data.get("type"), "standard")
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
        self.assertNotEquals(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEquals(data.get("created"), "")
        self.assertNotEquals(data.get("modified"), "")
        self.assertEquals(data.get("type"), "standard")
        self.assertEquals(data.get("description"), "Updated description")

        update_workspace = Workspace.objects.filter(id=workspace.id).first()
        self.assertEquals(update_workspace.name, "Updated name")
        self.assertEquals(update_workspace.description, "Updated description")
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
        self.assertNotEquals(data.get("created"), "")
        self.assertNotEquals(data.get("modified"), "")
        self.assertEquals(data.get("type"), "standard")

        update_workspace = Workspace.objects.filter(id=workspace.id).first()
        self.assertEquals(update_workspace.name, "New Workspace")

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
        self.assertNotEquals(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEquals(data.get("created"), "")
        self.assertNotEquals(data.get("modified"), "")
        self.assertEquals(data.get("type"), "standard")

        update_workspace = Workspace.objects.filter(id=workspace.id).first()
        self.assertEquals(update_workspace.name, "Updated name")
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

    def test_get_workspace(self):
        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data.get("name"), "Standard Workspace")
        self.assertEquals(data.get("description"), "Standard Workspace - description")
        self.assertNotEquals(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEquals(data.get("created"), "")
        self.assertNotEquals(data.get("modified"), "")
        self.assertEqual(response.get("content-type"), "application/json")
        self.assertEqual(data.get("ancestry"), None)
        self.assertEquals(data.get("type"), "standard")
        self.assertEqual(response.get("content-type"), "application/json")

    def test_get_workspace_with_ancestry(self):
        base_url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        url = f"{base_url}?include_ancestry=true"
        client = APIClient()
        response = client.get(url, None, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data.get("name"), "Standard Workspace")
        self.assertEquals(data.get("description"), "Standard Workspace - description")
        self.assertNotEquals(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEquals(data.get("created"), "")
        self.assertNotEquals(data.get("modified"), "")
        self.assertEqual(
            data.get("ancestry"),
            [{"name": self.root_workspace.name, "id": str(self.root_workspace.id), "parent_id": None}],
        )
        self.assertEquals(data.get("type"), "standard")
        self.assertEqual(response.get("content-type"), "application/json")
        self.assertEqual(data.get("ancestry"), None)

    def test_get_workspace_with_ancestry(self):
        base_url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        url = f"{base_url}?include_ancestry=true"
        client = APIClient()
        response = client.get(url, None, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data.get("name"), "Standard Workspace")
        self.assertEquals(data.get("description"), "Standard Workspace - description")
        self.assertNotEquals(data.get("id"), "")
        self.assertIsNotNone(data.get("id"))
        self.assertNotEquals(data.get("created"), "")
        self.assertNotEquals(data.get("modified"), "")
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
        self.assertEquals(data.get("type"), "standard")
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

    def test_get_workspace_authorized_through_custom_role(self):
        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META
        self._setup_access_for_principal(self.user_data["username"], "inventory:groups:read")

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
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

    def test_get_workspace_authorized_through_platform_default_access(self):
        request_context = self._create_request_context(self.customer_data, self.user_data, is_org_admin=False)

        request = request_context["request"]
        headers = request.META
        self._setup_access_for_principal(self.user_data["username"], "inventory:groups:read", platform_default=True)

        url = reverse("v2_management:workspace-detail", kwargs={"pk": self.standard_workspace.id})
        client = APIClient()
        response = client.get(url, None, format="json", **headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

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
        self.assertEqual(len(payload.get("data")), 3)
        self.assertEqual(payload.get("meta").get("count"), Workspace.objects.count() - 1)


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
