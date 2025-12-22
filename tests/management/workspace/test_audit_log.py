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
"""Test the workspace audit log functionality."""
from importlib import reload
from unittest.mock import patch

from django.test.utils import override_settings
from django.urls import clear_url_caches, reverse
from rest_framework import status
from rest_framework.test import APIClient

from management.models import AuditLog, Workspace
from management.workspace.service import WorkspaceService
from migration_tool.in_memory_tuples import InMemoryRelationReplicator, InMemoryTuples
from rbac import urls
from tests.identity_request import TransactionalIdentityRequest


@override_settings(V2_APIS_ENABLED=True, WORKSPACE_HIERARCHY_DEPTH_LIMIT=100, WORKSPACE_RESTRICT_DEFAULT_PEERS=False)
class WorkspaceAuditLogTests(TransactionalIdentityRequest):
    """Test audit logging for workspace operations."""

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=10)
    def setUp(self) -> None:
        """Set up the workspace audit log tests."""
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
        self.standard_workspace = self.service.create(
            {"name": "Standard Workspace", "description": "Test workspace", "parent_id": self.default_workspace.id},
            self.tenant,
        )

        self.tuples = InMemoryTuples()
        self.in_memory_replicator = InMemoryRelationReplicator(self.tuples)

        # Patch get_queryset to not use select_for_update during tests
        from management.workspace.view import WorkspaceViewSet

        original_get_queryset = WorkspaceViewSet.get_queryset

        def get_queryset_without_lock(self):
            from management.base_viewsets import BaseV2ViewSet

            return BaseV2ViewSet.get_queryset(self)

        self.patcher = patch.object(WorkspaceViewSet, "get_queryset", get_queryset_without_lock)
        self.patcher.start()

    def tearDown(self) -> None:
        """Tear down workspace audit log tests."""
        self.patcher.stop()
        from management.utils import PRINCIPAL_CACHE

        Workspace.objects.update(parent=None)
        Workspace.objects.all().delete()
        AuditLog.objects.all().delete()
        PRINCIPAL_CACHE.delete_all_principals_for_tenant(self.tenant.org_id)
        super().tearDown()

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate_workspace")
    def test_create_workspace_creates_audit_log(self, replicate_workspace, replicate) -> None:
        """Test that creating a workspace creates an audit log entry."""
        replicate.side_effect = self.in_memory_replicator.replicate
        workspace_data = {"name": "Audited Workspace", "description": "Test", "parent_id": self.default_workspace.id}

        url = reverse("v2_management:workspace-list")
        client = APIClient()
        response = client.post(url, workspace_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify audit log was created
        audit_logs = AuditLog.objects.filter(resource_type=AuditLog.WORKSPACE, action=AuditLog.CREATE)
        self.assertEqual(audit_logs.count(), 1)

        audit_log = audit_logs.first()
        self.assertEqual(audit_log.action, AuditLog.CREATE)
        self.assertEqual(audit_log.resource_type, AuditLog.WORKSPACE)
        self.assertIn("Audited Workspace", audit_log.description)
        self.assertEqual(str(audit_log.resource_uuid), response.data.get("id"))
        self.assertEqual(audit_log.principal_username, self.user_data["username"])

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate_workspace")
    def test_update_workspace_creates_audit_log(self, replicate_workspace, replicate) -> None:
        """Test that updating a workspace creates an audit log entry."""
        replicate.side_effect = self.in_memory_replicator.replicate

        url = reverse("v2_management:workspace-detail", kwargs={"pk": str(self.standard_workspace.id)})
        client = APIClient()
        update_data = {"name": "Updated Workspace Name", "description": "Updated description"}
        response = client.put(url, update_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify audit log was created
        audit_logs = AuditLog.objects.filter(resource_type=AuditLog.WORKSPACE, action=AuditLog.EDIT)
        self.assertEqual(audit_logs.count(), 1)

        audit_log = audit_logs.first()
        self.assertEqual(audit_log.action, AuditLog.EDIT)
        self.assertEqual(audit_log.resource_type, AuditLog.WORKSPACE)
        self.assertIn("Updated Workspace Name", audit_log.description)
        self.assertIn("name:", audit_log.description)
        # Verify description change is also logged when both name and description change
        self.assertIn("description updated", audit_log.description)
        self.assertEqual(str(audit_log.resource_uuid), str(self.standard_workspace.id))
        self.assertEqual(audit_log.principal_username, self.user_data["username"])

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate_workspace")
    def test_update_workspace_only_description_creates_audit_log(self, replicate_workspace, replicate) -> None:
        """Test that updating only description creates correct audit log."""
        replicate.side_effect = self.in_memory_replicator.replicate

        url = reverse("v2_management:workspace-detail", kwargs={"pk": str(self.standard_workspace.id)})
        client = APIClient()
        # Keep same name, only update description
        update_data = {"name": self.standard_workspace.name, "description": "New description only"}
        response = client.put(url, update_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        audit_logs = AuditLog.objects.filter(resource_type=AuditLog.WORKSPACE, action=AuditLog.EDIT)
        self.assertEqual(audit_logs.count(), 1)

        audit_log = audit_logs.first()
        self.assertEqual(audit_log.action, AuditLog.EDIT)
        self.assertEqual(audit_log.resource_type, AuditLog.WORKSPACE)
        self.assertIn("description updated", audit_log.description)
        self.assertNotIn("name:", audit_log.description)
        self.assertEqual(str(audit_log.resource_uuid), str(self.standard_workspace.id))
        self.assertEqual(audit_log.principal_username, self.user_data["username"])

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate_workspace")
    def test_delete_workspace_creates_audit_log(self, replicate_workspace, replicate) -> None:
        """Test that deleting a workspace creates an audit log entry."""
        replicate.side_effect = self.in_memory_replicator.replicate

        # Create a workspace to delete
        workspace_to_delete = self.service.create(
            {"name": "Workspace to Delete", "description": "Will be deleted", "parent_id": self.default_workspace.id},
            self.tenant,
        )
        workspace_id = str(workspace_to_delete.id)
        workspace_name = workspace_to_delete.name

        url = reverse("v2_management:workspace-detail", kwargs={"pk": workspace_id})
        client = APIClient()
        response = client.delete(url, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Verify audit log was created
        audit_logs = AuditLog.objects.filter(resource_type=AuditLog.WORKSPACE, action=AuditLog.DELETE)
        self.assertEqual(audit_logs.count(), 1)

        audit_log = audit_logs.first()
        self.assertEqual(audit_log.action, AuditLog.DELETE)
        self.assertEqual(audit_log.resource_type, AuditLog.WORKSPACE)
        self.assertIn(workspace_name, audit_log.description)
        self.assertEqual(str(audit_log.resource_uuid), workspace_id)
        self.assertEqual(audit_log.principal_username, self.user_data["username"])

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate_workspace")
    def test_move_workspace_creates_audit_log(self, replicate_workspace, replicate) -> None:
        """Test that moving a workspace creates an audit log entry."""
        replicate.side_effect = self.in_memory_replicator.replicate

        # Create target parent workspace
        target_workspace = self.service.create(
            {"name": "Target Parent", "description": "Target", "parent_id": self.default_workspace.id},
            self.tenant,
        )

        # Create workspace to move
        workspace_to_move = self.service.create(
            {"name": "Workspace to Move", "description": "Will be moved", "parent_id": self.default_workspace.id},
            self.tenant,
        )
        original_parent_id = workspace_to_move.parent_id

        url = reverse("v2_management:workspace-move", kwargs={"pk": str(workspace_to_move.id)})
        client = APIClient()
        move_data = {"parent_id": str(target_workspace.id)}
        response = client.post(url, move_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify audit log was created
        audit_logs = AuditLog.objects.filter(resource_type=AuditLog.WORKSPACE, action=AuditLog.MOVE)
        self.assertEqual(audit_logs.count(), 1)

        audit_log = audit_logs.first()
        self.assertEqual(audit_log.action, AuditLog.MOVE)
        self.assertEqual(audit_log.resource_type, AuditLog.WORKSPACE)
        self.assertIn("Workspace to Move", audit_log.description)
        self.assertIn(str(original_parent_id), audit_log.description)
        self.assertIn(str(target_workspace.id), audit_log.description)
        self.assertEqual(str(audit_log.resource_uuid), str(workspace_to_move.id))
        self.assertEqual(str(audit_log.secondary_resource_uuid), str(target_workspace.id))
        self.assertEqual(audit_log.principal_username, self.user_data["username"])

    def test_audit_log_workspace_resource_type_exists(self) -> None:
        """Test that WORKSPACE is a valid resource type choice."""
        self.assertEqual(AuditLog.WORKSPACE, "workspace")
        resource_types = [choice[0] for choice in AuditLog.RESOURCE_CHOICES]
        self.assertIn(AuditLog.WORKSPACE, resource_types)

    def test_audit_log_move_action_exists(self) -> None:
        """Test that MOVE is a valid action type choice."""
        self.assertEqual(AuditLog.MOVE, "move")
        action_types = [choice[0] for choice in AuditLog.ACTION_CHOICES]
        self.assertIn(AuditLog.MOVE, action_types)


@override_settings(V2_APIS_ENABLED=True, WORKSPACE_HIERARCHY_DEPTH_LIMIT=100, WORKSPACE_RESTRICT_DEFAULT_PEERS=False)
class WorkspaceAuditLogModelTests(TransactionalIdentityRequest):
    """Test audit log model methods for workspace operations."""

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=10)
    def setUp(self) -> None:
        """Set up the workspace audit log model tests."""
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

    def tearDown(self) -> None:
        """Tear down workspace audit log model tests."""
        from management.utils import PRINCIPAL_CACHE

        Workspace.objects.update(parent=None)
        Workspace.objects.all().delete()
        AuditLog.objects.all().delete()
        PRINCIPAL_CACHE.delete_all_principals_for_tenant(self.tenant.org_id)
        super().tearDown()

    def test_log_workspace_create_sets_correct_fields(self) -> None:
        """Test that log_workspace_create sets all required fields correctly."""
        workspace = Workspace.objects.create(
            name="Test Workspace",
            tenant=self.tenant,
            parent=self.default_workspace,
        )

        # Create a mock request
        from unittest.mock import Mock

        request = Mock()
        request.user = Mock()
        request.user.username = "test_user"
        request._user = Mock()
        request._user.org_id = self.tenant.org_id

        audit_log = AuditLog()
        audit_log.log_workspace_create(request, workspace)

        self.assertEqual(audit_log.principal_username, "test_user")
        self.assertEqual(audit_log.resource_type, AuditLog.WORKSPACE)
        self.assertEqual(audit_log.action, AuditLog.CREATE)
        self.assertEqual(audit_log.resource_uuid, workspace.id)
        self.assertIsNone(audit_log.resource_id)
        self.assertIn("Test Workspace", audit_log.description)
        self.assertEqual(audit_log.tenant_id, self.tenant.id)

    def test_log_workspace_update_captures_name_change(self) -> None:
        """Test that log_workspace_update captures name changes."""
        workspace = Workspace.objects.create(
            name="New Name",
            tenant=self.tenant,
            parent=self.default_workspace,
        )

        from unittest.mock import Mock

        request = Mock()
        request.user = Mock()
        request.user.username = "test_user"
        request._user = Mock()
        request._user.org_id = self.tenant.org_id

        audit_log = AuditLog()
        audit_log.log_workspace_update(request, workspace, "Old Name", "Old description")

        self.assertEqual(audit_log.action, AuditLog.EDIT)
        self.assertIn("name:", audit_log.description)
        self.assertIn("Old Name", audit_log.description)
        self.assertIn("New Name", audit_log.description)

    def test_log_workspace_delete_sets_correct_fields(self) -> None:
        """Test that log_workspace_delete sets all required fields correctly."""
        workspace = Workspace.objects.create(
            name="Workspace to Delete",
            tenant=self.tenant,
            parent=self.default_workspace,
        )

        from unittest.mock import Mock

        request = Mock()
        request.user = Mock()
        request.user.username = "test_user"
        request._user = Mock()
        request._user.org_id = self.tenant.org_id

        audit_log = AuditLog()
        audit_log.log_workspace_delete(request, workspace)

        self.assertEqual(audit_log.principal_username, "test_user")
        self.assertEqual(audit_log.resource_type, AuditLog.WORKSPACE)
        self.assertEqual(audit_log.action, AuditLog.DELETE)
        self.assertEqual(audit_log.resource_uuid, workspace.id)
        self.assertIn("Workspace to Delete", audit_log.description)
        self.assertEqual(audit_log.tenant_id, self.tenant.id)

    def test_log_workspace_move_sets_correct_fields(self) -> None:
        """Test that log_workspace_move sets all required fields correctly."""
        workspace = Workspace.objects.create(
            name="Moving Workspace",
            tenant=self.tenant,
            parent=self.default_workspace,
        )

        from unittest.mock import Mock
        import uuid

        request = Mock()
        request.user = Mock()
        request.user.username = "test_user"
        request._user = Mock()
        request._user.org_id = self.tenant.org_id

        old_parent_id = uuid.uuid4()
        new_parent_id = uuid.uuid4()

        audit_log = AuditLog()
        audit_log.log_workspace_move(request, workspace, old_parent_id, new_parent_id)

        self.assertEqual(audit_log.principal_username, "test_user")
        self.assertEqual(audit_log.resource_type, AuditLog.WORKSPACE)
        self.assertEqual(audit_log.action, AuditLog.MOVE)
        self.assertEqual(audit_log.resource_uuid, workspace.id)
        self.assertEqual(audit_log.secondary_resource_uuid, new_parent_id)
        self.assertIn("Moving Workspace", audit_log.description)
        self.assertIn(str(old_parent_id), audit_log.description)
        self.assertIn(str(new_parent_id), audit_log.description)
        self.assertEqual(audit_log.tenant_id, self.tenant.id)
