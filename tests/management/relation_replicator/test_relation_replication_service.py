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
"""Test RelationReplicationService."""

from django.test import TestCase, override_settings
from management.relation_replicator.outbox_replicator import InMemoryLog, OutboxReplicator
from management.relation_replicator.relation_replication_service import RelationReplicationService
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.types import RelationTuple
from migration_tool.in_memory_tuples import InMemoryRelationReplicator, InMemoryTuples


@override_settings(REPLICATION_TO_RELATION_ENABLED=True)
class RelationReplicationServiceTest(TestCase):
    """Test RelationReplicationService functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.tuples = InMemoryTuples()
        self.replicator = InMemoryRelationReplicator(self.tuples)
        self.service = RelationReplicationService(replicator=self.replicator)

    def _make_permission_tuple(self, role_id: str, permission: str) -> RelationTuple:
        """Create a permission tuple for testing."""
        return RelationTuple(
            resource_type_namespace="rbac",
            resource_type_name="role",
            resource_id=role_id,
            relation=permission,
            subject_type_namespace="rbac",
            subject_type_name="principal",
            subject_id="*",
            subject_relation=None,
        )

    def test_replicate_create_adds_tuples(self):
        """Test that replicate_create adds tuples."""
        tuples = [
            self._make_permission_tuple("role-123", "inventory_hosts_read"),
            self._make_permission_tuple("role-123", "inventory_hosts_write"),
        ]

        self.service.replicate_create(
            event_type=ReplicationEventType.CREATE_CUSTOM_ROLE,
            info={"role_uuid": "role-123", "org_id": "12345"},
            tuples=tuples,
        )

        # Verify tuples were added
        self.assertEqual(len(self.tuples), 2)

    def test_replicate_update_adds_new_and_removes_old(self):
        """Test that replicate_update adds new tuples and removes old ones."""
        old_tuples = [
            self._make_permission_tuple("role-123", "inventory_hosts_read"),
        ]
        new_tuples = [
            self._make_permission_tuple("role-123", "inventory_hosts_write"),
            self._make_permission_tuple("role-123", "cost_reports_read"),
        ]

        # First add the old tuples
        self.service.replicate_create(
            event_type=ReplicationEventType.CREATE_CUSTOM_ROLE,
            info={"role_uuid": "role-123", "org_id": "12345"},
            tuples=old_tuples,
        )
        self.assertEqual(len(self.tuples), 1)

        # Now update: remove old, add new
        self.service.replicate_update(
            event_type=ReplicationEventType.UPDATE_CUSTOM_ROLE,
            info={"role_uuid": "role-123", "org_id": "12345"},
            new_tuples=new_tuples,
            old_tuples=old_tuples,
        )

        # Should have 2 tuples (old one removed, 2 new added)
        self.assertEqual(len(self.tuples), 2)

    def test_replicate_delete_removes_tuples(self):
        """Test that replicate_delete removes tuples."""
        tuples = [
            self._make_permission_tuple("role-123", "inventory_hosts_read"),
        ]

        # First add tuples
        self.service.replicate_create(
            event_type=ReplicationEventType.CREATE_CUSTOM_ROLE,
            info={"role_uuid": "role-123", "org_id": "12345"},
            tuples=tuples,
        )
        self.assertEqual(len(self.tuples), 1)

        # Now delete
        self.service.replicate_delete(
            event_type=ReplicationEventType.DELETE_CUSTOM_ROLE,
            info={"role_uuid": "role-123", "org_id": "12345"},
            tuples=tuples,
        )

        # Should have 0 tuples
        self.assertEqual(len(self.tuples), 0)

    def test_converts_relation_tuple_to_protobuf(self):
        """Test that RelationTuple is correctly converted to protobuf Relationship."""
        log = InMemoryLog()
        replicator = OutboxReplicator(log)
        service = RelationReplicationService(replicator=replicator)

        tuples = [
            self._make_permission_tuple("role-456", "inventory_hosts_read"),
        ]

        service.replicate_create(
            event_type=ReplicationEventType.CREATE_CUSTOM_ROLE,
            info={"role_uuid": "role-456", "org_id": "12345"},
            tuples=tuples,
        )

        # Verify the outbox event was created with correct structure
        self.assertEqual(len(log), 1)
        outbox_event = log.first()

        # Check the payload has the expected structure
        relations_to_add = outbox_event.payload["relations_to_add"]
        self.assertEqual(len(relations_to_add), 1)

        relation = relations_to_add[0]
        self.assertEqual(relation["resource"]["type"]["namespace"], "rbac")
        self.assertEqual(relation["resource"]["type"]["name"], "role")
        self.assertEqual(relation["resource"]["id"], "role-456")
        self.assertEqual(relation["relation"], "inventory_hosts_read")
        self.assertEqual(relation["subject"]["subject"]["type"]["namespace"], "rbac")
        self.assertEqual(relation["subject"]["subject"]["type"]["name"], "principal")
        self.assertEqual(relation["subject"]["subject"]["id"], "*")


@override_settings(REPLICATION_TO_RELATION_ENABLED=False)
class RelationReplicationServiceDisabledTest(TestCase):
    """Test RelationReplicationService when replication is disabled."""

    def test_uses_noop_replicator_when_disabled(self):
        """Test that NoopReplicator is used when replication is disabled."""
        from management.relation_replicator.noop_replicator import NoopReplicator

        service = RelationReplicationService()

        # Should use NoopReplicator
        self.assertIsInstance(service._replicator, NoopReplicator)

    def test_replicate_create_does_nothing_when_disabled(self):
        """Test that replicate_create is a no-op when disabled."""
        service = RelationReplicationService()

        tuples = [
            RelationTuple(
                resource_type_namespace="rbac",
                resource_type_name="role",
                resource_id="role-123",
                relation="test_permission",
                subject_type_namespace="rbac",
                subject_type_name="principal",
                subject_id="*",
                subject_relation=None,
            )
        ]

        # Should not raise, just do nothing
        service.replicate_create(
            event_type=ReplicationEventType.CREATE_CUSTOM_ROLE,
            info={"role_uuid": "role-123", "org_id": "12345"},
            tuples=tuples,
        )
