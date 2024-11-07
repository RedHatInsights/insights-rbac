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
"""Test OutboxReplicator."""

from django.test import TestCase, override_settings
from google.protobuf import json_format
from management.relation_replicator.outbox_replicator import InMemoryLog, OutboxReplicator
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType
from migration_tool.utils import create_relationship


class OutboxReplicatorTest(TestCase):
    """Test OutboxReplicator."""

    def setUp(self):
        """Set up."""
        self.log = InMemoryLog()
        self.replicator = OutboxReplicator(self.log)

    @override_settings(ENV_NAME="test-env")
    def test_replicate_sends_event_to_log_as_json(self):
        """Test replicate uses partition key from settings.ENV_NAME."""
        principal_to_group_add1 = create_relationship(
            ("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p1", "member"
        )
        principal_to_group_add2 = create_relationship(
            ("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p2", "member"
        )
        principal_to_group_remove1 = create_relationship(
            ("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p3", "member"
        )
        principal_to_group_remove2 = create_relationship(
            ("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p4", "member"
        )
        event = ReplicationEvent(
            add=[principal_to_group_add1, principal_to_group_add2],
            remove=[principal_to_group_remove1, principal_to_group_remove2],
            event_type=ReplicationEventType.ADD_PRINCIPALS_TO_GROUP,
            info={"key": "value"},
            partition_key=PartitionKey.byEnvironment(),
        )
        self.replicator.replicate(event)

        self.assertEqual(len(self.log), 1)

        logged_event = self.log.first()

        self.assertEqual(logged_event.aggregateid, "test-env")
        self.assertEqual(logged_event.event_type, ReplicationEventType.ADD_PRINCIPALS_TO_GROUP)
        self.assertEqual(
            logged_event.payload,
            {
                "relations_to_add": [
                    json_format.MessageToDict(principal_to_group_add1),
                    json_format.MessageToDict(principal_to_group_add2)
                ],
                "relations_to_remove": [
                    json_format.MessageToDict(principal_to_group_remove1),
                    json_format.MessageToDict(principal_to_group_remove2)
                ],
            },
        )
        self.assertEqual(logged_event.aggregatetype, "relations-replication-event")

    def test_replicate_empty_event_warns_instead_of_saving(self):
        """Test replicate with empty event warns."""
        event = ReplicationEvent(
            add=[],
            remove=[],
            event_type=ReplicationEventType.ADD_PRINCIPALS_TO_GROUP,
            info={"key": "value"},
            partition_key=PartitionKey.byEnvironment(),
        )

        with self.assertLogs("management.relation_replicator.outbox_replicator", level="WARNING") as logs:
            self.replicator.replicate(event)

        self.assertEqual(len(self.log), 0)
        self.assertEqual(len(logs.output), 1)
        self.assertIn("Skipping empty replication event.", logs.output[0])
        self.assertIn("info.key='value'", logs.output[0])
        self.assertIn(str(ReplicationEventType.ADD_PRINCIPALS_TO_GROUP), logs.output[0])

    def test_does_not_warn_if_not_empty_payload(self):
        """Test replicate with non-empty payload."""
        principal_to_group = create_relationship(
            ("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p1", "member"
        )
        event = ReplicationEvent(
            add=[principal_to_group],
            remove=[],
            event_type=ReplicationEventType.ADD_PRINCIPALS_TO_GROUP,
            info={"key": "value"},
            partition_key=PartitionKey.byEnvironment(),
        )

        with self.assertLogs("management.relation_replicator.outbox_replicator") as logs:
            self.replicator.replicate(event)

        self.assertEqual(len(self.log), 1)
        self.assertFalse(any(record.levelname == "WARNING" for record in logs.records))

    def test_only_remove_is_not_considered_empty(self):
        """Test replicate with only remove is not considered empty."""
        principal_to_group = create_relationship(
            ("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p1", "member"
        )
        event = ReplicationEvent(
            add=[],
            remove=[principal_to_group],
            event_type=ReplicationEventType.ADD_PRINCIPALS_TO_GROUP,
            info={"key": "value"},
            partition_key=PartitionKey.byEnvironment(),
        )

        self.replicator.replicate(event)
        self.assertEqual(len(self.log), 1)

    def test_only_add_is_not_considered_empty(self):
        """Test replicate with only add is not considered empty."""
        principal_to_group = create_relationship(
            ("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p1", "member"
        )
        event = ReplicationEvent(
            add=[principal_to_group],
            remove=[],
            event_type=ReplicationEventType.ADD_PRINCIPALS_TO_GROUP,
            info={"key": "value"},
            partition_key=PartitionKey.byEnvironment(),
        )

        self.replicator.replicate(event)
        self.assertEqual(len(self.log), 1)

    def test_both_add_and_remove_is_not_considered_empty(self):
        """Test replicate with both add and remove is not considered empty."""
        principal_to_group_add = create_relationship(
            ("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p1", "member"
        )
        principal_to_group_remove = create_relationship(
            ("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p2", "member"
        )
        event = ReplicationEvent(
            add=[principal_to_group_add],
            remove=[principal_to_group_remove],
            event_type=ReplicationEventType.ADD_PRINCIPALS_TO_GROUP,
            info={"key": "value"},
            partition_key=PartitionKey.byEnvironment(),
        )

        self.replicator.replicate(event)
        self.assertEqual(len(self.log), 1)
