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

import logging
from uuid import uuid4
from django.test import TestCase, override_settings
from google.protobuf import json_format
from management.relation_replicator.outbox_replicator import InMemoryLog, OutboxReplicator, OutboxWAL
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType
from migration_tool.utils import create_relationship
from prometheus_client import REGISTRY


@override_settings(
    LOGGING={
        "version": 1,
        "disable_existing_loggers": False,
        "loggers": {
            "management.relation_replicator.outbox_replicator": {
                "level": "INFO",
            },
        },
    },
)
class OutboxReplicatorTest(TestCase):
    """Test OutboxReplicator."""

    def setUp(self):
        """Set up."""
        super().setUp()
        self.log = InMemoryLog()
        self.replicator = OutboxReplicator(self.log)
        self._prior_logging_disable_level = logging.root.manager.disable
        logging.disable(logging.NOTSET)

    def tearDown(self) -> None:
        super().tearDown()
        logging.disable(self._prior_logging_disable_level)

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
                    json_format.MessageToDict(principal_to_group_add2),
                ],
                "relations_to_remove": [
                    json_format.MessageToDict(principal_to_group_remove1),
                    json_format.MessageToDict(principal_to_group_remove2),
                ],
            },
        )
        self.assertEqual(logged_event.aggregatetype, "relations-replication-event")

    def test_replicate_sets_resource_type_and_id_from_identifiers_for_workspace(self):
        """Test that resource_type and resource_id are set correctly based on resource identifiers for workspace event."""

        principal_to_group = create_relationship(
            ("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p1", "member"
        )

        # Test workspace resource type
        workspace_id = uuid4()
        event = ReplicationEvent(
            add=[principal_to_group],
            remove=[],
            event_type=ReplicationEventType.CREATE_WORKSPACE,
            info={"workspace_id": workspace_id, "org_id": "123456"},
            partition_key=PartitionKey.byEnvironment(),
        )
        self.replicator.replicate(event)

        logged_event = self.log[0]
        self.assertIn("resource_type", logged_event.payload["resource_context"])
        self.assertEqual(logged_event.payload["resource_context"]["resource_type"], "Workspace")
        self.assertIn("resource_id", logged_event.payload["resource_context"])
        self.assertEqual(logged_event.payload["resource_context"]["resource_id"], str(workspace_id))
        self.assertNotIn("workspace_id", logged_event.payload["resource_context"])

    def test_resource_context_for_system_role_events(self):
        """Test resource context for system role events."""
        relation = create_relationship(("rbac", "role"), "r1", ("rbac", "principal"), "localhost/p1", "member")
        role_uuid = uuid4()

        test_cases = [
            (ReplicationEventType.CREATE_SYSTEM_ROLE, "role_uuid", "SystemRole"),
            (ReplicationEventType.UPDATE_SYSTEM_ROLE, "role_uuid", "SystemRole"),
            (ReplicationEventType.DELETE_SYSTEM_ROLE, "v1_role_uuid", "SystemRole"),
            (ReplicationEventType.MIGRATE_SYSTEM_ROLE_ASSIGNMENT, "role_uuid", "SystemRole"),
        ]

        for event_type, id_field, expected_type in test_cases:
            self.log.clear()
            event = ReplicationEvent(
                add=[relation],
                remove=[],
                event_type=event_type,
                info={id_field: role_uuid, "org_id": "123456"},
                partition_key=PartitionKey.byEnvironment(),
            )
            self.replicator.replicate(event)

            logged_event = self.log[0]
            context = logged_event.payload["resource_context"]
            self.assertEqual(context["resource_type"], expected_type)
            self.assertEqual(context["resource_id"], str(role_uuid))
            self.assertEqual(context["org_id"], "123456")

    def test_resource_context_for_custom_role_events(self):
        """Test resource context for custom role events."""
        relation = create_relationship(("rbac", "role"), "r1", ("rbac", "principal"), "localhost/p1", "member")
        role_uuid = uuid4()

        test_cases = [
            (ReplicationEventType.CREATE_CUSTOM_ROLE, "role_uuid"),
            (ReplicationEventType.UPDATE_CUSTOM_ROLE, "role_uuid"),
            (ReplicationEventType.DELETE_CUSTOM_ROLE, "v1_role_uuid"),
            (ReplicationEventType.MIGRATE_CUSTOM_ROLE, "role_uuid"),
        ]

        for event_type, id_field in test_cases:
            self.log.clear()
            event = ReplicationEvent(
                add=[relation],
                remove=[],
                event_type=event_type,
                info={id_field: role_uuid, "org_id": "123456"},
                partition_key=PartitionKey.byEnvironment(),
            )
            self.replicator.replicate(event)

            logged_event = self.log[0]
            context = logged_event.payload["resource_context"]
            self.assertEqual(context["resource_type"], "CustomRole")
            self.assertEqual(context["resource_id"], str(role_uuid))

    def test_resource_context_for_group_events(self):
        """Test resource context for group events."""
        relation = create_relationship(("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p1", "member")
        group_uuid = uuid4()

        test_cases = [
            ReplicationEventType.CREATE_GROUP,
            ReplicationEventType.UPDATE_GROUP,
            ReplicationEventType.DELETE_GROUP,
            ReplicationEventType.ADD_PRINCIPALS_TO_GROUP,
            ReplicationEventType.REMOVE_PRINCIPALS_FROM_GROUP,
            ReplicationEventType.CUSTOMIZE_DEFAULT_GROUP,
        ]

        for event_type in test_cases:
            self.log.clear()
            event = ReplicationEvent(
                add=[relation],
                remove=[],
                event_type=event_type,
                info={"group_uuid": group_uuid, "org_id": "123456"},
                partition_key=PartitionKey.byEnvironment(),
            )
            self.replicator.replicate(event)

            logged_event = self.log[0]
            context = logged_event.payload["resource_context"]
            self.assertEqual(context["resource_type"], "Group")
            self.assertEqual(context["resource_id"], str(group_uuid))

    def test_resource_context_for_user_events(self):
        """Test resource context for user events."""
        relation = create_relationship(("rbac", "user"), "u1", ("rbac", "group"), "g1", "member")
        user_id = "test-user-123"

        test_cases = [
            ReplicationEventType.EXTERNAL_USER_UPDATE,
            ReplicationEventType.EXTERNAL_USER_DISABLE,
        ]

        for event_type in test_cases:
            self.log.clear()
            event = ReplicationEvent(
                add=[relation],
                remove=[],
                event_type=event_type,
                info={"user_id": user_id, "org_id": "123456"},
                partition_key=PartitionKey.byEnvironment(),
            )
            self.replicator.replicate(event)

            logged_event = self.log[0]
            context = logged_event.payload["resource_context"]
            self.assertEqual(context["resource_type"], "User")
            self.assertEqual(context["resource_id"], user_id)

    def test_resource_context_for_tenant_events(self):
        """Test resource context for tenant events."""
        relation = create_relationship(("rbac", "tenant"), "t1", ("rbac", "workspace"), "w1", "owner")

        event = ReplicationEvent(
            add=[relation],
            remove=[],
            event_type=ReplicationEventType.BOOTSTRAP_TENANT,
            info={"org_id": "123456", "default_workspace_id": str(uuid4())},
            partition_key=PartitionKey.byEnvironment(),
        )
        self.replicator.replicate(event)

        logged_event = self.log[0]
        context = logged_event.payload["resource_context"]
        self.assertEqual(context["resource_type"], "Tenant")
        self.assertEqual(context["org_id"], "123456")

    def test_resource_context_for_cross_account_events(self):
        """Test resource context for cross-account request events."""
        relation = create_relationship(("rbac", "user"), "u1", ("rbac", "role"), "r1", "member")
        user_id = "cross-account-user"

        test_cases = [
            ReplicationEventType.APPROVE_CROSS_ACCOUNT_REQUEST,
            ReplicationEventType.DENY_CROSS_ACCOUNT_REQUEST,
            ReplicationEventType.EXPIRE_CROSS_ACCOUNT_REQUEST,
            ReplicationEventType.MIGRATE_CROSS_ACCOUNT_REQUEST,
        ]

        for event_type in test_cases:
            self.log.clear()
            event = ReplicationEvent(
                add=[relation],
                remove=[],
                event_type=event_type,
                info={"user_id": user_id, "org_id": "123456"},
                partition_key=PartitionKey.byEnvironment(),
            )
            self.replicator.replicate(event)

            logged_event = self.log[0]
            context = logged_event.payload["resource_context"]
            self.assertEqual(context["resource_type"], "CrossAccountRequest")
            self.assertEqual(context["resource_id"], user_id)

    def test_resource_context_for_bulk_events(self):
        """Test resource context for bulk events."""
        relation = create_relationship(("rbac", "tenant"), "t1", ("rbac", "workspace"), "w1", "owner")

        # Test bulk tenant bootstrap
        event = ReplicationEvent(
            add=[relation],
            remove=[],
            event_type=ReplicationEventType.BULK_BOOTSTRAP_TENANT,
            info={"num_tenants": 5, "first_org_id": "111111", "org_id": "123456"},
            partition_key=PartitionKey.byEnvironment(),
        )
        self.replicator.replicate(event)

        logged_event = self.log[0]
        context = logged_event.payload["resource_context"]
        self.assertEqual(context["resource_type"], "BulkTenant")
        self.assertEqual(context["resource_id"], "bulk:5:111111")

        # Test bulk user update
        self.log.clear()
        event = ReplicationEvent(
            add=[relation],
            remove=[],
            event_type=ReplicationEventType.BULK_EXTERNAL_USER_UPDATE,
            info={"num_users": 10, "first_user_id": "user-001", "org_id": "123456"},
            partition_key=PartitionKey.byEnvironment(),
        )
        self.replicator.replicate(event)

        logged_event = self.log[0]
        context = logged_event.payload["resource_context"]
        self.assertEqual(context["resource_type"], "BulkUser")
        self.assertEqual(context["resource_id"], "bulk:10:user-001")

    def test_resource_context_for_role_assignment_events(self):
        """Test resource context for role assignment events."""
        relation = create_relationship(("rbac", "role"), "r1", ("rbac", "principal"), "localhost/p1", "member")
        role_uuid = uuid4()

        test_cases = [
            ReplicationEventType.ASSIGN_ROLE,
            ReplicationEventType.UNASSIGN_ROLE,
        ]

        for event_type in test_cases:
            self.log.clear()
            event = ReplicationEvent(
                add=[relation],
                remove=[],
                event_type=event_type,
                info={"role_uuid": role_uuid, "org_id": "123456"},
                partition_key=PartitionKey.byEnvironment(),
            )
            self.replicator.replicate(event)

            logged_event = self.log[0]
            context = logged_event.payload["resource_context"]
            self.assertEqual(context["resource_type"], "RoleAssignment")
            self.assertEqual(context["resource_id"], str(role_uuid))

    def test_resource_context_returns_none_for_unsupported_events(self):
        """Test that events without resource context return None."""
        relation = create_relationship(("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p1", "member")

        # Create a replication event without org_id or resource identifiers
        event = ReplicationEvent(
            add=[relation],
            remove=[],
            event_type=ReplicationEventType.ADD_PRINCIPALS_TO_GROUP,
            info={},  # Empty info
            partition_key=PartitionKey.byEnvironment(),
        )

        # Call resource_context directly to verify it returns None
        context = event.resource_context()
        self.assertIsNone(context)

    def test_resource_context_raises_error_when_org_id_missing(self):
        """Test that events without org_id raise ValueError for resource_context."""
        relation = create_relationship(("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p1", "member")
        group_uuid = uuid4()

        # Create event with group_uuid but missing org_id
        event = ReplicationEvent(
            add=[relation],
            remove=[],
            event_type=ReplicationEventType.CREATE_GROUP,
            info={"group_uuid": group_uuid},  # Missing org_id
            partition_key=PartitionKey.byEnvironment(),
        )

        # Verify resource_context raises ValueError when org_id is missing
        with self.assertRaises(ValueError) as context_manager:
            event.resource_context()

        self.assertIn("Missing required org_id", str(context_manager.exception))

    def test_resource_context_raises_error_when_org_id_empty(self):
        """Test that events with empty org_id raise ValueError for resource_context."""
        relation = create_relationship(("rbac", "group"), "g1", ("rbac", "principal"), "localhost/p1", "member")
        group_uuid = uuid4()

        # Create event with group_uuid but empty org_id
        event = ReplicationEvent(
            add=[relation],
            remove=[],
            event_type=ReplicationEventType.CREATE_GROUP,
            info={"group_uuid": group_uuid, "org_id": ""},  # Empty org_id
            partition_key=PartitionKey.byEnvironment(),
        )

        # Verify resource_context raises ValueError when org_id is empty
        with self.assertRaises(ValueError) as context_manager:
            event.resource_context()

        self.assertIn("Missing required org_id", str(context_manager.exception))

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


class OutboxReplicatorPrometheusTest(TestCase):
    """Test OutboxReplicator Prometheus Metrics."""

    def setUp(self):
        """Set up."""
        super().setUp()
        self.log = OutboxWAL()
        self.replicator = OutboxReplicator(self.log)

    def test_replicate_sends_event_to_log_as_json(self):
        """Test replicate uses partition key from settings.ENV_NAME."""
        before = REGISTRY.get_sample_value("relations_replication_event_total")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
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

        self.assertEqual(len(callbacks), 1)

        after = REGISTRY.get_sample_value("relations_replication_event_total")
        self.assertEqual(1, after - before)
