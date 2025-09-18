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

"""Tests for RBAC Kafka consumer."""

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

# Ensure the rbac module can be found when running in different environments
# This MUST be done before any rbac imports
if "/var/workdir" in str(Path(__file__).parent):
    # Running in container environment, add parent directory to path
    sys.path.insert(0, "/var/workdir")
else:
    # Running in local environment
    project_root = Path(__file__).parent.parent.parent
    rbac_source_dir = str(project_root / "rbac")

    # Only add the rbac source directory if it's not already in the path
    if rbac_source_dir not in sys.path:
        sys.path.insert(0, rbac_source_dir)

    # Also ensure the project root is early in sys.path for rbac package imports
    if str(project_root) not in sys.path:
        sys.path.insert(1, str(project_root))

from core.kafka_consumer import (
    DebeziumMessage,
    MessageValidator,
    RBACKafkaConsumer,
    ReplicationMessage,
    RetryConfig,
)
from django.test import TestCase
from django.test.utils import override_settings
from kafka.errors import KafkaError


class MessageValidatorTests(TestCase):
    """Tests for MessageValidator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.validator = MessageValidator()

    def test_validate_parsed_message_valid(self):
        """Test validation of valid parsed message."""
        message = {
            "aggregatetype": "relations",
            "aggregateid": "test-id-123",
            "type": "create_group",
            "payload": {"relations_to_add": [], "relations_to_remove": []},
        }

        self.assertTrue(self.validator.validate_parsed_message(message))

    def test_validate_parsed_message_missing_field(self):
        """Test validation fails when required field is missing."""
        message = {
            "aggregatetype": "relations",
            "aggregateid": "test-id-123",
            # Missing "type" field
            "payload": {},
        }

        self.assertFalse(self.validator.validate_parsed_message(message))

    def test_validate_parsed_message_invalid_aggregatetype(self):
        """Test validation fails with invalid aggregatetype."""
        message = {
            "aggregatetype": "invalid_type",
            "aggregateid": "test-id-123",
            "type": "create_group",
            "payload": {},
        }

        self.assertFalse(self.validator.validate_parsed_message(message))

    def test_validate_parsed_message_empty_aggregateid(self):
        """Test validation fails with empty aggregateid."""
        message = {
            "aggregatetype": "relations",
            "aggregateid": "",
            "type": "create_group",
            "payload": {},
        }

        self.assertFalse(self.validator.validate_parsed_message(message))

    def test_validate_parsed_message_empty_event_type(self):
        """Test validation fails with empty event type."""
        message = {
            "aggregatetype": "relations",
            "aggregateid": "test-id-123",
            "type": "",
            "payload": {},
        }

        self.assertFalse(self.validator.validate_parsed_message(message))

    def test_validate_parsed_message_invalid_payload_type(self):
        """Test validation fails with non-dict payload."""
        message = {
            "aggregatetype": "relations",
            "aggregateid": "test-id-123",
            "type": "create_group",
            "payload": "invalid_payload",
        }

        self.assertFalse(self.validator.validate_parsed_message(message))

    def test_validate_replication_message_valid(self):
        """Test validation of valid replication message."""
        payload = {
            "relations_to_add": [
                {
                    "resource": {"type": "rbac", "id": "group1"},
                    "subject": {"type": "rbac", "id": "user1"},
                    "relation": "member",
                }
            ],
            "relations_to_remove": [],
        }

        self.assertTrue(self.validator.validate_replication_message(payload))

    def test_validate_replication_message_missing_field(self):
        """Test validation fails when required field is missing."""
        payload = {
            "relations_to_add": []
            # Missing "relations_to_remove"
        }

        self.assertFalse(self.validator.validate_replication_message(payload))

    def test_validate_replication_message_invalid_type(self):
        """Test validation fails with invalid field types."""
        payload = {"relations_to_add": "not_a_list", "relations_to_remove": []}

        self.assertFalse(self.validator.validate_replication_message(payload))

    def test_validate_replication_message_empty_relations(self):
        """Test validation fails when both relations lists are empty."""
        payload = {"relations_to_add": [], "relations_to_remove": []}

        self.assertFalse(self.validator.validate_replication_message(payload))

    def test_validate_replication_message_invalid_relation_structure(self):
        """Test validation fails with invalid relation structure."""
        payload = {
            "relations_to_add": [
                {
                    "resource": {"type": "rbac", "id": "group1"},
                    # Missing "subject" field
                    "relation": "member",
                }
            ],
            "relations_to_remove": [],
        }

        self.assertFalse(self.validator.validate_replication_message(payload))


class DebeziumMessageTests(TestCase):
    """Tests for DebeziumMessage class."""

    def test_from_kafka_message(self):
        """Test creating DebeziumMessage from Kafka message."""
        message_value = {
            "aggregatetype": "relations",
            "aggregateid": "test-id-123",
            "type": "create_group",
            "payload": {"test": "data"},
        }

        msg = DebeziumMessage.from_kafka_message(message_value)

        self.assertEqual(msg.aggregatetype, "relations")
        self.assertEqual(msg.aggregateid, "test-id-123")
        self.assertEqual(msg.event_type, "create_group")
        self.assertEqual(msg.payload, {"test": "data"})

    def test_from_kafka_message_missing_fields(self):
        """Test creating DebeziumMessage with missing fields."""
        message_value = {}

        msg = DebeziumMessage.from_kafka_message(message_value)

        self.assertEqual(msg.aggregatetype, "")
        self.assertEqual(msg.aggregateid, "")
        self.assertEqual(msg.event_type, "")
        self.assertEqual(msg.payload, {})


class ReplicationMessageTests(TestCase):
    """Tests for ReplicationMessage class."""

    def test_from_payload(self):
        """Test creating ReplicationMessage from payload."""
        payload = {
            "relations_to_add": [{"test": "add"}],
            "relations_to_remove": [{"test": "remove"}],
        }

        msg = ReplicationMessage.from_payload(payload)

        self.assertEqual(msg.relations_to_add, [{"test": "add"}])
        self.assertEqual(msg.relations_to_remove, [{"test": "remove"}])

    def test_from_payload_missing_fields(self):
        """Test creating ReplicationMessage with missing fields."""
        payload = {}

        msg = ReplicationMessage.from_payload(payload)

        self.assertEqual(msg.relations_to_add, [])
        self.assertEqual(msg.relations_to_remove, [])


class DebeziumMessageParsingTests(TestCase):
    """Tests for Debezium message parsing functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.liveness_file = Path(self.temp_dir) / "kubernetes-liveness"
        self.readiness_file = Path(self.temp_dir) / "kubernetes-readiness"

    @override_settings(KAFKA_ENABLED=True, RBAC_KAFKA_CONSUMER_TOPIC="test-topic")
    @patch("core.kafka_consumer.Path")
    def test_parse_standard_debezium_message_with_string_payload(self, mock_path):
        """Test parsing standard Debezium message with JSON string payload."""
        mock_path.return_value = self.liveness_file
        consumer = RBACKafkaConsumer()

        # Standard Debezium message format as provided in the user's question
        debezium_message = {
            "schema": {
                "type": "string",
                "optional": False,
                "name": "io.debezium.data.Json",
                "version": 1,
            },
            "payload": (
                '{"relations_to_add": [{"subject": {"subject": {"id": "09e360f0-ba13-48e2-a25a-76224b1f1717", '
                '"type": {"name": "group", "namespace": "rbac"}}, "relation": "member"}, "relation": "subject", '
                '"resource": {"id": "f2c095b1-b02d-4cf7-a71f-4dc06de0d9e1", "type": {"name": "role_binding", '
                '"namespace": "rbac"}}}], "relations_to_remove": [{"subject": {"subject": {"id": '
                '"09e360f0-ba13-48e2-a25a-76224b1f1717", "type": {"name": "group", "namespace": "rbac"}}, '
                '"relation": "member"}, "relation": "subject", "resource": {"id": '
                '"f2c095b1-b02d-4cf7-a71f-4dc06de0d9e1", "type": {"name": "role_binding", "namespace": "rbac"}}}]}'
            ),
        }

        result = consumer._parse_debezium_message(debezium_message)

        self.assertIsNotNone(result)
        self.assertEqual(result["aggregatetype"], "relations")
        self.assertEqual(result["aggregateid"], "debezium-message")
        self.assertEqual(result["type"], "relation_change")

        # Verify the payload was correctly parsed
        payload = result["payload"]
        self.assertIn("relations_to_add", payload)
        self.assertIn("relations_to_remove", payload)
        self.assertEqual(len(payload["relations_to_add"]), 1)
        self.assertEqual(len(payload["relations_to_remove"]), 1)

    @override_settings(KAFKA_ENABLED=True, RBAC_KAFKA_CONSUMER_TOPIC="test-topic")
    @patch("core.kafka_consumer.Path")
    def test_parse_debezium_message_with_dict_payload(self, mock_path):
        """Test parsing Debezium message with dict payload (already parsed)."""
        mock_path.return_value = self.liveness_file
        consumer = RBACKafkaConsumer()

        debezium_message = {
            "schema": {
                "type": "string",
                "optional": False,
                "name": "io.debezium.data.Json",
                "version": 1,
            },
            "payload": {
                "relations_to_add": [
                    {
                        "subject": {"id": "user-123", "type": "user"},
                        "relation": "member",
                        "resource": {"id": "group-456", "type": "group"},
                    }
                ],
                "relations_to_remove": [],
            },
        }

        result = consumer._parse_debezium_message(debezium_message)

        self.assertIsNotNone(result)
        self.assertEqual(result["aggregatetype"], "relations")
        self.assertEqual(result["aggregateid"], "debezium-message")
        self.assertEqual(result["type"], "relation_change")
        self.assertEqual(len(result["payload"]["relations_to_add"]), 1)
        self.assertEqual(len(result["payload"]["relations_to_remove"]), 0)

    @override_settings(KAFKA_ENABLED=True, RBAC_KAFKA_CONSUMER_TOPIC="test-topic")
    @patch("core.kafka_consumer.Path")
    def test_parse_non_debezium_message_rejected(self, mock_path):
        """Test that non-Debezium messages are rejected."""
        mock_path.return_value = self.liveness_file
        consumer = RBACKafkaConsumer()

        # Legacy format should now be rejected
        legacy_message = {
            "aggregatetype": "relations",
            "aggregateid": "group-123",
            "type": "create_group",
            "payload": {"relations_to_add": [], "relations_to_remove": []},
        }

        result = consumer._parse_debezium_message(legacy_message)
        self.assertIsNone(result)  # Should be rejected

    @override_settings(KAFKA_ENABLED=True, RBAC_KAFKA_CONSUMER_TOPIC="test-topic")
    @patch("core.kafka_consumer.Path")
    def test_parse_invalid_debezium_message(self, mock_path):
        """Test parsing invalid Debezium message."""
        mock_path.return_value = self.liveness_file
        consumer = RBACKafkaConsumer()

        # Test message without schema field
        message_no_schema = {"payload": '{"relations_to_add": [], "relations_to_remove": []}'}
        result = consumer._parse_debezium_message(message_no_schema)
        self.assertIsNone(result)

        # Test message without payload field
        message_no_payload = {"schema": {"type": "string"}}
        result = consumer._parse_debezium_message(message_no_payload)
        self.assertIsNone(result)

        # Test message with neither schema nor payload
        invalid_message = {"some_field": "value"}
        result = consumer._parse_debezium_message(invalid_message)
        self.assertIsNone(result)

    @override_settings(KAFKA_ENABLED=True, RBAC_KAFKA_CONSUMER_TOPIC="test-topic")
    @patch("core.kafka_consumer.Path")
    def test_parse_debezium_message_invalid_json_payload(self, mock_path):
        """Test parsing Debezium message with invalid JSON in payload."""
        mock_path.return_value = self.liveness_file
        consumer = RBACKafkaConsumer()

        debezium_message = {"schema": {"type": "string"}, "payload": "invalid json {"}

        result = consumer._parse_debezium_message(debezium_message)
        self.assertIsNone(result)

    @override_settings(KAFKA_ENABLED=True, RBAC_KAFKA_CONSUMER_TOPIC="test-topic")
    @patch("core.kafka_consumer.Path")
    def test_parse_debezium_message_unknown_payload_structure(self, mock_path):
        """Test parsing Debezium message with unknown payload structure."""
        mock_path.return_value = self.liveness_file
        consumer = RBACKafkaConsumer()

        debezium_message = {
            "schema": {"type": "string"},
            "payload": '{"unknown_field": "value"}',
        }

        result = consumer._parse_debezium_message(debezium_message)
        self.assertIsNone(result)


class RBACKafkaConsumerTests(TestCase):
    """Tests for RBACKafkaConsumer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.liveness_file = Path(self.temp_dir) / "kubernetes-liveness"
        self.readiness_file = Path(self.temp_dir) / "kubernetes-readiness"

    @override_settings(KAFKA_ENABLED=True, RBAC_KAFKA_CONSUMER_TOPIC="test-topic")
    @patch("core.kafka_consumer.Path")
    def test_init(self, mock_path):
        """Test consumer initialization."""
        mock_path.return_value = self.liveness_file

        consumer = RBACKafkaConsumer(topic="custom-topic", health_check_interval=10)

        self.assertEqual(consumer.topic, "custom-topic")
        self.assertIsNone(consumer.consumer)
        self.assertIsInstance(consumer.validator, MessageValidator)
        self.assertFalse(consumer.is_healthy)
        self.assertFalse(consumer.is_consuming)
        self.assertEqual(consumer.health_check_interval, 10)
        self.assertIsNone(consumer.health_check_thread)

    @override_settings(KAFKA_ENABLED=False)
    def test_create_consumer_kafka_disabled(self):
        """Test consumer creation fails when Kafka is disabled."""
        consumer = RBACKafkaConsumer()

        with self.assertRaises(RuntimeError) as cm:
            consumer._create_consumer()

        self.assertIn("Kafka must be enabled", str(cm.exception))

    @override_settings(KAFKA_ENABLED=True, RBAC_KAFKA_CONSUMER_TOPIC=None)
    def test_create_consumer_no_topic(self):
        """Test consumer creation fails when no topic is configured."""
        consumer = RBACKafkaConsumer(topic=None)

        with self.assertRaises(RuntimeError) as cm:
            consumer._create_consumer()

        self.assertIn("Consumer topic must be configured", str(cm.exception))

    @override_settings(
        KAFKA_ENABLED=True,
        RBAC_KAFKA_CONSUMER_TOPIC="test-topic",
        KAFKA_AUTH=None,
        KAFKA_SERVERS=["localhost:9092"],
    )
    @patch("core.kafka_consumer.KafkaConsumer")
    def test_create_consumer_success(self, mock_kafka_consumer):
        """Test successful consumer creation."""
        mock_consumer_instance = Mock()
        mock_kafka_consumer.return_value = mock_consumer_instance

        consumer = RBACKafkaConsumer()
        result = consumer._create_consumer()

        self.assertEqual(result, mock_consumer_instance)
        mock_kafka_consumer.assert_called_once()

    @patch("core.kafka_consumer.Path")
    def test_update_health_status_healthy(self, mock_path):
        """Test updating health status to healthy."""
        mock_liveness = Mock()
        mock_readiness = Mock()
        mock_path.side_effect = [mock_liveness, mock_readiness]

        consumer = RBACKafkaConsumer()
        consumer._update_health_status(True)

        self.assertTrue(consumer.is_healthy)
        mock_liveness.touch.assert_called_once()
        mock_readiness.touch.assert_called_once()

    @patch("core.kafka_consumer.Path")
    def test_update_health_status_unhealthy(self, mock_path):
        """Test updating health status to unhealthy."""
        mock_liveness = Mock()
        mock_readiness = Mock()
        mock_readiness.exists.return_value = True
        mock_path.side_effect = [mock_liveness, mock_readiness]

        consumer = RBACKafkaConsumer()
        consumer._update_health_status(False)

        self.assertFalse(consumer.is_healthy)
        mock_readiness.unlink.assert_called_once()

    def test_process_debezium_message_valid_relations(self):
        """Test processing valid relations message."""
        consumer = RBACKafkaConsumer()

        message_value = {
            "aggregatetype": "relations",
            "aggregateid": "test-id-123",
            "type": "create_group",
            "payload": {
                "relations_to_add": [
                    {
                        "resource": {"type": "rbac", "id": "group1"},
                        "subject": {"type": "rbac", "id": "user1"},
                        "relation": "member",
                    }
                ],
                "relations_to_remove": [],
            },
        }

        with patch.object(consumer, "_process_relations_message", return_value=True) as mock_process:
            result = consumer._process_debezium_message(message_value)

            self.assertTrue(result)
            mock_process.assert_called_once()

    def test_process_debezium_message_workspace_unknown(self):
        """Test processing workspace message is treated as unknown type."""
        consumer = RBACKafkaConsumer()

        message_value = {
            "aggregatetype": "workspace",
            "aggregateid": "workspace-123",
            "type": "create_workspace",
            "payload": {
                "org_id": "12345",
                "workspace": {"id": "workspace-123", "name": "Test Workspace"},
            },
        }

        result = consumer._process_debezium_message(message_value)

        self.assertFalse(result)  # Should return False for unknown aggregate type

    def test_process_debezium_message_invalid(self):
        """Test processing invalid message."""
        consumer = RBACKafkaConsumer()

        message_value = {
            "aggregatetype": "invalid",
            # Missing required fields
        }

        result = consumer._process_debezium_message(message_value)

        self.assertFalse(result)

    def test_process_relations_message_success(self):
        """Test successful relations message processing."""
        consumer = RBACKafkaConsumer()

        debezium_msg = DebeziumMessage(
            aggregatetype="relations",
            aggregateid="test-id-123",
            event_type="create_group",
            payload={
                "relations_to_add": [
                    {
                        "resource": {"type": "rbac", "id": "group1"},
                        "subject": {"type": "rbac", "id": "user1"},
                        "relation": "member",
                    }
                ],
                "relations_to_remove": [],
            },
        )

        result = consumer._process_relations_message(debezium_msg)

        self.assertTrue(result)

    def test_process_relations_message_invalid_payload(self):
        """Test relations message processing with invalid payload."""
        consumer = RBACKafkaConsumer()

        debezium_msg = DebeziumMessage(
            aggregatetype="relations",
            aggregateid="test-id-123",
            event_type="create_group",
            payload={
                "relations_to_add": [],
                "relations_to_remove": [],
            },  # Both empty - invalid
        )

        result = consumer._process_relations_message(debezium_msg)

        self.assertFalse(result)

    @override_settings(
        KAFKA_ENABLED=True,
        RBAC_KAFKA_CONSUMER_TOPIC="test-topic",
        KAFKA_AUTH=None,
        KAFKA_SERVERS=["localhost:9092"],
    )
    @patch(
        "core.kafka_consumer.MessageValidator.validate_parsed_message",
        return_value=True,
    )
    @patch(
        "core.kafka_consumer.MessageValidator.validate_replication_message",
        return_value=True,
    )
    @patch("core.kafka_consumer.KafkaConsumer")
    @patch("core.kafka_consumer.Path")
    def test_start_consuming_success(
        self,
        mock_path,
        mock_kafka_consumer,
        mock_validate_replication,
        mock_validate_parsed,
    ):
        """Test successful message consumption."""
        # Mock Kafka consumer
        mock_consumer_instance = Mock()
        mock_message = Mock()
        # Create proper Debezium message format
        message_dict = {
            "schema": {"type": "string"},
            "payload": {
                "relations_to_add": [
                    {
                        "resource": {"type": "rbac", "id": "group1"},
                        "subject": {"type": "rbac", "id": "user1"},
                        "relation": "member",
                    }
                ],
                "relations_to_remove": [],
            },
        }
        mock_message.value = json.dumps(message_dict).encode("utf-8")
        mock_message.partition = 0
        mock_message.offset = 123
        mock_consumer_instance.__iter__ = Mock(return_value=iter([mock_message]))
        mock_kafka_consumer.return_value = mock_consumer_instance

        # Mock health files
        mock_liveness = Mock()
        mock_readiness = Mock()
        mock_path.side_effect = [mock_liveness, mock_readiness]

        consumer = RBACKafkaConsumer()

        # Mock the message processing to avoid infinite loop
        with patch.object(consumer, "_process_debezium_message", return_value=True) as mock_process:
            # Use a side effect to break the loop after one iteration
            def side_effect(*args):
                consumer.stop_consuming()
                return True

            mock_process.side_effect = side_effect

            consumer.start_consuming()

            mock_process.assert_called_once()

    @override_settings(KAFKA_ENABLED=True)
    @patch("core.kafka_consumer.KafkaConsumer")
    def test_start_consuming_kafka_error(self, mock_kafka_consumer):
        """Test handling Kafka errors during consumption."""
        mock_kafka_consumer.side_effect = KafkaError("Connection failed")

        consumer = RBACKafkaConsumer(topic="test-topic")

        with self.assertRaises(KafkaError):
            consumer.start_consuming()

    @patch("core.kafka_consumer.Path")
    def test_stop_consuming(self, mock_path):
        """Test stopping consumer."""
        mock_consumer = Mock()
        mock_liveness = Mock()
        mock_readiness = Mock()
        mock_readiness.exists.return_value = True
        mock_path.side_effect = [mock_liveness, mock_readiness]

        consumer = RBACKafkaConsumer()
        consumer.consumer = mock_consumer

        consumer.stop_consuming()

        mock_consumer.close.assert_called_once()
        self.assertIsNone(consumer.consumer)
        self.assertFalse(consumer.is_healthy)

    @patch("core.kafka_consumer.Path")
    def test_is_ready(self, mock_path):
        """Test readiness check."""
        mock_readiness = Mock()
        mock_readiness.exists.return_value = True
        mock_path.return_value = mock_readiness

        consumer = RBACKafkaConsumer()

        result = consumer.is_ready()

        self.assertTrue(result)
        mock_readiness.exists.assert_called_once()

    @patch("core.kafka_consumer.Path")
    def test_is_alive(self, mock_path):
        """Test liveness check."""
        mock_liveness = Mock()
        mock_liveness.exists.return_value = True
        mock_path.return_value = mock_liveness

        consumer = RBACKafkaConsumer()

        result = consumer.is_alive()

        self.assertTrue(result)
        mock_liveness.exists.assert_called_once()

    @patch("core.kafka_consumer.Path")
    @patch("core.kafka_consumer.threading.Event")
    @patch("core.kafka_consumer.threading.Thread")
    def test_health_check_thread_management(self, mock_thread_class, mock_event_class, mock_path):
        """Test health check thread start and stop."""
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread
        mock_event = Mock()
        mock_event_class.return_value = mock_event
        mock_liveness = Mock()
        mock_readiness = Mock()
        mock_path.side_effect = [mock_liveness, mock_readiness]

        consumer = RBACKafkaConsumer(health_check_interval=5)

        # Test starting health check thread
        consumer._start_health_check_thread()

        mock_thread_class.assert_called_once()
        mock_thread.start.assert_called_once()
        self.assertIsNotNone(consumer.health_check_thread)

        # Test stopping health check thread
        consumer._stop_health_check_thread()

        mock_event.set.assert_called_once()
        mock_thread.join.assert_called_once_with(timeout=5)
        self.assertIsNone(consumer.health_check_thread)

    @patch("core.kafka_consumer.Path")
    @patch("core.kafka_consumer.time.time")
    def test_update_health_status_with_activity_tracking(self, mock_time, mock_path):
        """Test health status update includes activity tracking."""
        mock_time.return_value = 1234567890
        mock_liveness = Mock()
        mock_readiness = Mock()
        mock_path.side_effect = [mock_liveness, mock_readiness]

        consumer = RBACKafkaConsumer()

        consumer._update_health_status(True)

        self.assertTrue(consumer.is_healthy)
        self.assertEqual(consumer.last_activity, 1234567890)
        mock_liveness.touch.assert_called_once()
        mock_readiness.touch.assert_called_once()


class RetryConfigTests(TestCase):
    """Tests for RetryConfig class."""

    def test_default_config(self):
        """Test default retry configuration."""
        config = RetryConfig()

        self.assertEqual(config.initial_delay, 1.0)
        self.assertEqual(config.max_delay, 300.0)
        self.assertEqual(config.backoff_multiplier, 2.0)
        self.assertEqual(config.jitter_factor, 0.1)

    def test_custom_config(self):
        """Test custom retry configuration."""
        config = RetryConfig(initial_delay=0.5, max_delay=60.0, backoff_multiplier=1.5, jitter_factor=0.2)

        self.assertEqual(config.initial_delay, 0.5)
        self.assertEqual(config.max_delay, 60.0)
        self.assertEqual(config.backoff_multiplier, 1.5)
        self.assertEqual(config.jitter_factor, 0.2)

    @patch("random.random")
    def test_calculate_delay_exponential_backoff(self, mock_random):
        """Test delay calculation with exponential backoff."""
        mock_random.return_value = 0.5  # Fixed jitter for testing
        config = RetryConfig(
            initial_delay=1.0,
            max_delay=100.0,
            backoff_multiplier=2.0,
            jitter_factor=0.1,
        )

        # Test first few attempts
        delay_0 = config.calculate_delay(0)  # 1.0 * (2^0) + jitter = 1.0 + 0.05 = 1.05
        delay_1 = config.calculate_delay(1)  # 1.0 * (2^1) + jitter = 2.0 + 0.1 = 2.1
        delay_2 = config.calculate_delay(2)  # 1.0 * (2^2) + jitter = 4.0 + 0.2 = 4.2

        self.assertAlmostEqual(delay_0, 1.05, places=2)
        self.assertAlmostEqual(delay_1, 2.1, places=2)
        self.assertAlmostEqual(delay_2, 4.2, places=2)

    @patch("random.random")
    def test_calculate_delay_max_limit(self, mock_random):
        """Test delay calculation respects max limit."""
        mock_random.return_value = 0.0  # No jitter for simpler testing
        config = RetryConfig(initial_delay=1.0, max_delay=10.0, backoff_multiplier=2.0, jitter_factor=0.1)

        # High attempt number should be capped at max_delay
        delay = config.calculate_delay(10)  # Would be 1024 without cap

        self.assertLessEqual(delay, 10.0)

    def test_calculate_delay_with_jitter(self):
        """Test that jitter adds randomness to delays."""
        config = RetryConfig(initial_delay=1.0, max_delay=100.0, jitter_factor=0.1)

        # Calculate delays multiple times to check they're different due to jitter
        delays = [config.calculate_delay(1) for _ in range(10)]

        # All delays should be around 2.0 but slightly different
        for delay in delays:
            self.assertGreater(delay, 2.0)
            self.assertLess(delay, 2.3)  # 2.0 + max jitter (0.2)

        # Check that we got some variation
        self.assertGreater(len(set(delays)), 5)  # Should have at least some different values


class SelectiveRetryLogicTests(TestCase):
    """Tests for the new selective retry logic."""

    def setUp(self):
        """Set up test fixtures."""
        self.consumer = RBACKafkaConsumer()

    def test_should_retry_exception_json_errors(self):
        """Test that JSON errors are not retried."""
        json_error = json.JSONDecodeError("test", "doc", 0)
        unicode_error = UnicodeDecodeError("utf-8", b"", 0, 1, "test")

        self.assertFalse(self.consumer._should_retry_exception(json_error))
        self.assertFalse(self.consumer._should_retry_exception(unicode_error))

    def test_should_retry_exception_network_errors(self):
        """Test that network errors are retried."""
        connection_error = ConnectionError("Connection failed")
        timeout_error = TimeoutError("Request timed out")
        os_error = OSError("Network unreachable")

        self.assertTrue(self.consumer._should_retry_exception(connection_error))
        self.assertTrue(self.consumer._should_retry_exception(timeout_error))
        self.assertTrue(self.consumer._should_retry_exception(os_error))

    def test_should_retry_exception_validation_errors(self):
        """Test that validation errors are not retried."""
        validation_error = ValueError("validation failed")
        generic_value_error = ValueError("some other error")

        self.assertFalse(self.consumer._should_retry_exception(validation_error))
        self.assertTrue(self.consumer._should_retry_exception(generic_value_error))  # Only validation-specific ones

    @patch("core.kafka_consumer.logger")
    def test_process_message_with_retry_permanent_error(self, mock_logger):
        """Test that permanent errors are not retried."""
        # Use proper Debezium message format
        message_value = {
            "schema": {"type": "string"},
            "payload": {"relations_to_add": [], "relations_to_remove": []},
        }

        # Mock _process_debezium_message to raise a JSON error
        with patch.object(
            self.consumer,
            "_process_debezium_message",
            side_effect=json.JSONDecodeError("test", "doc", 0),
        ):
            result = self.consumer._process_message_with_retry(message_value, 1234, 0)

        self.assertFalse(result)
        # Should log as permanent error, not retry
        mock_logger.error.assert_called()
        self.assertIn("Permanent JSON decode error", mock_logger.error.call_args[0][0])

    @patch("core.kafka_consumer.logger")
    def test_process_message_with_retry_processing_failure(self, mock_logger):
        """Test that processing failures are not retried."""
        # Use proper Debezium message format
        message_value = {
            "schema": {"type": "string"},
            "payload": {"relations_to_add": [], "relations_to_remove": []},
        }

        # Mock _process_debezium_message to return False (processing failed)
        with patch.object(self.consumer, "_process_debezium_message", return_value=False):
            result = self.consumer._process_message_with_retry(message_value, 1234, 0)

        self.assertFalse(result)
        # Should log as processing failed, not retry
        mock_logger.error.assert_called()
        self.assertIn("Message processing failed", mock_logger.error.call_args[0][0])


class HealthCheckTests(TestCase):
    """Tests for health check functionality."""

    @override_settings(RBAC_KAFKA_CONSUMER_TOPIC="test-topic")
    def setUp(self):
        """Set up test fixtures."""
        self.consumer = RBACKafkaConsumer()

    @patch("core.kafka_consumer.threading.Thread")
    @patch("core.kafka_consumer.Path")
    def test_background_health_check_thread(self, mock_path, mock_thread):
        """Test that background health check thread is started."""
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance

        self.consumer._start_health_check_thread()

        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()

    @patch.object(Path, "touch")
    def test_health_check_during_idle(self, mock_touch):
        """Test health check behavior during idle periods."""
        # Mock the health check logic
        self.consumer.is_consuming = True
        self.consumer.consumer = Mock()

        # Test that health check can run without active message processing
        self.consumer._update_health_status(True)

        # Verify health files are managed correctly - touch should be called twice (liveness + readiness)
        self.assertEqual(mock_touch.call_count, 2)


class RBACKafkaConsumerRetryTests(TestCase):
    """Tests for retry functionality in RBACKafkaConsumer."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.retry_config = RetryConfig(initial_delay=0.01, max_delay=0.1)  # Fast retries for testing

    @patch("core.kafka_consumer.Path")
    @patch("core.kafka_consumer.time.sleep")
    def test_process_message_with_retry_success_after_failures(self, mock_sleep, mock_path):
        """Test message processing succeeds after initial failures."""
        mock_liveness = Mock()
        mock_readiness = Mock()
        mock_path.side_effect = [mock_liveness, mock_readiness]

        consumer = RBACKafkaConsumer(retry_config=self.retry_config)

        # Mock _process_debezium_message to fail twice then succeed
        call_count = 0

        def mock_process_side_effect(*args):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                # Raise an exception that should be retried (network error)
                raise ConnectionError("Temporary network error")
            return True

        # Create a proper Debezium message format
        test_message = {
            "schema": {"type": "string"},
            "payload": {"relations_to_add": [], "relations_to_remove": []},
        }

        # Patch the method before calling
        original_method = consumer._process_debezium_message
        consumer._process_debezium_message = Mock(side_effect=mock_process_side_effect)

        try:
            result = consumer._process_message_with_retry(test_message, 123, 0)
        finally:
            # Restore original method
            consumer._process_debezium_message = original_method

        self.assertTrue(result)
        self.assertEqual(call_count, 3)  # Failed twice, succeeded on third attempt

    @patch("core.kafka_consumer.Path")
    @patch("core.kafka_consumer.time.sleep")
    def test_process_message_with_retry_json_error_skipped(self, mock_sleep, mock_path):
        """Test that JSON decode errors are not retried."""
        mock_liveness = Mock()
        mock_readiness = Mock()
        mock_path.side_effect = [mock_liveness, mock_readiness]

        consumer = RBACKafkaConsumer(retry_config=self.retry_config)

        # Mock _process_debezium_message to raise JSON decode error
        with patch.object(
            consumer,
            "_process_debezium_message",
            side_effect=json.JSONDecodeError("Invalid JSON", "", 0),
        ):
            result = consumer._process_message_with_retry({"test": "message"}, 123, 0)

        self.assertFalse(result)
        # Should not have slept (no retries for JSON errors)
        mock_sleep.assert_not_called()

    @patch("core.kafka_consumer.Path")
    def test_consumer_init_with_retry_config(self, mock_path):
        """Test consumer initialization with custom retry config."""
        mock_liveness = Mock()
        mock_readiness = Mock()
        mock_path.side_effect = [mock_liveness, mock_readiness]

        custom_config = RetryConfig(initial_delay=2.0, max_delay=60.0)
        consumer = RBACKafkaConsumer(retry_config=custom_config)

        self.assertEqual(consumer.retry_config.initial_delay, 2.0)
        self.assertEqual(consumer.retry_config.max_delay, 60.0)

    @patch("core.kafka_consumer.Path")
    def test_consumer_init_with_default_retry_config(self, mock_path):
        """Test consumer initialization with default retry config."""
        mock_liveness = Mock()
        mock_readiness = Mock()
        mock_path.side_effect = [mock_liveness, mock_readiness]

        consumer = RBACKafkaConsumer()

        self.assertEqual(consumer.retry_config.initial_delay, 1.0)
        self.assertEqual(consumer.retry_config.max_delay, 300.0)
