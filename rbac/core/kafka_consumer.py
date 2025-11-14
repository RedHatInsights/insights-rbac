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

"""RBAC Kafka consumer for processing Debezium and replication messages."""

import json
import logging
import random
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from django.conf import settings
from google.protobuf import json_format
from kafka import KafkaConsumer, TopicPartition
from kafka.consumer.subscription_state import ConsumerRebalanceListener
from kafka.errors import KafkaError
from kafka.structs import OffsetAndMetadata
from kessel.relations.v1beta1 import common_pb2
from management.relation_replicator.relations_api_replicator import (
    RelationsApiReplicator,
)
from prometheus_client import Counter, Histogram

from api.models import Tenant

relations_api_replication = RelationsApiReplicator()
logger = logging.getLogger("rbac.core.kafka_consumer")

# Metrics
messages_processed_total = Counter(
    "rbac_kafka_consumer_messages_processed_total",
    "Total number of messages processed",
    ["message_type", "status"],
)

message_processing_duration = Histogram(
    "rbac_kafka_consumer_message_processing_duration_seconds",
    "Time spent processing messages",
    ["message_type"],
)

validation_errors_total = Counter(
    "rbac_kafka_consumer_validation_errors_total",
    "Total number of validation errors",
    ["error_type"],
)

retry_attempts_total = Counter(
    "rbac_kafka_consumer_retry_attempts_total",
    "Total number of message retry attempts",
    ["retry_reason", "attempt_number"],
)

message_retry_duration = Histogram(
    "rbac_kafka_consumer_message_retry_duration_seconds",
    "Time spent retrying message processing",
    ["retry_reason"],
)


@dataclass
class RetryConfig:
    """Configuration for retry logic.

    Implements exponential backoff with the formula:
    backoff = min(backoff_factor * attempts * base_delay, max_backoff_seconds)
    """

    operation_max_retries: int = 10  # Max operation retry attempts (-1 = infinite)
    backoff_factor: int = 5  # Exponential backoff multiplier
    max_backoff_seconds: int = 30  # Maximum wait time between retries
    base_delay: float = 0.3  # Base delay in seconds (300ms)
    jitter_factor: float = 0.1  # Random jitter to avoid thundering herd

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt with exponential backoff and jitter.

        Formula: backoff = min(backoff_factor * attempts * base_delay, max_backoff_seconds)

        Example with defaults (backoff_factor=5, base_delay=0.3s, max=30s):
        - Attempt 1: 1.5s (5 * 1 * 0.3)
        - Attempt 2: 3.0s (5 * 2 * 0.3)
        - Attempt 3: 4.5s (5 * 3 * 0.3)
        - Attempt 10+: 30s (capped)
        """
        # Calculate exponential backoff: backoff_factor * (attempt+1) * base_delay
        # Note: attempt starts at 0, so we add 1 to get proper delay on first retry
        delay = self.backoff_factor * (attempt + 1) * self.base_delay
        delay = min(delay, self.max_backoff_seconds)

        # Add jitter to avoid thundering herd problem
        jitter = delay * self.jitter_factor * random.random()
        return delay + jitter


@dataclass
class CommitConfig:
    """Configuration for offset commit policy."""

    commit_modulo: int = 10  # Commit every N messages (batch commits)
    commit_on_rebalance: bool = True  # Commit offsets on rebalance
    commit_on_shutdown: bool = True  # Commit offsets on shutdown


@dataclass
class DebeziumMessage:
    """Represents a validated Debezium message."""

    aggregatetype: str
    aggregateid: str
    event_type: str
    payload: Dict[str, Any]

    @classmethod
    def from_kafka_message(cls, message_value: Dict[str, Any]) -> "DebeziumMessage":
        """Create DebeziumMessage from Kafka message value."""
        return cls(
            aggregatetype=message_value.get("aggregatetype", ""),
            aggregateid=message_value.get("aggregateid", ""),
            event_type=message_value.get("type", ""),
            payload=message_value.get("payload", {}),
        )


@dataclass
class ReplicationMessage:
    """Represents a validated replication message."""

    relations_to_add: List[Dict[str, Any]]
    relations_to_remove: List[Dict[str, Any]]

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "ReplicationMessage":
        """Create ReplicationMessage from payload."""
        return cls(
            relations_to_add=payload.get("relations_to_add", []),
            relations_to_remove=payload.get("relations_to_remove", []),
        )


class MessageValidator:
    """Validates Kafka messages."""

    REQUIRED_PARSED_MESSAGE_FIELDS = ["aggregatetype", "aggregateid", "type", "payload"]
    VALID_AGGREGATE_TYPES = ["relations"]

    @staticmethod
    def validate_parsed_message(message_value: Dict[str, Any]) -> bool:
        """Validate parsed message structure (after Debezium parsing)."""
        try:
            # Check required fields in the parsed message
            for field in MessageValidator.REQUIRED_PARSED_MESSAGE_FIELDS:
                if field not in message_value:
                    logger.error(f"Missing required field '{field}' in parsed message")
                    validation_errors_total.labels(error_type="missing_field").inc()
                    return False

            # Validate payload is a dict
            payload = message_value.get("payload")
            if not isinstance(payload, dict):
                logger.error("payload must be a dictionary")
                validation_errors_total.labels(error_type="invalid_payload_type").inc()
                return False

            return True

        except Exception as e:
            logger.error(f"Error validating parsed message: {e}")
            validation_errors_total.labels(error_type="validation_exception").inc()
            return False

    @staticmethod
    def validate_replication_message(payload: Dict[str, Any]) -> bool:
        """Validate replication message payload."""
        try:
            # Check that at least one of relations_to_add or relations_to_remove is present
            has_relations_to_add = "relations_to_add" in payload
            has_relations_to_remove = "relations_to_remove" in payload

            if not has_relations_to_add and not has_relations_to_remove:
                logger.error(
                    "Missing required field: at least one of 'relations_to_add' "
                    "or 'relations_to_remove' must be present"
                )
                validation_errors_total.labels(error_type="missing_relations_fields").inc()
                return False

            # Validate relations_to_add is a list if present
            relations_to_add = payload.get("relations_to_add", [])
            if has_relations_to_add and not isinstance(relations_to_add, list):
                logger.error("relations_to_add must be a list")
                validation_errors_total.labels(error_type="invalid_relations_to_add_type").inc()
                return False

            # Validate relations_to_remove is a list if present
            relations_to_remove = payload.get("relations_to_remove", [])
            if has_relations_to_remove and not isinstance(relations_to_remove, list):
                logger.error("relations_to_remove must be a list")
                validation_errors_total.labels(error_type="invalid_relations_to_remove_type").inc()
                return False

            # Validate that at least one list is not empty (meaningful message)
            if not relations_to_add and not relations_to_remove:
                logger.warning("Both relations_to_add and relations_to_remove are empty - this may indicate a bug")
                validation_errors_total.labels(error_type="empty_relations").inc()
                return False

            # Validate structure of relations
            all_relations = list(relations_to_add) + list(relations_to_remove)
            for relation in all_relations:
                if not isinstance(relation, dict):
                    logger.error("Each relation must be a dictionary")
                    validation_errors_total.labels(error_type="invalid_relation_type").inc()
                    return False

                # Basic relation structure validation
                if "resource" not in relation or "subject" not in relation:
                    logger.error("Each relation must have 'resource' and 'subject' fields")
                    validation_errors_total.labels(error_type="invalid_relation_structure").inc()
                    return False

            return True

        except Exception as e:
            logger.error(f"Error validating replication message: {e}")
            validation_errors_total.labels(error_type="replication_validation_exception").inc()
            return False


class ValidationError(Exception):
    """Raised when message validation fails permanently (non-retryable)."""

    pass


class RetryHelper:
    """Handles retry logic with exponential backoff for message processing.

    This class encapsulates all retry policy and logic, making it easy to test
    and maintain separately from the business logic.
    """

    def __init__(
        self,
        retry_config: RetryConfig,
        shutdown_event: threading.Event,
        error_handler=None,
    ):
        """Initialize the retry helper.

        Args:
            retry_config: Configuration for retry behavior
            shutdown_event: Event to signal shutdown (interrupts retries)
            error_handler: Optional callable(Exception) -> bool to short-circuit retries
        """
        self.retry_config = retry_config
        self.shutdown_event = shutdown_event
        self.error_handler = error_handler

    def run(self, fn, *args, **kwargs):
        """Execute a function with retry logic.

        Args:
            fn: The function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            The return value from the successful function execution

        Raises:
            The final exception if all retries are exhausted or shutdown occurs
        """
        attempt = 0
        start_time = time.time()

        while True:
            try:
                result = fn(*args, **kwargs)
                if attempt > 0:
                    total_duration = time.time() - start_time
                    logger.info(
                        f"Operation successful after {attempt + 1} attempts "
                        f"(total retry time: {total_duration:.2f}s)"
                    )
                    message_retry_duration.labels(retry_reason="processing_error").observe(total_duration)
                return result

            except Exception as e:
                # Check if error handler wants to short-circuit retry
                if not self._should_retry(e):
                    logger.warning(f"Error handler short-circuited retry: {e}. " f"Operation will be skipped.")
                    raise

                # Check if we've hit max retries (if configured)
                if self._exceeded_max_retries(attempt):
                    error_msg = f"Max operation retries ({self.retry_config.operation_max_retries}) " f"exceeded: {e}"
                    logger.error(error_msg)
                    raise RuntimeError(error_msg) from e

                # Determine error type for logging
                error_type = type(e).__name__
                retry_reason = self._classify_error(e)

                logger.warning(f"Error on attempt {attempt + 1}: {error_type}: {e}")

                # Record retry attempt
                retry_attempts_total.labels(
                    retry_reason=retry_reason,
                    attempt_number=min(attempt + 1, 10),  # Cap at 10 for cardinality
                ).inc()

                # Calculate delay and wait before retry
                delay = self.retry_config.calculate_delay(attempt)
                logger.info(f"Retrying in {delay:.2f}s (attempt {attempt + 1})")

                # Sleep with ability to interrupt for shutdown
                if self.shutdown_event.wait(delay):
                    logger.info("Retry interrupted by shutdown signal")
                    raise InterruptedError("Shutdown signal received during retry")

                attempt += 1

                # Log periodic status for long-running retries
                if attempt % 10 == 0:
                    elapsed = time.time() - start_time
                    logger.warning(f"Operation still retrying after {attempt} attempts " f"(elapsed: {elapsed:.2f}s)")

    def _should_retry(self, exception: Exception) -> bool:
        """Determine if an exception should trigger a retry.

        Args:
            exception: The exception to evaluate

        Returns:
            bool: True if should retry, False if should skip retry
        """
        # Allow custom error handler to short-circuit retry logic
        if self.error_handler and callable(self.error_handler):
            if self.error_handler(exception):
                return False

        # Retry on ALL exceptions - we want to ensure at-least-once delivery
        return True

    def _exceeded_max_retries(self, attempt: int) -> bool:
        """Check if max retries have been exceeded.

        Args:
            attempt: The current attempt number (0-indexed)

        Returns:
            bool: True if max retries exceeded
        """
        max_retries = self.retry_config.operation_max_retries
        return 0 <= max_retries <= attempt

    def _classify_error(self, exception: Exception) -> str:
        """Classify error type for metrics.

        Args:
            exception: The exception to classify

        Returns:
            str: Error classification for metrics
        """
        if isinstance(exception, (json.JSONDecodeError, UnicodeDecodeError)):
            return "json_error"
        elif isinstance(exception, (ConnectionError, TimeoutError, OSError)):
            return "network_error"
        elif isinstance(exception, ValueError):
            return "validation_error"
        else:
            return "error"


class OffsetManager:
    """Manages Kafka offset storage and batch commits.

    This class encapsulates all offset management logic, making the main
    consumer loop cleaner and easier to understand.
    """

    def __init__(self, consumer: KafkaConsumer, commit_config: CommitConfig):
        """Initialize the offset manager.

        Args:
            consumer: The Kafka consumer instance
            commit_config: Configuration for commit behavior
        """
        self.consumer = consumer
        self.commit_config = commit_config
        # Store tuples of (offset, leader_epoch) for each partition
        self.stored_offsets: Dict[TopicPartition, tuple] = {}
        self.offset_mutex = threading.Lock()

    def store(self, topic_partition: TopicPartition, offset: int, leader_epoch: Optional[int] = None):
        """Store offset and leader_epoch for later batch commit (thread-safe).

        Args:
            topic_partition: The topic partition
            offset: The message offset
            leader_epoch: The leader epoch for the partition (optional)
        """
        with self.offset_mutex:
            self.stored_offsets[topic_partition] = (offset, leader_epoch)
            logger.debug(
                f"Stored offset {offset} (leader_epoch={leader_epoch}) " f"for partition {topic_partition.partition}"
            )

    def should_commit(self, offset: int) -> bool:
        """Check if offset should trigger a batch commit.

        Args:
            offset: The current message offset

        Returns:
            bool: True if offset should be committed now
        """
        if self.commit_config.commit_modulo <= 0:
            return False  # Disabled

        return (offset + 1) % self.commit_config.commit_modulo == 0

    def commit(self) -> bool:
        """Commit all stored offsets to Kafka (thread-safe).

        Returns:
            bool: True if commit succeeded, False otherwise
        """
        if not self.consumer:
            logger.warning("Cannot commit offsets: consumer not initialized")
            return False

        # Create a copy of offsets to avoid holding the lock during commit
        with self.offset_mutex:
            if not self.stored_offsets:
                logger.debug("No stored offsets to commit")
                return True

            offsets_to_commit = self.stored_offsets.copy()

        # Initialize offset_dict before try block to avoid scoping issues
        offset_dict = None

        try:
            # Commit the copied offsets
            # Note: Kafka expects offset+1 for the next message to consume
            # kafka-python requires OffsetAndMetadata objects with leader_epoch
            offset_dict = {
                tp: OffsetAndMetadata(offset + 1, None, leader_epoch)
                for tp, (offset, leader_epoch) in offsets_to_commit.items()
            }

            # Verify all partitions are currently assigned before committing
            assigned_partitions = self.consumer.assignment()
            unassigned_partitions = set(offset_dict.keys()) - assigned_partitions
            if unassigned_partitions:
                logger.warning(
                    f"Attempting to commit offsets for unassigned partitions: {unassigned_partitions}. "
                    f"Currently assigned: {assigned_partitions}. Skipping unassigned partitions."
                )
                # Filter out unassigned partitions
                offset_dict = {tp: om for tp, om in offset_dict.items() if tp in assigned_partitions}

                if not offset_dict:
                    logger.warning("No assigned partitions to commit after filtering")
                    return False

            logger.info(f"Committing {len(offset_dict)} offset(s) to Kafka: {offset_dict}")
            self.consumer.commit(offsets=offset_dict)
            logger.info("Successfully committed offsets")

            # Clear stored offsets after successful commit
            with self.offset_mutex:
                self.stored_offsets.clear()

            return True

        except Exception as e:
            # Build error message with safe access to offset_dict
            error_details = f"Failed to commit offsets: {type(e).__name__}: {e}."
            if offset_dict is not None:
                error_details += f" Attempted to commit {len(offset_dict)} offset(s): {offset_dict}."
            else:
                error_details += f" Failed before creating offset_dict. Offsets to commit: {offsets_to_commit}."

            error_details += (
                f" Consumer state: group_id={self.consumer.config.get('group_id')}, "
                f"bootstrap_servers={self.consumer.config.get('bootstrap_servers')}, "
                f"assigned_partitions={self.consumer.assignment() if self.consumer else 'N/A'}"
            )
            logger.error(error_details)

            # On commit failure, restore offsets back to storage for next attempt
            with self.offset_mutex:
                for tp, (offset, leader_epoch) in offsets_to_commit.items():
                    # Only restore if not updated by another thread
                    # Compare by offset only (first element of tuple)
                    if tp not in self.stored_offsets or self.stored_offsets[tp][0] <= offset:
                        self.stored_offsets[tp] = (offset, leader_epoch)

            return False

    def clear(self):
        """Clear all stored offsets (thread-safe)."""
        with self.offset_mutex:
            self.stored_offsets.clear()


class RebalanceListener(ConsumerRebalanceListener):
    """Listen for Kafka consumer rebalance events.

    Inherits from ConsumerRebalanceListener to properly integrate with kafka-python.
    """

    def __init__(self, consumer_instance):
        """Initialize the rebalance listener.

        Args:
            consumer_instance: The RBACKafkaConsumer instance
        """
        self.consumer_instance = consumer_instance

    def on_partitions_revoked(self, revoked):
        """Handle partition revocation during rebalance.

        Args:
            revoked: List of TopicPartition objects being revoked
        """
        self.consumer_instance._on_partitions_revoked(revoked)

    def on_partitions_assigned(self, assigned):
        """Handle partition assignment during rebalance.

        Args:
            assigned: List of TopicPartition objects being assigned
        """
        logger.info(f"Partitions assigned: {assigned}")


class RBACKafkaConsumer:
    """RBAC Kafka consumer for processing Debezium and replication messages."""

    def __init__(
        self,
        topic: Optional[str] = None,
        health_check_interval: int = 30,
        retry_config: Optional[RetryConfig] = None,
        commit_config: Optional[CommitConfig] = None,
    ):
        """Initialize the consumer."""
        self.topic = topic or settings.RBAC_KAFKA_CONSUMER_TOPIC
        self.consumer: Optional[KafkaConsumer] = None
        self.validator = MessageValidator()
        self.retry_config = retry_config or RetryConfig()
        self.commit_config = commit_config or CommitConfig()
        self.liveness_file = Path("/tmp/kubernetes-liveness")
        self.readiness_file = Path("/tmp/kubernetes-readiness")
        self.is_healthy = False
        self.is_consuming = False
        self.is_paused_for_retry = False  # Track if consumer is paused due to max retries
        self.health_check_interval = health_check_interval
        self.health_check_thread: Optional[threading.Thread] = None
        self._stop_health_check = threading.Event()
        self.last_activity = time.time()
        self._shutdown_in_progress = False

        # Offset manager (will be initialized when consumer is created)
        self.offset_manager: Optional[OffsetManager] = None

    def _create_consumer(self) -> KafkaConsumer:
        """Create and configure Kafka consumer."""
        if not settings.KAFKA_ENABLED:
            raise RuntimeError("Kafka must be enabled to run the consumer")

        if not self.topic:
            raise RuntimeError("Consumer topic must be configured")

        # Check if custom broker is configured for the consumer
        custom_broker = settings.RBAC_KAFKA_CUSTOM_CONSUMER_BROKER
        if custom_broker:
            # Use custom broker configuration
            logger.info(f"Using custom Kafka broker: {custom_broker}")
            kafka_servers = [custom_broker]
            kafka_auth = None  # Don't use auth with custom broker
        else:
            # Use default Clowder/localhost configuration
            kafka_auth = settings.KAFKA_AUTH
            kafka_servers = settings.KAFKA_SERVERS

        try:
            if kafka_auth:
                # Filter out producer-specific configurations that are not valid for consumers
                # Producer-only configs: retries, max_in_flight_requests_per_connection, acks, etc.
                producer_only_configs = {
                    "retries",
                    "max_in_flight_requests_per_connection",
                    "acks",
                    "enable_idempotence",
                    "transactional_id",
                    "transaction_timeout_ms",
                    "compression_type",
                    "batch_size",
                    "linger_ms",
                    "buffer_memory",
                    "max_block_ms",
                    "delivery_timeout_ms",
                }
                consumer_auth = {k: v for k, v in kafka_auth.items() if k not in producer_only_configs}
                # Log if any producer-specific configs were filtered out
                filtered_configs = set(kafka_auth.keys()) & producer_only_configs
                if filtered_configs:
                    logger.info(f"Filtered out producer-specific configs for consumer: {filtered_configs}")
                consumer = KafkaConsumer(
                    self.topic,
                    auto_offset_reset="earliest",  # Process all messages from beginning if no offset exists
                    enable_auto_commit=False,  # Manual commit for at-least-once processing
                    group_id=settings.RBAC_KAFKA_CONSUMER_GROUP_ID,
                    **consumer_auth,
                )
                logger.info(f"Kafka consumer created with auth for topic: {self.topic}")
            else:
                consumer = KafkaConsumer(
                    self.topic,
                    bootstrap_servers=kafka_servers,
                    auto_offset_reset="earliest",  # Process all messages from beginning if no offset exists
                    enable_auto_commit=False,  # Manual commit for at-least-once processing
                    group_id=settings.RBAC_KAFKA_CONSUMER_GROUP_ID,
                )
                logger.info(f"Kafka consumer created with servers {kafka_servers} for topic: {self.topic}")

            return consumer

        except Exception as e:
            logger.error(f"Failed to create Kafka consumer: {e}")
            raise

    def _on_partitions_revoked(self, revoked_partitions):
        """Handle partition rebalance - commit offsets before partitions are revoked.

        This is called by Kafka when partitions are being reassigned to other consumers.
        We commit our current offsets to ensure we don't lose progress.
        """
        if not self.commit_config.commit_on_rebalance:
            logger.debug("Rebalance offset commit disabled by config")
            return

        if self._shutdown_in_progress:
            logger.debug("Skipping rebalance commit during shutdown")
            return

        logger.info(f"Partitions being revoked: {revoked_partitions}")

        # Commit any stored offsets before losing the partitions
        if self.offset_manager and self.offset_manager.commit():
            logger.info("Successfully committed offsets during rebalance")
        else:
            logger.warning("Failed to commit offsets during rebalance")

    def _update_health_status(self, healthy: bool):
        """Update health status files."""
        self.is_healthy = healthy
        self.last_activity = time.time()

        if healthy:
            # Create/update liveness file
            self.liveness_file.touch()
            # Create/update readiness file
            self.readiness_file.touch()
            logger.debug("Health status updated: healthy")
        else:
            # Remove readiness file but keep liveness file
            if self.readiness_file.exists():
                self.readiness_file.unlink()
            logger.warning("Health status updated: unhealthy")

    def _start_health_check_thread(self):
        """Start the background health check thread."""
        if self.health_check_thread is not None:
            return

        self._stop_health_check.clear()
        self.health_check_thread = threading.Thread(
            target=self._health_check_loop,
            name="kafka-consumer-health-check",
            daemon=True,
        )
        self.health_check_thread.start()
        logger.info(f"Started health check thread with {self.health_check_interval}s interval")

    def _stop_health_check_thread(self):
        """Stop the background health check thread."""
        if self.health_check_thread is None:
            return

        self._stop_health_check.set()
        self.health_check_thread.join(timeout=5)
        self.health_check_thread = None
        logger.info("Stopped health check thread")

    def _health_check_loop(self):
        """Background thread that periodically updates health status."""
        while not self._stop_health_check.wait(self.health_check_interval):
            try:
                # Check if consumer is still alive and connected
                if self.is_consuming and self.consumer is not None:
                    # Try to check Kafka connection by getting partition metadata
                    # This is a lightweight operation that verifies connectivity
                    try:
                        # This will raise an exception if Kafka is unreachable
                        # Use partitions_for_topic which is more universally available
                        self.consumer.partitions_for_topic(self.topic)

                        # Consumer is alive and connected
                        self._update_health_status(True)
                        logger.debug("Health check passed: consumer is connected and ready")

                    except Exception as e:
                        logger.warning(f"Health check failed: Kafka connectivity issue: {e}")
                        # Don't immediately mark as unhealthy, give it a few tries
                        # Only update liveness (consumer process is alive) but not readiness
                        self.liveness_file.touch()
                        if self.readiness_file.exists():
                            self.readiness_file.unlink()

                elif self.is_consuming:
                    # Consumer should be running but isn't - this is a problem
                    logger.error("Health check failed: consumer should be running but isn't")
                    self._update_health_status(False)
                else:
                    # Consumer is not supposed to be running (stopped/stopping)
                    logger.debug("Health check: consumer is not running (expected)")

            except Exception as e:
                logger.error(f"Health check thread error: {e}")
                # Keep liveness but remove readiness on thread errors
                self.liveness_file.touch()
                if self.readiness_file.exists():
                    self.readiness_file.unlink()

    def _process_single(self, message_value: Dict[str, Any], message_partition: int, message_offset: int) -> bool:
        """Process a single message (parse and handle).

        This is the core message processing logic without retry concerns.

        Args:
            message_value: The Kafka message value to process
            message_partition: The partition number (for logging)
            message_offset: The message offset (for logging)

        Returns:
            bool: True if message processed successfully

        Raises:
            ValidationError: If message validation fails
            Other exceptions: If processing fails
        """
        # Parse Debezium message (may raise ValidationError or JSONDecodeError)
        parsed_message = self._parse_debezium_message(message_value)

        # Process the message (may raise ValidationError or other exceptions)
        return self._process_debezium_message(parsed_message)

    def _parse_debezium_message(self, message_value: Dict[str, Any]) -> Dict[str, Any]:
        """Parse standard Debezium message format with schema/payload wrapper.

        Standard Debezium messages come in this format:
        {
            "schema": {...},
            "payload": "JSON_STRING_CONTAINING_ACTUAL_DATA"
        }

        This method extracts and parses the payload to get the actual business data.

        Raises:
            ValidationError: If message format is invalid
        """
        try:
            # Only accept standard Debezium message format with schema and payload
            if "schema" not in message_value or "payload" not in message_value:
                error_msg = (
                    f"Message is not in standard Debezium format. "
                    f"Expected 'schema' and 'payload' fields. Got: {list(message_value.keys())}"
                )
                logger.error(error_msg)
                raise ValidationError(error_msg)

            payload_str = message_value.get("payload")

            # Parse payload to dict if it's a string
            if isinstance(payload_str, str):
                try:
                    payload_data = json.loads(payload_str)
                    logger.debug(f"Parsed Debezium payload: {payload_data}")
                except json.JSONDecodeError as e:
                    error_msg = f"Failed to parse Debezium payload JSON: {e}, payload: {payload_str}"
                    logger.error(error_msg)
                    # JSONDecodeError will be caught by default error handler
                    raise
            elif isinstance(payload_str, dict):
                # Payload is already parsed as dict
                payload_data = payload_str
                logger.debug(f"Debezium payload already parsed: {payload_data}")
            else:
                error_msg = f"Debezium payload must be a string or dict, got: {type(payload_str)}"
                logger.error(error_msg)
                raise ValidationError(error_msg)

            # Validate payload structure - common logic for both string and dict payloads
            if "relations_to_add" in payload_data or "relations_to_remove" in payload_data:
                # Extract aggregatetype and aggregateid from the event if available
                return {
                    "aggregatetype": payload_data.get("aggregatetype", ""),
                    "aggregateid": payload_data.get("aggregateid", ""),
                    "type": payload_data.get("type", ""),
                    "payload": payload_data,
                }
            else:
                error_msg = (
                    f"Unknown payload structure in Debezium message. "
                    f"Expected 'relations_to_add' or 'relations_to_remove'. "
                    f"Got: {list(payload_data.keys())}"
                )
                logger.error(error_msg)
                raise ValidationError(error_msg)

        except ValidationError:
            # Re-raise ValidationError - will NOT be retried (non-retryable)
            raise
        except json.JSONDecodeError:
            # Re-raise JSONDecodeError to be handled by error handler
            raise
        except Exception as e:
            logger.error(f"Error parsing Debezium message: {e}")
            # Re-raise other exceptions to be handled by retry logic
            raise

    def _process_message_with_retry(
        self,
        message_value: Dict[str, Any],
        message_offset: int,
        message_partition: int,
        topic_partition: TopicPartition,
        leader_epoch: Optional[int] = None,
        error_handler=None,
    ) -> bool:
        """Process a message with comprehensive retry logic.

        Retries transient errors (network, DB, etc.) but NOT ValidationError.
        ValidationError indicates permanently malformed messages that won't become valid.

        Args:
            message_value: The Kafka message value to process
            message_offset: The message offset
            message_partition: The partition number
            topic_partition: TopicPartition object for offset tracking
            leader_epoch: The leader epoch for the partition (optional)
            error_handler: Optional callable(Exception) -> bool to short-circuit retries

        Returns:
            bool: True if message processed successfully, False only on shutdown (InterruptedError)

        Raises:
            Exception: Re-raises any exception that should stop the consumer
        """  # noqa: D202

        # Define error handler to skip retries for non-retryable errors
        def should_skip_retry(exception: Exception) -> bool:
            """Return True if retry should be skipped (non-retryable error)."""
            # Import here to avoid circular dependency
            from google.protobuf.json_format import ParseError

            # ValidationError and ParseError mean bad message format - retrying won't help
            if isinstance(exception, (ValidationError, ParseError)):
                logger.error(
                    f"{type(exception).__name__} is non-retryable for message at partition {message_partition}, "
                    f"offset {message_offset}. Consumer will stop."
                )
                return True
            # Use custom error handler if provided
            if error_handler and callable(error_handler):
                return error_handler(exception)
            return False

        # Create a retry helper with custom error handling
        retry_helper = RetryHelper(
            retry_config=self.retry_config,
            shutdown_event=self._stop_health_check,
            error_handler=should_skip_retry,
        )

        # Process message with retry logic
        def process_wrapper():
            """Wrap message processing for retry logic."""
            # Process the message
            success = self._process_single(message_value, message_partition, message_offset)

            # If processing returned False, treat as an error and retry
            if not success:
                raise RuntimeError("Message processing failed with False return value")

            return True

        try:
            # Run with retry logic
            # IMPORTANT: We do NOT commit offsets during retries
            # Offsets are only committed after successful processing
            retry_helper.run(process_wrapper)
            logger.info(f"Message processed successfully (partition: {message_partition}, offset: {message_offset})")
            return True

        except InterruptedError:
            # Shutdown signal received - this is the ONLY case where we return False
            logger.info("Message processing interrupted by shutdown signal")
            return False

        except RuntimeError as e:
            # Max retries exceeded - pause consumer and wait for manual restart
            error_msg = (
                f"Max operation retries exceeded for message "
                f"(partition: {message_partition}, offset: {message_offset}): {e}. "
                f"Consumer will PAUSE and wait for manual restart.\n"
                f"Offset NOT committed - message will be retried on restart.\n"
                f"To resolve: Fix the issue and restart the pod manually.\n"
                f"Message content: {message_value}"
            )
            logger.error(error_msg)
            messages_processed_total.labels(message_type="unknown", status="max_retries_exceeded").inc()

            # Mark consumer as paused to prevent offset commit on shutdown
            self.is_paused_for_retry = True

            # Pause indefinitely - keep pod alive, wait for manual restart
            logger.critical(
                "CONSUMER PAUSED: Max retries exceeded. Manual intervention required. "
                "Pod will remain running. Restart the pod to retry the message."
            )

            # Enter infinite sleep to keep pod alive but not processing
            while True:
                time.sleep(60)
                logger.warning(
                    f"Consumer still paused waiting for restart "
                    f"(partition: {message_partition}, offset: {message_offset})"
                )

        except Exception as e:
            # Error handler short-circuited retry or other unexpected error
            # This should NOT be silently ignored - raise to stop the consumer
            error_msg = (
                f"Error handler short-circuited retry for message "
                f"(partition: {message_partition}, offset: {message_offset}): {e}. "
                f"Consumer will stop to prevent silent message loss."
            )
            logger.error(error_msg)
            messages_processed_total.labels(message_type="unknown", status="error_handler_skip").inc()
            raise

    def _process_debezium_message(self, message_value: Dict[str, Any]) -> bool:
        """Process a Debezium message."""
        with message_processing_duration.labels(message_type="debezium").time():
            try:
                # Create structured message
                # Note: message structure is already validated by _parse_debezium_message
                debezium_msg = DebeziumMessage.from_kafka_message(message_value)

                # Process all messages with relations - no strict aggregate type checking
                return self._process_relations_message(debezium_msg)

            except ValidationError:
                # Re-raise ValidationError - will NOT be retried (non-retryable)
                raise
            except Exception as e:
                logger.error(f"Error processing Debezium message: {e}")
                messages_processed_total.labels(message_type="debezium", status="error").inc()
                # Re-raise to allow retry logic to handle
                raise

    def _process_relations_message(self, debezium_msg: DebeziumMessage) -> bool:
        """Process a relations Debezium message."""
        try:
            # Validate replication payload
            if not self.validator.validate_replication_message(debezium_msg.payload):
                logger.error(f"Replication message validation failed. Payload content: {debezium_msg.payload}")
                messages_processed_total.labels(message_type="relations", status="validation_failed").inc()
                # Raise ValidationError instead of returning False
                # This signals a permanent validation failure that shouldn't be retried
                raise ValidationError(
                    f"Replication message validation failed for aggregateid: {debezium_msg.aggregateid}"
                )

            resource_context = debezium_msg.payload.get("resource_context")
            org_id = None
            event_type = None

            # Extract org_id and event_type from resource_context if present
            if resource_context and isinstance(resource_context, dict):
                org_id = resource_context.get("org_id")
                event_type = resource_context.get("event_type")
            else:
                logger.debug(
                    f"No resource_context found, skipping org_id and event_type extraction. "
                    f"aggregateid: {debezium_msg.aggregateid}"
                )

            # Create structured replication message
            replication_msg = ReplicationMessage.from_payload(debezium_msg.payload)

            logger.info(
                f"Processing relations message - org_id: {org_id}, "
                f"event_type: {event_type}, "
                f"relations_to_add: {len(replication_msg.relations_to_add)}, "
                f"relations_to_remove: {len(replication_msg.relations_to_remove)}"
            )

            # Convert JSON dictionaries to protobuf objects
            relations_to_add_pb = []
            for relation_dict in replication_msg.relations_to_add:
                relation_pb = json_format.ParseDict(relation_dict, common_pb2.Relationship())
                relations_to_add_pb.append(relation_pb)

            relations_to_remove_pb = []
            for relation_dict in replication_msg.relations_to_remove:
                relation_pb = json_format.ParseDict(relation_dict, common_pb2.Relationship())
                relations_to_remove_pb.append(relation_pb)

            # Do tuple deletes for relationships
            replication_delete_response = relations_api_replication._delete_relationships(
                relationships=relations_to_remove_pb
            )

            # Do tuple writes for relationships
            replication_add_response = relations_api_replication._write_relationships(
                relationships=relations_to_add_pb
            )

            # Extract consistency token from responses
            token = getattr(replication_add_response.consistency_token, "token", None) or getattr(
                replication_delete_response.consistency_token, "token", None
            )

            if token and org_id:
                try:
                    tenant = Tenant.objects.get(org_id=org_id)
                    tenant.relations_consistency_token = token
                    tenant.save()
                except Tenant.DoesNotExist:
                    logger.warning(
                        f"Tenant not found for org_id: {org_id}. " f"Unable to save consistency token: {token}"
                    )
            else:
                logger.warning(
                    f"No consistency token in either write or delete response - "
                    f"org_id: {org_id}, "
                    f"aggregateid: {debezium_msg.aggregateid}"
                )
            messages_processed_total.labels(message_type="relations", status="success").inc()
            return True

        except ValidationError:
            # Re-raise ValidationError - will NOT be retried (non-retryable)
            raise
        except Exception as e:
            logger.error(f"Error processing relations message: {e}")
            messages_processed_total.labels(message_type="relations", status="error").inc()
            # Re-raise to trigger retry logic
            raise

    def start_consuming(self):
        """Start consuming messages from Kafka.

        The consumer will stop on fatal errors (e.g., max retries exceeded).
        Use Kubernetes/orchestration layer to restart the consumer pod on failure.
        """
        try:
            self.consumer = self._create_consumer()

            # Initialize offset manager now that consumer is created
            self.offset_manager = OffsetManager(self.consumer, self.commit_config)

            # Subscribe to topic with rebalance listener
            # This registers our callback for partition revocation events
            rebalance_listener = RebalanceListener(self)
            self.consumer.subscribe([self.topic], listener=rebalance_listener)

            self.is_consuming = True

            # Start health check thread
            self._start_health_check_thread()

            # Initial health status
            self._update_health_status(True)

            logger.info(f'RBAC Kafka consumer started, listening on topic "{self.topic}"')
            logger.info(f"Batch commit enabled: every {self.commit_config.commit_modulo} messages")
            logger.info("Waiting for messages from Kafka...")

            # Track committed offsets per partition
            last_committed_offsets = {}

            # Process incoming messages with infinite retry
            for message in self.consumer:
                try:
                    # Create TopicPartition object for offset tracking
                    topic_partition = TopicPartition(message.topic, message.partition)

                    # Get committed offset for this partition on first message
                    if topic_partition not in last_committed_offsets:
                        try:
                            committed = self.consumer.committed(topic_partition)
                            last_committed_offsets[topic_partition] = committed if committed is not None else -1
                            logger.info(
                                f"Partition {message.partition}: starting from offset {message.offset}, "
                                f"last committed offset: {last_committed_offsets[topic_partition]}"
                            )
                        except Exception as e:
                            logger.warning(f"Could not get committed offset for partition {message.partition}: {e}")
                            last_committed_offsets[topic_partition] = -1

                    if message.value is None:
                        logger.warning(
                            f"Received message with None value, skipping "
                            f"(partition: {message.partition}, offset: {message.offset})"
                        )
                        # Treat None messages as successfully processed and commit the offset
                        # to move past them. None values are valid in Kafka (e.g., tombstone messages).
                        self.offset_manager.store(topic_partition, message.offset, message.leader_epoch)
                        if self.offset_manager.should_commit(message.offset):
                            self.offset_manager.commit()
                        continue

                    # Parse JSON from raw message bytes
                    try:
                        message_value = json.loads(message.value.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        # Fail fast on JSON parse errors
                        raw_content = message.value[:100] if len(message.value) > 100 else message.value
                        error_msg = (
                            f"Failed to parse JSON from message at partition {message.partition}, "
                            f"offset {message.offset}: {e}. "
                            f"Sample content: {raw_content}. "
                            f"This indicates a malformed message in the Kafka topic. "
                            f"Fix the producer or manually skip the offset, then restart the consumer."
                        )
                        logger.error(error_msg)
                        messages_processed_total.labels(message_type="unknown", status="json_error").inc()
                        raise

                    # Log processing with last committed offset info
                    last_committed = last_committed_offsets.get(topic_partition, -1)
                    logger.info(
                        f"Processing message (partition: {message.partition}, offset: {message.offset}, "
                        f"last_committed: {last_committed})"
                    )
                    logger.debug(
                        f"Message content (partition: {message.partition}, offset: {message.offset}): {message_value}"
                    )

                    # Process the message with retry logic
                    # This will keep retrying until success or shutdown
                    success = self._process_message_with_retry(
                        message_value,
                        message.offset,
                        message.partition,
                        topic_partition,
                        message.leader_epoch,
                    )

                    if success:
                        # Store the offset after successful processing
                        self.offset_manager.store(topic_partition, message.offset, message.leader_epoch)

                        # Check if we should commit based on batch size (CommitModulo)
                        if self.offset_manager.should_commit(message.offset):
                            logger.info(
                                f"Batch commit triggered at offset {message.offset} "
                                f"(CommitModulo: {self.commit_config.commit_modulo})"
                            )
                            if self.offset_manager.commit():
                                # Update tracking of last committed offset
                                last_committed_offsets[topic_partition] = message.offset + 1
                        else:
                            logger.debug(f"Offset {message.offset} stored, waiting for batch commit")

                        # Update activity timestamp (health check thread handles status updates)
                        self.last_activity = time.time()
                    else:
                        # Only happens on shutdown (InterruptedError)
                        logger.info(
                            f"Message processing interrupted by shutdown "
                            f"(partition: {message.partition}, offset: {message.offset}). "
                            f"Offset NOT committed - message will be retried on restart."
                        )
                        # Break out of the message loop to trigger shutdown
                        break

                except Exception as e:
                    # Fail fast on unexpected exceptions - stop the consumer
                    # This ensures we don't lose messages by silently continuing
                    logger.error(
                        f"Unexpected error in message loop (partition: {getattr(message, 'partition', 'unknown')}, "
                        f"offset: {getattr(message, 'offset', 'unknown')}): {e}. "
                        f"Consumer will stop to prevent data loss. "
                        f"Message will be retried on restart."
                    )
                    messages_processed_total.labels(message_type="unknown", status="unexpected_error").inc()
                    # Re-raise to stop the consumer - do NOT continue to next message
                    raise

        except KafkaError as e:
            logger.error(f"Kafka error: {e}")
            self._update_health_status(False)
            raise
        except Exception as e:
            logger.error(f"Consumer error: {e}")
            self._update_health_status(False)
            raise
        finally:
            self._shutdown_in_progress = True
            self.is_consuming = False
            self._stop_health_check_thread()

            # Commit any remaining offsets on shutdown ONLY if not paused for retry
            if self.commit_config.commit_on_shutdown and self.offset_manager:
                if self.is_paused_for_retry:
                    logger.warning(
                        "Consumer was paused due to max retries - NOT committing offsets on shutdown. "
                        "Message will be retried on next restart."
                    )
                else:
                    logger.info("Committing remaining offsets on shutdown")
                    if self.offset_manager.commit():
                        logger.info("Successfully committed offsets on shutdown")
                    else:
                        logger.warning("Failed to commit offsets on shutdown")

            if self.consumer:
                self.consumer.close()
                logger.info("Kafka consumer closed")

    def stop_consuming(self):
        """Stop consuming messages."""
        self._shutdown_in_progress = True
        self.is_consuming = False
        self._stop_health_check_thread()

        # Commit any remaining offsets on stop ONLY if not paused for retry
        if self.commit_config.commit_on_shutdown and self.offset_manager:
            if self.is_paused_for_retry:
                logger.warning(
                    "Consumer was paused due to max retries - NOT committing offsets on stop. "
                    "Message will be retried on next restart."
                )
            else:
                logger.info("Committing remaining offsets on stop")
                if self.offset_manager.commit():
                    logger.info("Successfully committed offsets on stop")
                else:
                    logger.warning("Failed to commit offsets on stop")

        if self.consumer:
            self.consumer.close()
            self.consumer = None

        self._update_health_status(False)
        logger.info("Kafka consumer stopped")

    def is_ready(self) -> bool:
        """Check if consumer is ready."""
        return self.readiness_file.exists()

    def is_alive(self) -> bool:
        """Check if consumer is alive."""
        return self.liveness_file.exists()
