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
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from django.conf import settings
from kafka import KafkaConsumer
from kafka.errors import KafkaError
from prometheus_client import Counter, Histogram

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
    """Configuration for retry logic."""

    initial_delay: float = 1.0  # Initial delay in seconds
    max_delay: float = 300.0  # Maximum delay (5 minutes)
    backoff_multiplier: float = 2.0  # Exponential backoff multiplier
    jitter_factor: float = 0.1  # Random jitter to avoid thundering herd

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt with exponential backoff and jitter."""
        import random

        # Exponential backoff: delay = initial_delay * (backoff_multiplier ^ attempt)
        delay = self.initial_delay * (self.backoff_multiplier**attempt)
        delay = min(delay, self.max_delay)

        # Add jitter to avoid thundering herd problem
        jitter = delay * self.jitter_factor * random.random()
        return delay + jitter


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
    REQUIRED_REPLICATION_FIELDS = ["relations_to_add", "relations_to_remove"]
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

            # Validate aggregatetype
            aggregatetype = message_value.get("aggregatetype", "").lower()
            if aggregatetype not in MessageValidator.VALID_AGGREGATE_TYPES:
                logger.error(
                    f"Invalid aggregatetype '{aggregatetype}'. "
                    f"Must be one of: {MessageValidator.VALID_AGGREGATE_TYPES}"
                )
                validation_errors_total.labels(error_type="invalid_aggregatetype").inc()
                return False

            # Validate aggregateid is not empty
            aggregateid = message_value.get("aggregateid", "")
            if not aggregateid or not str(aggregateid).strip():
                logger.error("aggregateid cannot be empty")
                validation_errors_total.labels(error_type="empty_aggregateid").inc()
                return False

            # Validate event_type is not empty
            event_type = message_value.get("type", "")
            if not event_type or not str(event_type).strip():
                logger.error("event_type cannot be empty")
                validation_errors_total.labels(error_type="empty_event_type").inc()
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
            # Check required fields
            for field in MessageValidator.REQUIRED_REPLICATION_FIELDS:
                if field not in payload:
                    logger.error(f"Missing required field '{field}' in replication message")
                    validation_errors_total.labels(error_type="missing_replication_field").inc()
                    return False

            # Validate relations_to_add is a list
            relations_to_add = payload.get("relations_to_add")
            if not isinstance(relations_to_add, list):
                logger.error("relations_to_add must be a list")
                validation_errors_total.labels(error_type="invalid_relations_to_add_type").inc()
                return False

            # Validate relations_to_remove is a list
            relations_to_remove = payload.get("relations_to_remove")
            if not isinstance(relations_to_remove, list):
                logger.error("relations_to_remove must be a list")
                validation_errors_total.labels(error_type="invalid_relations_to_remove_type").inc()
                return False

            # Validate that at least one list is not empty (meaningful message)
            if not relations_to_add and not relations_to_remove:
                logger.warning("Both relations_to_add and relations_to_remove are empty - this may indicate a bug")
                validation_errors_total.labels(error_type="empty_relations").inc()
                return False

            # Validate structure of relations
            for relation in relations_to_add + relations_to_remove:
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


class RBACKafkaConsumer:
    """RBAC Kafka consumer for processing Debezium and replication messages."""

    def __init__(
        self,
        topic: Optional[str] = None,
        health_check_interval: int = 30,
        retry_config: Optional[RetryConfig] = None,
    ):
        """Initialize the consumer."""
        self.topic = topic or settings.RBAC_KAFKA_CONSUMER_TOPIC
        self.consumer: Optional[KafkaConsumer] = None
        self.validator = MessageValidator()
        self.retry_config = retry_config or RetryConfig()
        self.liveness_file = Path("/tmp/kubernetes-liveness")
        self.readiness_file = Path("/tmp/kubernetes-readiness")
        self.is_healthy = False
        self.is_consuming = False
        self.health_check_interval = health_check_interval
        self.health_check_thread: Optional[threading.Thread] = None
        self._stop_health_check = threading.Event()
        self.last_activity = time.time()
        self.skipped_messages_count = 0
        self.last_skipped_log_time = time.time()

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
                consumer = KafkaConsumer(
                    self.topic,
                    auto_offset_reset="latest",
                    enable_auto_commit=False,  # Manual commit for exactly-once processing
                    group_id=settings.RBAC_KAFKA_CONSUMER_GROUP_ID,
                    **kafka_auth,
                )
                logger.info(f"Kafka consumer created with auth for topic: {self.topic}")
            else:
                consumer = KafkaConsumer(
                    self.topic,
                    bootstrap_servers=kafka_servers,
                    auto_offset_reset="latest",
                    enable_auto_commit=False,  # Manual commit for exactly-once processing
                    group_id=settings.RBAC_KAFKA_CONSUMER_GROUP_ID,
                )
                logger.info(f"Kafka consumer created with servers {kafka_servers} for topic: {self.topic}")

            return consumer

        except Exception as e:
            logger.error(f"Failed to create Kafka consumer: {e}")
            raise

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

    def _should_retry_exception(self, exception: Exception) -> bool:
        """Determine if an exception should trigger a retry."""
        # JSON parsing errors - don't retry (permanent)
        if isinstance(exception, (json.JSONDecodeError, UnicodeDecodeError)):
            return False

        # Validation errors - don't retry (permanent)
        if isinstance(exception, ValueError) and "validation" in str(exception).lower():
            return False

        # Future: Add network/gRPC exception types here when gRPC calls are added
        # if isinstance(exception, grpc.RpcError):
        #     return True
        # if isinstance(exception, requests.exceptions.RequestException):
        #     return True

        # For now, retry connection, timeout errors, and generic ValueErrors (but not validation-specific ones)
        # This will be expanded when network calls are added to _process_relations_message
        return isinstance(exception, (ConnectionError, TimeoutError, OSError, ValueError))

    def _parse_debezium_message(self, message_value: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse standard Debezium message format with schema/payload wrapper.

        Standard Debezium messages come in this format:
        {
            "schema": {...},
            "payload": "JSON_STRING_CONTAINING_ACTUAL_DATA"
        }

        This method extracts and parses the payload to get the actual business data.
        """
        try:
            # Only accept standard Debezium message format with schema and payload
            if "schema" not in message_value or "payload" not in message_value:
                logger.error(
                    f"Message is not in standard Debezium format. "
                    f"Expected 'schema' and 'payload' fields. Got: {list(message_value.keys())}"
                )
                return None

            payload_str = message_value.get("payload")

            if isinstance(payload_str, str):
                # Parse the JSON string in the payload
                try:
                    payload_data = json.loads(payload_str)
                    logger.debug(f"Parsed Debezium payload: {payload_data}")

                    # For relation messages, wrap the payload in the expected structure
                    if "relations_to_add" in payload_data or "relations_to_remove" in payload_data:
                        return {
                            "aggregatetype": "relations",
                            "aggregateid": "debezium-message",  # Default ID for Debezium messages
                            "type": "relation_change",  # Default type for relation changes
                            "payload": payload_data,
                        }
                    else:
                        logger.error(
                            f"Unknown payload structure in Debezium message. "
                            f"Expected 'relations_to_add' or 'relations_to_remove'. "
                            f"Got: {list(payload_data.keys())}"
                        )
                        return None

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Debezium payload JSON: {e}, payload: {payload_str}")
                    return None

            elif isinstance(payload_str, dict):
                # Payload is already parsed as dict
                logger.debug(f"Debezium payload already parsed: {payload_str}")

                # For relation messages, wrap the payload in the expected structure
                if "relations_to_add" in payload_str or "relations_to_remove" in payload_str:
                    return {
                        "aggregatetype": "relations",
                        "aggregateid": "debezium-message",  # Default ID for Debezium messages
                        "type": "relation_change",  # Default type for relation changes
                        "payload": payload_str,
                    }
                else:
                    logger.error(
                        f"Unknown payload structure in Debezium message. "
                        f"Expected 'relations_to_add' or 'relations_to_remove'. "
                        f"Got: {list(payload_str.keys())}"
                    )
                    return None
            else:
                logger.error(f"Debezium payload must be a string or dict, got: {type(payload_str)}")
                return None

        except Exception as e:
            logger.error(f"Error parsing Debezium message: {e}")
            return None

    def _process_message_with_retry(
        self, message_value: Dict[str, Any], message_offset: int, message_partition: int
    ) -> bool:
        """Process a message with selective retry logic - only retry network/processing errors."""
        attempt = 0
        start_time = time.time()

        while True:
            try:
                # Check if this is a standard Debezium message format
                parsed_message = self._parse_debezium_message(message_value)
                if parsed_message is None:
                    logger.error(f"Failed to parse Debezium message format: {message_value}")
                    return False

                # Attempt to process the message
                success = self._process_debezium_message(parsed_message)

                if success:
                    if attempt > 0:
                        total_duration = time.time() - start_time
                        logger.info(
                            f"Message successfully processed after {attempt + 1} attempts "
                            f"(partition: {message_partition}, offset: {message_offset}, "
                            f"total retry time: {total_duration:.2f}s)"
                        )
                        message_retry_duration.labels(retry_reason="processing_error").observe(total_duration)

                    return True

                # If processing failed, this could be validation or business logic failure
                # Don't retry - validation failures and business logic errors are permanent
                logger.error(
                    f"Message processing failed (partition: {message_partition}, "
                    f"offset: {message_offset}). Message will be skipped.\n"
                    f"Message content: {message_value}"
                )
                messages_processed_total.labels(message_type="unknown", status="processing_failed").inc()
                return False

            except json.JSONDecodeError as e:
                # JSON decode errors are permanent - should not retry
                logger.error(
                    f"Permanent JSON decode error for message (partition: {message_partition}, "
                    f"offset: {message_offset}): {e}. Message will be skipped.\n"
                    f"Message content: {message_value}"
                )
                messages_processed_total.labels(message_type="unknown", status="json_error").inc()
                return False

            except Exception as e:
                # Only retry specific network/processing exceptions
                if self._should_retry_exception(e):
                    retry_reason = "network_error"
                    logger.warning(
                        f"Retryable network error for message (partition: {message_partition}, "
                        f"offset: {message_offset}) on attempt {attempt + 1}: {e}\n"
                        f"Message content: {message_value}"
                    )
                else:
                    # Permanent errors - don't retry
                    logger.error(
                        f"Permanent error for message (partition: {message_partition}, "
                        f"offset: {message_offset}): {e}. Message will be skipped.\n"
                        f"Message content: {message_value}"
                    )
                    messages_processed_total.labels(message_type="unknown", status="permanent_error").inc()
                    return False

            # Calculate delay and wait before retry
            delay = self.retry_config.calculate_delay(attempt)
            retry_attempts_total.labels(
                retry_reason=retry_reason,
                attempt_number=min(attempt + 1, 10),  # Cap at 10 for cardinality
            ).inc()

            logger.info(
                f"Retrying message processing in {delay:.2f}s "
                f"(attempt {attempt + 1}, partition: {message_partition}, offset: {message_offset})"
            )

            # Sleep with ability to interrupt for shutdown
            if self._stop_health_check.wait(delay):
                logger.info("Retry interrupted by shutdown signal")
                return False

            attempt += 1

            # Log periodic status for long-running retries
            if attempt % 10 == 0:
                elapsed = time.time() - start_time
                logger.warning(
                    f"Message still retrying after {attempt} attempts "
                    f"(partition: {message_partition}, offset: {message_offset}, "
                    f"elapsed: {elapsed:.2f}s)"
                )

    def _process_debezium_message(self, message_value: Dict[str, Any]) -> bool:
        """Process a Debezium message."""
        with message_processing_duration.labels(message_type="debezium").time():
            try:
                # Validate parsed message structure
                if not self.validator.validate_parsed_message(message_value):
                    logger.error(f"Parsed message validation failed. Message content: {message_value}")
                    messages_processed_total.labels(message_type="debezium", status="validation_failed").inc()
                    return False

                # Create structured message
                debezium_msg = DebeziumMessage.from_kafka_message(message_value)

                # Process based on aggregate type
                if debezium_msg.aggregatetype.lower() == "relations":
                    return self._process_relations_message(debezium_msg)
                else:
                    logger.warning(f"Unknown aggregate type: {debezium_msg.aggregatetype}")
                    messages_processed_total.labels(message_type="debezium", status="unknown_type").inc()
                    return False

            except Exception as e:
                logger.error(f"Error processing Debezium message: {e}")
                messages_processed_total.labels(message_type="debezium", status="error").inc()
                return False

    def _process_relations_message(self, debezium_msg: DebeziumMessage) -> bool:
        """Process a relations Debezium message."""
        try:
            # Validate replication payload
            if not self.validator.validate_replication_message(debezium_msg.payload):
                logger.error(f"Replication message validation failed. Payload content: {debezium_msg.payload}")
                messages_processed_total.labels(message_type="relations", status="validation_failed").inc()
                return False

            # Create structured replication message
            replication_msg = ReplicationMessage.from_payload(debezium_msg.payload)

            logger.info(
                f"Processing relations message - aggregateid: {debezium_msg.aggregateid}, "
                f"event_type: {debezium_msg.event_type}, "
                f"relations_to_add: {len(replication_msg.relations_to_add)}, "
                f"relations_to_remove: {len(replication_msg.relations_to_remove)}"
            )

            # TODO: Add actual processing logic here
            # This is where you would integrate with the relation replication system

            messages_processed_total.labels(message_type="relations", status="success").inc()
            return True

        except Exception as e:
            logger.error(f"Error processing relations message: {e}")
            messages_processed_total.labels(message_type="relations", status="error").inc()
            return False

    def start_consuming(self):
        """Start consuming messages from Kafka."""
        try:
            self.consumer = self._create_consumer()
            self.is_consuming = True

            # Start health check thread
            self._start_health_check_thread()

            # Initial health status
            self._update_health_status(True)

            logger.info(f'RBAC Kafka consumer started, listening on topic "{self.topic}"')
            logger.info("Waiting for messages from Kafka...")

            # Process incoming messages with infinite retry
            for message in self.consumer:
                try:
                    if message.value is None:
                        logger.warning(
                            f"Received message with None value, skipping "
                            f"(partition: {message.partition}, offset: {message.offset})"
                        )
                        self.consumer.commit()  # Commit the offset for None messages
                        continue

                    # Parse JSON from raw message bytes
                    try:
                        message_value = json.loads(message.value.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        # Count skipped messages and log periodically to reduce noise
                        self.skipped_messages_count += 1
                        current_time = time.time()

                        # Log every 10 skipped messages or every 30 seconds
                        if self.skipped_messages_count % 10 == 0 or current_time - self.last_skipped_log_time > 30:

                            raw_content = message.value[:100] if len(message.value) > 100 else message.value
                            logger.info(
                                f"Skipped {self.skipped_messages_count} non-JSON messages "
                                f"(latest: partition {message.partition}, offset {message.offset}) - "
                                f"Sample content: {raw_content}"
                            )
                            self.last_skipped_log_time = current_time

                        messages_processed_total.labels(message_type="unknown", status="json_error").inc()
                        # Skip malformed JSON messages and commit offset
                        self.consumer.commit()
                        continue

                    logger.info(f"Processing message (partition: {message.partition}, offset: {message.offset})")
                    logger.debug(
                        f"Message content (partition: {message.partition}, offset: {message.offset}): {message_value}"
                    )

                    # Process the message with retry logic
                    # This will keep retrying until success or shutdown
                    success = self._process_message_with_retry(message_value, message.offset, message.partition)

                    if success:
                        logger.info(
                            f"Message processed successfully (partition: {message.partition}, offset: {message.offset})"
                        )

                        # Commit the offset only after successful processing
                        # This ensures exactly-once processing and message ordering
                        try:
                            self.consumer.commit()
                            logger.info(f"Committed offset (partition: {message.partition}, offset: {message.offset})")
                        except Exception as commit_error:
                            logger.error(f"Failed to commit offset: {commit_error}")
                            # Don't raise - we'll retry on next consumer restart

                        # Update activity timestamp (health check thread handles status updates)
                        self.last_activity = time.time()
                    else:
                        # Only happens on shutdown or permanent errors (like JSON decode)
                        logger.warning(
                            f"Message processing abandoned (partition: {message.partition}, offset: {message.offset})"
                        )
                        # For permanent errors, we still commit to avoid reprocessing the same bad message
                        try:
                            self.consumer.commit()
                            logger.debug(
                                f"Committed offset for abandoned message "
                                f"(partition: {message.partition}, offset: {message.offset})"
                            )
                        except Exception as commit_error:
                            logger.error(f"Failed to commit offset for abandoned message: {commit_error}")

                except Exception as e:
                    # This should rarely happen as retry logic handles most exceptions
                    logger.error(
                        f"Unexpected error in message loop (partition: {getattr(message, 'partition', 'unknown')}, "
                        f"offset: {getattr(message, 'offset', 'unknown')}): {e}"
                    )
                    messages_processed_total.labels(message_type="unknown", status="unexpected_error").inc()
                    # Continue to next message - don't let one bad message break the entire consumer

        except KafkaError as e:
            logger.error(f"Kafka error: {e}")
            self._update_health_status(False)
            raise
        except Exception as e:
            logger.error(f"Consumer error: {e}")
            self._update_health_status(False)
            raise
        finally:
            self.is_consuming = False
            self._stop_health_check_thread()
            if self.consumer:
                self.consumer.close()
                logger.info("Kafka consumer closed")

    def stop_consuming(self):
        """Stop consuming messages."""
        self.is_consuming = False
        self._stop_health_check_thread()

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
