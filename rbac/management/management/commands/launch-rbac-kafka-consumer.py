"""Launch RBAC Kafka consumer command."""

import logging
from pathlib import Path

from django.core.management import BaseCommand
from kafka import KafkaConsumer

from rbac import settings

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Command for launching the Kafka consumer for the read-after-writes."""

    help = "Launches the Kafka consumer"

    def handle(self, *args, **options):
        """Launch the Kafka consumer."""
        if not settings.KAFKA_ENABLED:
            raise RuntimeError("Kafka must be enabled to be able to run the consumer")

        # Grab the Kafka settings.
        kafka_auth = settings.KAFKA_AUTH
        kafka_servers = settings.KAFKA_SERVERS

        consumer: KafkaConsumer
        if kafka_auth:
            consumer = KafkaConsumer(settings.RBAC_KAFKA_CONSUMER_READ_AFTER_WRITE_TOPIC, **kafka_auth)
        else:
            consumer = KafkaConsumer(
                settings.RBAC_KAFKA_CONSUMER_READ_AFTER_WRITE_TOPIC, bootstrap_servers=kafka_servers
            )

        # Create the liveness file for Kubernetes and log the startup.
        Path("/tmp/kubernetes-liveness").touch()
        logger.info(
            f'RBAC Kafka consumer listening on topic "{settings.RBAC_KAFKA_CONSUMER_READ_AFTER_WRITE_TOPIC}"',
        )

        # Process incoming messages.
        for message in consumer:
            logger.info(message)
