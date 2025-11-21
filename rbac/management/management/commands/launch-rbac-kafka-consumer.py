"""Launch RBAC Kafka consumer command."""

import logging
import signal
import sys

import sentry_sdk
from app_common_python import LoadedConfig
from core.kafka_consumer import RBACKafkaConsumer
from django.core.management import BaseCommand
from prometheus_client import start_http_server

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Command for launching the Kafka consumer for the read-after-writes."""

    help = "Launches the RBAC Kafka consumer with validation and health checks"

    def __init__(self, *args, **kwargs):
        """Initialize the command."""
        super().__init__(*args, **kwargs)
        self.consumer = None

    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            "--topic",
            type=str,
            help="Kafka topic to consume from (overrides settings)",
        )

    def handle(self, *args, **options):
        """Launch the Kafka consumer."""
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        try:
            # Start Prometheus metrics HTTP server
            # Use the same port configuration as Celery workers
            # Note: Consumer is single-process, so we use the default REGISTRY
            # (Celery uses a custom registry with MultiProcessCollector for multi-process)
            metrics_port = getattr(LoadedConfig, "metricsPort", 9000)

            try:
                start_http_server(metrics_port, addr="0.0.0.0")
                logger.info(f"Prometheus metrics server started on port {metrics_port}")
            except Exception as e:
                sentry_sdk.capture_exception(e)
                logger.error(f"Failed to start metrics server on port {metrics_port}: {e}")
                # Exit the entire process, we don't want to spin up the consumer without metrics
                sys.exit(1)

            # Create and start consumer
            topic = options.get("topic")
            self.consumer = RBACKafkaConsumer(topic=topic)

            logger.info("Starting RBAC Kafka consumer...")
            self.consumer.start_consuming()

        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
        except Exception as e:
            logger.error(f"Consumer failed: {e}")
            sys.exit(1)
        finally:
            self._cleanup()

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self._cleanup()
        sys.exit(0)

    def _cleanup(self):
        """Clean up resources."""
        if self.consumer:
            self.consumer.stop_consuming()
            self.consumer = None
