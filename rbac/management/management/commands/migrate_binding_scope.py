"""Migrate binding scope command."""

import logging

from django.core.management.base import BaseCommand
from management.relation_replicator.outbox_replicator import OutboxReplicator
from migration_tool.migrate_binding_scope import migrate_all_binding_scopes

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Command(BaseCommand):
    """Command class for migrating binding scopes based on permission scope."""

    help = "Migrates existing binding mappings to appropriate scope based on permissions"

    def add_arguments(self, parser):
        """Add arguments to command."""
        parser.add_argument(
            "--batch-size",
            type=int,
            default=100,
            help="Number of bindings to process in each batch (default: 100).",
        )

    def handle(self, *args, **options):
        """Handle method for command."""
        batch_size = options["batch_size"]

        # Always use OutboxReplicator for binding scope migration
        replicator = OutboxReplicator()
        logger.info("Using OutboxReplicator")

        logger.info("*** Starting binding scope migration... ***")
        logger.info(f"Batch size: {batch_size}")
        logger.info("Migrating all tenants")

        try:
            bindings_checked, bindings_migrated = migrate_all_binding_scopes(
                replicator=replicator, batch_size=batch_size
            )

            logger.info("*** Binding scope migration completed. ***")
            logger.info(f"Bindings checked: {bindings_checked}")
            logger.info(f"Bindings migrated: {bindings_migrated}")

        except Exception as e:
            logger.error(f"Binding scope migration failed: {e}", exc_info=True)
            raise
