"""Import user data command."""

import logging

from django.core.management.base import BaseCommand
from management.management.commands.utils import add_ungrouped_hosts_for_tenants

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Command(BaseCommand):
    """Command class for importing tenant and user data into database."""

    help = "Import tenant and user data into db"

    def add_arguments(self, parser):
        """Add arguments to command."""
        parser.add_argument("--batch_size", default=1000, help="The number of records to process as a batch")

    def handle(self, *args, **options):
        """Handle method for command."""
        logger.info("*** Adding ungrouped hosts for tenants... ***")
        batch_size = int(options["batch_size"])
        add_ungrouped_hosts_for_tenants(batch_size)
        logger.info("*** Adding ungrouped hosts finished for all tenants. ***")
