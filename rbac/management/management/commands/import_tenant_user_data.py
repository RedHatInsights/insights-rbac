"""Seeds command."""

import logging

from django.core.management.base import BaseCommand
from management.management.commands.utils import download_tenant_user_data, populate_tenant_user_data

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Command(BaseCommand):
    """Command class for importing tenant and user data into database."""

    help = "Import tenant and user data into db"

    def add_arguments(self, parser):
        """Add arguments to command."""
        parser.add_argument("--start_line", default=1, help="The line of records to start scanning")
        parser.add_argument("--batch_size", default=1000, help="The number of records to process as a batch")

    def handle(self, *args, **options):
        """Handle method for command."""
        logger.info("*** Downloading tenant and user data file... ***")
        download_tenant_user_data()
        logger.info("*** Importing completed. ***\n")
        logger.info("*** Populating tenant and user data... ***")
        start_line = int(options["start_line"])
        batch_size = int(options["batch_size"])
        populate_tenant_user_data(start_line=start_line, batch_size=batch_size)
        logger.info("*** Data population completed. ***")
