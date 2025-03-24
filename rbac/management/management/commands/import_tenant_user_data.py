"""Import user data command."""

import logging

from django.core.management.base import BaseCommand
from management.management.commands.utils import download_data_from_S3, populate_tenant_user_data

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
FILE_NAME = "data_user.csv"


class Command(BaseCommand):
    """Command class for importing tenant and user data into database."""

    help = "Import tenant and user data into db"

    def add_arguments(self, parser):
        """Add arguments to command."""
        parser.add_argument("--skip_download", default="false", help="Skipping the download of file")
        parser.add_argument("--start_line", default=1, help="The line of records to start scanning")
        parser.add_argument("--batch_size", default=1000, help="The number of records to process as a batch")

    def handle(self, *args, **options):
        """Handle method for command."""
        if options["skip_download"].lower() == "false":
            logger.info("*** Downloading tenant and user data file... ***")
            download_data_from_S3(FILE_NAME)
            logger.info("*** Downloading completed. ***\n")
        logger.info("*** Populating tenant and user data... ***")
        start_line = int(options["start_line"])
        batch_size = int(options["batch_size"])
        populate_tenant_user_data(FILE_NAME, start_line=start_line, batch_size=batch_size)
        logger.info("*** Data population completed. ***")
