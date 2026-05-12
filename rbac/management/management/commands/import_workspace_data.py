"""Import user data command."""

import logging

from django.core.management.base import BaseCommand
from management.management.commands.utils import download_data_from_S3, populate_workspace_data

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
FILE_NAME = "groups_data.csv"


class Command(BaseCommand):
    """Command class for importing tenant and user data into database."""

    help = "Import tenant and user data into db"

    def handle(self, *args, **options):
        """Handle method for command."""
        logger.info("*** Downloading workspace data file... ***")
        download_data_from_S3(FILE_NAME)
        logger.info("*** Downloading completed. ***\n")
        logger.info("*** Processing workspace data file... ***")
        populate_workspace_data(FILE_NAME)
        logger.info("*** Data population completed. ***")
