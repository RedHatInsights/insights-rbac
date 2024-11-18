"""Import user data command."""

import logging

from django.core.management.base import BaseCommand
from management.management.commands.utils import download_data_from_S3, populate_service_account_data

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
FILE_NAME = "service_account_user_id_mapping.csv"


class Command(BaseCommand):
    """Command class for importing tenant and user data into database."""

    help = "Import tenant and user data into db"

    def handle(self, *args, **options):
        """Handle method for command."""
        logger.info("*** Downloading service account data file... ***")
        download_data_from_S3(FILE_NAME)
        logger.info("*** Downloading completed. ***\n")
        logger.info("*** Populating service account data... ***")
        populate_service_account_data(FILE_NAME)
        logger.info("*** Data population completed. ***")
