"""Seeds command."""
import logging

from django.core.management.base import BaseCommand
from migration_tool.migrate import migrate_data

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Command(BaseCommand):
    """Command class for migrating v1 RBAC to v2 relations."""

    help = "Migrates v1 RBAC data to v2 relations"

    def add_arguments(self, parser):
        """Add arguments to command."""
        parser.add_argument("--org-list", nargs="+", default=[])
        parser.add_argument("--exclude-apps", nargs="+", default=[])
        parser.add_argument("--write-to-db", default=False, action="store_true")

    def handle(self, *args, **options):
        """Handle method for command."""
        logger.info("*** Migrating v1 RBAC data to v2 relations... ***")
        kwargs = {
            "exclude_apps": options["exclude_apps"],
            "orgs": options["org_list"],
            "write_db": options["write_to_db"],
        }
        migrate_data(**kwargs)
        logger.info("*** Migration completed. ***\n")
