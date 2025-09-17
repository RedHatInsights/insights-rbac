"""Command to create or retrieve the three parent roles for org level permissions."""

import logging

from django.core.management.base import BaseCommand
from management.management.commands.utils import _get_or_create_parent_roles_for_org_level_permissions

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Command(BaseCommand):
    """Create or retrieve the three parent roles for org-level permissions (Root, Default, Org)."""

    def handle(self, *args, **options):
        """Handle method for command."""
        logger.info("🔄 Running org_level_parent_roles initialization...")

        try:
            parent_roles = _get_or_create_parent_roles_for_org_level_permissions()
            logger.info("✅ Org-level parent roles initialized or retrieved successfully.")
            for name, role in parent_roles.items():
                logger.info(f"   • {name} ")
        except Exception as e:
            logger.error(f"❌ Error initializing org-level parent roles: {e}")
            raise e
