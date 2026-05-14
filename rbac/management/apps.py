#
# Copyright 2019 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Management application configuration module."""

import logging
import signal
import sys

from django.apps import AppConfig
from django.conf import settings
from django.db.utils import OperationalError, ProgrammingError
from management.seeds import group_seeding, permission_seeding, role_seeding

from rbac.settings import (
    GROUP_SEEDING_ENABLED,
    PERMISSION_SEEDING_ENABLED,
    ROLE_SEEDING_ENABLED,
)

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def _shutdown_handler(signum, frame):
    """Handle graceful shutdown signals - SEC-MON-REQ-1 compliance (#5 process_status)."""
    signal_name = (
        "SIGTERM" if signum == signal.SIGTERM else "SIGINT" if signum == signal.SIGINT else f"Signal {signum}"
    )
    logger.info(
        "RBAC service shutting down",
        extra={
            "event": "shutdown",
            "signal": signal_name,
            "version": settings.GIT_COMMIT,
        },
    )


class ManagementConfig(AppConfig):
    """Management application configuration."""

    name = "management"

    def ready(self):
        """Determine if app is ready on application startup."""
        # Don't run on Django tab completion commands
        if "manage.py" in sys.argv[0] and "runserver" not in sys.argv:
            return

        # Register shutdown signal handlers - SEC-MON-REQ-1 compliance (#5 process_status)
        signal.signal(signal.SIGTERM, _shutdown_handler)
        signal.signal(signal.SIGINT, _shutdown_handler)

        # Log startup configuration - SEC-MON-REQ-1 compliance (#5 process_status)
        logger.info(
            "RBAC service starting",
            extra={
                "event": "startup",
                "version": settings.GIT_COMMIT,
                "config": {
                    "v2_apis_enabled": settings.V2_APIS_ENABLED,
                    "v2_edit_api_enabled": settings.V2_EDIT_API_ENABLED,
                    "workspace_access_check_v2_enabled": settings.WORKSPACE_ACCESS_CHECK_V2_ENABLED,
                    "kessel_relations_server": settings.RELATION_API_SERVER,
                    "kessel_inventory_server": settings.INVENTORY_API_SERVER,
                    "kafka_enabled": settings.KAFKA_ENABLED,
                    "replication_to_relation_enabled": settings.REPLICATION_TO_RELATION_ENABLED,
                    "read_only_api_mode": settings.READ_ONLY_API_MODE,
                    "clowder_enabled": settings.CLOWDER_ENABLED,
                    "env_name": settings.ENV_NAME,
                },
            },
        )

        try:
            if PERMISSION_SEEDING_ENABLED:
                permission_seeding()
            if ROLE_SEEDING_ENABLED:
                role_seeding()
            if GROUP_SEEDING_ENABLED:
                group_seeding()

        except (OperationalError, ProgrammingError) as op_error:
            if "no such table" in str(op_error) or "does not exist" in str(op_error):
                # skip this if we haven't created tables yet.
                return
            else:
                logger.error("Error: %s.", op_error)
