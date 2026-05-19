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
"""API application configuration module."""

import logging
import sys

from django.apps import AppConfig

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class ApiConfig(AppConfig):
    """API application configuration."""

    name = "api"

    def ready(self):
        """Log startup configuration when Django app is ready."""
        # Only log on main process, not during migrations or management commands
        # Skip during test runs as well
        if any(arg in sys.argv for arg in ["migrate", "makemigrations", "test", "collectstatic"]):
            return

        # Only log once (Django calls ready() multiple times in some configurations)
        if hasattr(self, "_startup_logged"):
            return
        self._startup_logged = True

        from django.conf import settings

        # Service startup - SEC-MON-REQ-1 compliance (#5 process_status)
        logger.info(
            "RBAC service starting",
            extra={
                "event": "startup",
                "version": settings.GIT_COMMIT,
                "config": {
                    "log_level": settings.RBAC_LOGGING_LEVEL,
                    "django_debug": settings.DEBUG,
                    "v2_apis_enabled": getattr(settings, "V2_APIS_ENABLED", False),
                    "kessel_relations_enabled": getattr(settings, "KESSEL_RELATIONS_ENABLED", False),
                    "database_engine": settings.DATABASES.get("default", {}).get("ENGINE", "unknown"),
                    # DO NOT LOG: DATABASE_PASSWORD, SECRET_KEY, PSK values, API keys
                },
                "outcome": "success",
            },
        )
