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
import concurrent.futures
import logging
import sys

from django.apps import AppConfig
from django.db import connections
from django.db.utils import OperationalError, ProgrammingError

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class ManagementConfig(AppConfig):
    """Management application configuration."""

    name = "management"

    def ready(self):
        """Determine if app is ready on application startup."""
        # Don't run on Django tab completion commands
        if "manage.py" in sys.argv[0] and "runserver" not in sys.argv:
            return
        try:
            self.role_seeding()
            self.group_seeding()
        except (OperationalError, ProgrammingError) as op_error:
            if "no such table" in str(op_error) or "does not exist" in str(op_error):
                # skip this if we haven't created tables yet.
                return
            else:
                logger.error("Error: %s.", op_error)

    def on_complete(self, future):
        """Explicitly close the connection for the thread."""
        connections.close_all()

    def role_seeding(self):  # pylint: disable=R0201
        """Update any roles at startup."""
        # noqa: E402 pylint: disable=C0413
        from api.models import Tenant
        from management.role.definer import seed_roles
        from rbac.settings import ROLE_SEEDING_ENABLED, MAX_SEED_THREADS

        if not ROLE_SEEDING_ENABLED:
            return

        logger.info("Start role seed changes check.")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SEED_THREADS) as executor:
                for tenant in list(Tenant.objects.all()):
                    if tenant.schema_name != "public":
                        logger.info("Checking for role seed changes for tenant %s.", tenant.schema_name)
                        future = executor.submit(seed_roles, tenant, update=True)
                        future.add_done_callback(self.on_complete)
                        logger.info("Completed role seed changes for tenant %s.", future.result().schema_name)
        except Exception as exc:
            logger.error("Error encountered during role seeding %s.", exc)

    def group_seeding(self):  # pylint: disable=R0201
        """Update platform group at startup."""
        # noqa: E402 pylint: disable=C0413
        from api.models import Tenant
        from management.group.definer import seed_group
        from rbac.settings import GROUP_SEEDING_ENABLED, MAX_SEED_THREADS

        if not GROUP_SEEDING_ENABLED:
            return

        logger.info("Start goup seed changes check.")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SEED_THREADS) as executor:
                for tenant in list(Tenant.objects.all()):
                    if tenant.schema_name != "public":
                        logger.info("Checking for group seed changes for tenant %s.", tenant.schema_name)
                        future = executor.submit(seed_group, tenant)
                        future.add_done_callback(self.on_complete)
                        logger.info("Completed group seed changes for tenant %s.", future.result().schema_name)
        except Exception as exc:
            logger.error("Error encountered during group seeding %s.", exc)
