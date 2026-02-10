"""Command to fix orphan relations in all tenants."""

import datetime

#
# Copyright 2026 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
import logging

from django.core.management import BaseCommand, CommandError
from internal.migrations.remove_orphan_relations import cleanup_tenant_orphan_bindings

from api.models import Tenant

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Command to fix orphan relations in all tenants."""

    help = """
    Remove orphan relations from all tenants.

    This currently handles:
    * Orphaned relations from role bindings.
    * Orphaned parent relations from deleted workspaces.
    * Incorrect parent relations from existing workspaces.
    """

    def add_arguments(self, parser):
        """Add arguments for the command."""
        parser.add_argument(
            "--all",
            action="store_true",
            help="remove orphan relations for all tenants",
        )

    def handle(self, *args, **options):
        """Execute the command."""
        if not options["all"]:
            raise CommandError(
                "Must pass --all in order to remove orphan relations for all tenants. "
                "(This is for forwards compatibility purposes.)",
                returncode=2,
            )

        tenants_query = Tenant.objects.exclude(tenant_name="public").filter(org_id__isnull=False)

        success_count = 0
        failed_orgs = []

        tenant_count = tenants_query.count()

        for index, tenant in enumerate(tenants_query.iterator()):
            start_time = datetime.datetime.now(datetime.timezone.utc)

            print(
                f"Beginning migration of tenant {index + 1}/{tenant_count} with org_id={tenant.org_id!r} "
                f"at {start_time}"
            )

            try:
                result = cleanup_tenant_orphan_bindings(org_id=tenant.org_id)

                if "error" in result:
                    error = result["error"]
                    logger.error(
                        f"Failed to remove orphan relations for tenant with org_id={tenant.org_id!r}: {error}"
                    )
                    failed_orgs.append(tenant.org_id)
                    continue

                success_count += 1
            except Exception as e:
                logger.error(f"Failed to remove orphan relations for tenant with org_id={tenant.org_id!r}", exc_info=e)
                failed_orgs.append(tenant.org_id)

            end_time = datetime.datetime.now(datetime.timezone.utc)

            print(
                f"Done with migration of tenant with org_id={tenant.org_id!r} at {end_time}; "
                f"took {end_time - start_time}."
            )

        if len(failed_orgs) > 0:
            raise CommandError(
                f"Failed to remove orphan relations tenants with the following org_ids: {failed_orgs}", returncode=1
            )

        logger.info(f"Removed orphan relations for {success_count} tenants.")
