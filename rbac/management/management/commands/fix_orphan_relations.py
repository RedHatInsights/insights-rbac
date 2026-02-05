"""Command to fix orphan relations in all tenants."""

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
from django.db.models import Count, OuterRef, Subquery
from internal.migrations.remove_orphan_relations import cleanup_tenant_orphan_bindings
from management.models import Group, Role

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

        # This doesn't semantically affect the result, but operate on tenants that have groups and roles first because
        # (a) they are more likely to actually have issues that this script can fix, and (b) operating on them first
        # will bring up any issues/errors in the script earlier in the run.
        tenants_query = (
            Tenant.objects.exclude(tenant_name="public")
            .filter(org_id__isnull=False)
            .annotate(
                group_count=Count(Subquery(Group.objects.filter(tenant=OuterRef("pk")).values("pk"))),
                roles_count=Count(Subquery(Role.objects.filter(system=False, tenant=OuterRef("pk")).values("pk"))),
            )
            .order_by("-group_count", "-roles_count", "id")
        )

        success_count = 0
        failed_orgs = []

        for tenant in tenants_query.iterator():
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

        if len(failed_orgs) > 0:
            raise CommandError(
                f"Failed to remove orphan relations tenants with the following org_ids: {failed_orgs}", returncode=1
            )

        logger.info(f"Removed orphan relations for {success_count} tenants.")
