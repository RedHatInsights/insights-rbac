"""Command to fix orphan relations in all tenants."""

import dataclasses

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
import datetime
import enum
import logging
from collections.abc import Iterable

from django.core.management import BaseCommand, CommandError
from django.db.models import Q, QuerySet
from internal.migrations.remove_orphan_relations import cleanup_tenant_orphan_bindings
from management.group.model import Group
from management.role.model import Role
from management.workspace.model import Workspace

from api.models import Tenant

logger = logging.getLogger(__name__)

_abort_threshold = 10


class _StopReason(enum.Enum):
    SUCCESS = "success"
    ABORTED = "aborted"


@dataclasses.dataclass
class _MigrateResult:
    stop_reason: _StopReason
    success_count: int
    modified_count: int
    failed_orgs: frozenset[str]


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

    def _base_query(self) -> QuerySet:
        return Tenant.objects.exclude(tenant_name="public").filter(org_id__isnull=False)

    def _prioritized_tenants(self) -> Iterable[Tenant]:
        # We unfortunately must look through every tenant, since any tenant could have previously had an entity in
        # it, replicated it incorrectly, and later had the entity deleted. Since this is rather unlikely (a tenant that
        # has had something deleted has at some point been used, and thus has probably not been entirely cleared),
        # we prioritize any tenants that still have at least one thing in them over any tenants that don't.
        base = self._base_query()

        interesting_tenants = base.filter(
            Q(id__in=(Group.objects.all().values_list("tenant_id", flat=True)))
            | Q(id__in=(Role.objects.all().values_list("tenant_id", flat=True)))
            | Q(id__in=(Workspace.objects.filter(type=Workspace.Types.STANDARD).values_list("tenant_id", flat=True)))
        ).distinct()

        logger.info(f"About to load ~{interesting_tenants.count()} with an extant role, group, or workspace.")

        seen = set()

        for tenant in interesting_tenants.iterator():
            seen.add(tenant.pk)
            yield tenant

        logger.info(f"Yielded a total of {len(seen)} tenants with an extant role, group, or workspace.")

        yield from base.exclude(pk__in=seen).distinct().iterator()

    @staticmethod
    def _try_migrate(tenants: Iterable[Tenant], estimated_count: int) -> _MigrateResult:
        stop_reason = _StopReason.SUCCESS

        success_count = 0
        modified_count = 0
        failed_orgs = []

        for index, tenant in enumerate(tenants):
            start_time = datetime.datetime.now(datetime.timezone.utc)
            modified = False
            failed = False

            logger.info(
                f"Beginning migration of tenant {index + 1}/~{estimated_count} with org_id={tenant.org_id!r} "
                f"at {start_time}"
            )

            try:
                result = cleanup_tenant_orphan_bindings(org_id=tenant.org_id)

                if "error" in result:
                    error = result["error"]
                    logger.error(
                        f"Failed to remove orphan relations for tenant with org_id={tenant.org_id!r}: {error}"
                    )
                    failed = True

                if result["cleanup"]["relations_removed_count"] > 0:
                    modified = True
            except Exception as e:
                logger.error(f"Failed to remove orphan relations for tenant with org_id={tenant.org_id!r}", exc_info=e)
                failed = True

            end_time = datetime.datetime.now(datetime.timezone.utc)

            if failed:
                failed_orgs.append(tenant.org_id)

                logger.info(
                    f"Failed migration of tenant with org_id={tenant.org_id!r} at {end_time}; "
                    f"took {end_time - start_time}."
                )
            else:
                logger.info(
                    f"Done with migration of tenant with org_id={tenant.org_id!r} at {end_time}; "
                    f"modified={'true' if modified else 'false'}; took {end_time - start_time}."
                )

                success_count += 1

                if modified:
                    modified_count += 1

            if len(failed_orgs) >= _abort_threshold:
                stop_reason = _StopReason.ABORTED
                logger.error(f"Aborting after {_abort_threshold} tenants failed.")
                break

        return _MigrateResult(
            stop_reason=stop_reason,
            success_count=success_count,
            modified_count=modified_count,
            failed_orgs=frozenset(failed_orgs),
        )

    def handle(self, *args, **options):
        """Execute the command."""
        if not options["all"]:
            raise CommandError(
                "Must pass --all in order to remove orphan relations for all tenants. "
                "(This is for forwards compatibility purposes.)",
                returncode=2,
            )

        tenant_count = self._base_query().count()
        logger.info(f"About to remove orphan relations for ~{tenant_count} tenants.")

        result = self._try_migrate(tenants=self._prioritized_tenants(), estimated_count=tenant_count)

        logger.info(
            f"Successfully removed orphan relations for {result.success_count} tenants, "
            f"of which {result.modified_count} were modified."
        )

        if len(result.failed_orgs) > 0:
            raise CommandError(
                f"Failed to remove orphan relations tenants with the following org_ids: {result.failed_orgs}",
                returncode=1,
            )

        if result.stop_reason != _StopReason.SUCCESS:
            raise CommandError(f"Stopped for a reason other than success: {result.stop_reason.name}", returncode=1)
