"""Command to handle tenant bootstrapping."""

import enum
import logging

from django.core.management import BaseCommand, CommandError
from django.db import transaction
from django.db.models import QuerySet
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.tenant_service import V2TenantBootstrapService
from management.tenant_service.tenant_service import BootstrappedTenant

from api.models import Tenant


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class _BootstrapError(enum.IntEnum):
    NO_SUCH_TENANT = 1
    FAILED = 2


def _bootstrap_with_retry(
    bootstrap_service: V2TenantBootstrapService,
    raw_tenant: Tenant,
    force: bool,
) -> BootstrappedTenant | _BootstrapError:
    max_attempts = 5

    for attempt in range(max_attempts):
        with transaction.atomic():
            tenant = Tenant.objects.select_for_update().filter(pk=raw_tenant.pk).first()

            if tenant is None:
                logger.info(f"Tenant (pk={raw_tenant.pk!r}) no longer exists; not bootstrapping.")
                return _BootstrapError.NO_SUCH_TENANT

            tenant_desc = f"(pk={tenant.pk!r}, org_id={tenant.org_id!r})"

            try:
                logger.info(f"Bootstrapping tenant {tenant_desc}, attempt {attempt + 1}/{max_attempts}...")
                bootstrapped = bootstrap_service.bootstrap_tenant(tenant, force=force)

                logger.info(f"Successfully bootstrapped tenant {tenant_desc}.")
                return bootstrapped
            except Exception as e:
                logger.error(f"Failed to bootstrap tenant {tenant_desc}!", exc_info=e)

    logger.error(f"Could not bootstrap tenant (pk={raw_tenant.pk!r}) after {max_attempts} attempts.")
    return _BootstrapError.FAILED


class Command(BaseCommand):
    """Command for manually bootstrapping tenants and re-replicating existing bootstraps."""

    help = "Bootstrap tenants or re-replicate existing tenant bootstraps."

    def add_arguments(self, parser):
        """Parse command arguments."""
        parser.add_argument(
            "--all",
            action="store_true",
            help="bootstrap all tenants",
        )

        parser.add_argument(
            "--org-id",
            action="append",
            default=[],
            help="bootstrap tenant with specific org ID (repeatable)",
        )

        parser.add_argument(
            "--force",
            action="store_true",
            help="re-replicate bootstrap relations for bootstrapped tenants",
        )

    def handle(self, **options):
        """Run the command."""
        use_all = options["all"]

        requested_org_ids: set[str] = set(options["org_id"])
        use_org_ids = bool(requested_org_ids)

        if (not use_all and not use_org_ids) or (use_all and use_org_ids):
            raise CommandError(
                "Must either specify --all to bootstrap all tenants or use --org-id to "
                "specify one or more tenants to bootstrap."
            )

        if use_all:
            assert not use_org_ids
            logger.info("Bootstrap of all tenants requested.")
            base_query: QuerySet = Tenant.objects.all()
        else:
            assert use_org_ids
            logger.info(f"Bootstrapping of the tenants with the following org IDs requested: {requested_org_ids}")
            base_query: QuerySet = Tenant.objects.filter(org_id__in=requested_org_ids)

        force = options["force"]
        bootstrap_service = V2TenantBootstrapService(replicator=OutboxReplicator())

        query = base_query.exclude(tenant_name="public")
        estimate = query.count()

        logger.info(f"About to bootstrap an estimated {estimate} tenants...")

        successful_org_ids = set[str]()  # Only populated if use_org_ids is true.
        missing_org_ids = set[str]()
        failed_org_ids = set[str]()

        # These are "raw" because we haven't locked anything, and the tenant could vanish out from under us.
        for index, raw_tenant in enumerate(query.iterator()):
            logger.info(f"Bootstrapping tenant {index + 1}/{estimate}...")

            result = _bootstrap_with_retry(
                bootstrap_service=bootstrap_service,
                raw_tenant=raw_tenant,
                force=force,
            )

            if isinstance(result, BootstrappedTenant):
                if use_org_ids:
                    successful_org_ids.add(result.tenant.org_id)
            else:
                if result == _BootstrapError.NO_SUCH_TENANT:
                    missing_org_ids.add(raw_tenant.org_id)
                elif result == _BootstrapError.FAILED:
                    failed_org_ids.add(raw_tenant.org_id)
                else:
                    raise ValueError(f"Unexpected result: {result}")

        if missing_org_ids:
            logger.warning(
                f"The following org IDs were found but then disappeared before they could be bootstrapped: "
                f"{missing_org_ids}"
            )

        # Always exit with abnormal status if we failed to bootstrap a tenant.
        if failed_org_ids:
            failed_message = f"The following org IDs could not be bootstrapped: {failed_org_ids}"
            logger.warning(failed_message)
            raise CommandError(failed_message, returncode=1)

        if use_org_ids and (successful_org_ids != requested_org_ids):
            not_found = requested_org_ids.difference(successful_org_ids)

            raise CommandError(
                f"The following org IDs were requested to be bootstrapped but were not found: {not_found}",
                returncode=1,
            )
