"""Management command to fix duplicate role binding UUIDs in TenantMapping."""

import itertools
import logging
import uuid

from django.conf import settings
from django.core.management import BaseCommand
from django.db import transaction
from management.tenant_mapping.model import TenantMapping

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Fix duplicate role binding UUIDs that were created when migration 0070 ran.

    Migration 0070 added 4 new UUID fields to existing TenantMapping rows, but Django
    called uuid.uuid4() once per field and applied the same value to all existing rows.
    This command generates unique UUIDs for each tenant that has the known duplicate UUIDs.
    """

    help = "Fix duplicate role binding UUIDs in TenantMapping table"

    # Known duplicate UUIDs from migration 0070
    STAGE_DUPLICATE_UUID = "0e0451d3-440f-404a-b8a8-a77811e40925"
    PROD_DUPLICATE_UUID = "b79d902b-02ac-4d59-b3b2-6321fd7d557c"

    def add_arguments(self, parser):
        """Add command arguments."""
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of TenantMapping records to process in each batch (default: 1000)",
        )

    def handle(self, *args, **options):
        """Execute the command."""
        batch_size = options["batch_size"]

        env_name = settings.ENV_NAME
        self.stdout.write(f"Environment: {env_name}")
        self.stdout.write("=" * 80)

        # Determine which UUID to filter by based on environment
        if env_name.lower() == "stage":
            target_uuid = self.STAGE_DUPLICATE_UUID
            self.stdout.write(f"STAGE environment detected. Fixing UUID: {target_uuid}")
        elif env_name.lower() == "prod":
            target_uuid = self.PROD_DUPLICATE_UUID
            self.stdout.write(f"PROD environment detected. Fixing UUID: {target_uuid}")
        else:
            self.stdout.write(
                self.style.ERROR(
                    f"Environment '{env_name}' is neither 'stage' nor 'prod'. "
                    "Cannot determine which duplicate UUID to fix."
                )
            )
            return

        # Build the queryset with the environment-specific UUID filter
        base_qs = TenantMapping.objects.filter(root_scope_default_role_binding_uuid=target_uuid)

        # Count total records to process (estimate for progress tracking)
        estimate = base_qs.count()
        self.stdout.write(f"\nEstimated {estimate} TenantMapping records to process")

        if estimate == 0:
            self.stdout.write(self.style.SUCCESS("No TenantMapping records found with duplicate UUID. Nothing to do."))
            return

        # Process in batches using iterator (streaming cursor) - matches bootstrap_tenants pattern
        # This is more efficient than OFFSET-based pagination for large datasets
        processed = 0
        updated = 0

        # Use iterator() for streaming and batched() for grouping (like bootstrap_tenants command)
        for raw_mappings in itertools.batched(base_qs.order_by("id").iterator(), batch_size):
            with transaction.atomic():
                # Lock the records we're about to update (like bootstrap_tenants does)
                mapping_ids = [m.id for m in raw_mappings]
                mappings = list(TenantMapping.objects.select_for_update().filter(id__in=mapping_ids))

                if not mappings:
                    continue

                batch_count = len(mappings)
                logger.info(f"Processing batch: {processed + 1}-{processed + batch_count} of ~{estimate}")
                self.stdout.write(f"Processing batch: {processed + 1}-{processed + batch_count} of ~{estimate}")

                # Update each mapping with new unique UUIDs
                for mapping in mappings:
                    mapping.root_scope_default_role_binding_uuid = uuid.uuid4()
                    mapping.root_scope_default_admin_role_binding_uuid = uuid.uuid4()
                    mapping.tenant_scope_default_admin_role_binding_uuid = uuid.uuid4()
                    mapping.tenant_scope_default_role_binding_uuid = uuid.uuid4()

                # Bulk update for efficiency
                TenantMapping.objects.bulk_update(
                    mappings,
                    [
                        "root_scope_default_role_binding_uuid",
                        "root_scope_default_admin_role_binding_uuid",
                        "tenant_scope_default_admin_role_binding_uuid",
                        "tenant_scope_default_role_binding_uuid",
                    ],
                )

                processed += batch_count
                updated += batch_count

                # Log progress
                if estimate > 0:
                    progress_pct = (processed / estimate) * 100
                    self.stdout.write(f"Progress: {processed}/{estimate} ({progress_pct:.1f}%)")

        # Final summary
        self.stdout.write(self.style.SUCCESS(f"Successfully updated {updated} TenantMapping records."))

        self.stdout.write("\nFields updated:")
        self.stdout.write("  - root_scope_default_role_binding_uuid")
        self.stdout.write("  - root_scope_default_admin_role_binding_uuid")
        self.stdout.write("  - tenant_scope_default_admin_role_binding_uuid")
        self.stdout.write("  - tenant_scope_default_role_binding_uuid")
