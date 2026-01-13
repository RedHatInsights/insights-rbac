#
# Copyright 2025 Red Hat, Inc.
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
"""Management command to populate existing tenants with default role bindings."""
import itertools
import logging

from django.core.management.base import BaseCommand
from django.db import transaction
from management.permission.scope_service import TenantScopeResources
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.tenant_mapping.model import DefaultAccessType
from management.tenant_service.v2 import V2TenantBootstrapService

from api.models import Tenant

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Command to populate existing tenants with default role bindings."""

    help = "Populate existing tenants with default role bindings"

    def add_arguments(self, parser):
        """Add arguments to command."""
        parser.add_argument(
            "--tenant",
            type=str,
            help="Specific tenant org_id to process (if not provided, processes all tenants)",
        )

    def handle(self, *args, **options):
        """Handle method for command."""
        tenant_org_id = options.get("tenant")

        if tenant_org_id:
            try:
                query = Tenant.objects.filter(org_id=tenant_org_id)
                total_tenants = 1
            except Tenant.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"Tenant {tenant_org_id} not found"))
                return
        else:
            query = Tenant.objects.exclude(tenant_name="public").filter(ready=True)
            total_tenants = query.count()

        self.stdout.write(f"Processing {total_tenants} tenant(s)...")

        processed = 0
        errors = 0
        bootstrap_service = V2TenantBootstrapService(OutboxReplicator())

        # Process tenants in batches using iterator to avoid loading all into memory
        batch_size = 50
        tenants_seen = 0

        for raw_tenants in itertools.batched(query.iterator(), batch_size):
            # Collect tenants with mappings for this batch
            tenants_with_mappings = [(tenant, tenant.tenant_mapping) for tenant in raw_tenants]

            if not tenants_with_mappings:
                tenants_seen += len(raw_tenants)
                continue

            batch_num = (tenants_seen // batch_size) + 1
            self.stdout.write(
                f"\nProcessing batch {batch_num} "
                f"({tenants_seen + 1}-{tenants_seen + len(tenants_with_mappings)} of {total_tenants} tenants)..."
            )

            try:
                with transaction.atomic():
                    bootstrap_service._bulk_create_default_role_bindings(tenants_with_mappings)
                processed += len(tenants_with_mappings)
                self.stdout.write(
                    self.style.SUCCESS(f"  Successfully processed {len(tenants_with_mappings)} tenant(s)")
                )
            except Exception as e:
                errors += len(tenants_with_mappings)
                self.stdout.write(self.style.ERROR(f"  Error processing batch {batch_num}: {e}"))
                logger.exception(f"Error processing batch {batch_num}")
                # Fall back to individual processing for this batch
                for tenant, mapping in tenants_with_mappings:
                    try:
                        scope_resources = TenantScopeResources.for_tenant(tenant)
                        with transaction.atomic():
                            bootstrap_service._create_default_role_bindings(
                                tenant=tenant,
                                mapping=mapping,
                                scope_resources=scope_resources,
                                access_type=DefaultAccessType.USER,
                            )
                            bootstrap_service._create_default_role_bindings(
                                tenant=tenant,
                                mapping=mapping,
                                scope_resources=scope_resources,
                                access_type=DefaultAccessType.ADMIN,
                            )
                        processed += 1
                        errors -= 1  # Adjust error count since we processed individually
                    except Exception as individual_error:
                        self.stdout.write(
                            self.style.ERROR(f"  Error processing tenant {tenant.org_id}: {individual_error}")
                        )
                        logger.exception(f"Error populating role bindings for tenant {tenant.org_id}")

            tenants_seen += len(raw_tenants)

        self.stdout.write(f"\nProcessed {processed} tenant(s), {errors} error(s)")
