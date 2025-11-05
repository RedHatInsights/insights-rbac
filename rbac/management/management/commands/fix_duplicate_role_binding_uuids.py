"""Management command to fix duplicate role binding UUIDs in TenantMapping."""

import itertools
import logging
import uuid

from django.core.management import BaseCommand
from django.db import transaction
from django.db.models import Count
from kessel.relations.v1beta1.common_pb2 import Relationship
from management.group.platform import GlobalPolicyIdService
from management.permission.scope_service import Scope, TenantScopeResourcesCache
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.tenant_mapping.model import DefaultAccessType, TenantMapping
from management.tenant_service.relations import default_role_binding_tuples
from management.tenant_service.v2 import try_lock_tenants_for_bootstrap

from api.models import Tenant

logger = logging.getLogger(__name__)

_duplicated_fields = [
    "root_scope_default_role_binding_uuid",
    "root_scope_default_admin_role_binding_uuid",
    "tenant_scope_default_admin_role_binding_uuid",
    "tenant_scope_default_role_binding_uuid",
]

_relations_limit = 1000


def _replicate_removed_batches(replicator: RelationReplicator, to_remove_batches: list[list[Relationship]]):
    """Replicate the provided relations while grouping sublists but without splitting any sublist between events."""

    def _do_remove(relations: list[Relationship]):
        if not relations:
            return

        replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.DUPLICATE_BINDING_CLEANUP,
                partition_key=PartitionKey.byEnvironment(),
                remove=relations,
            )
        )

    collected = []

    for batch in to_remove_batches:
        if len(collected) + len(batch) > _relations_limit:
            _do_remove(collected)
            collected = []

        collected.extend(batch)

    _do_remove(collected)


class Command(BaseCommand):
    """
    Fix duplicate role binding UUIDs that were created when migration 0070 ran.

    Migration 0070 added 4 new UUID fields to existing TenantMapping rows, but Django
    called uuid.uuid4() once per field and applied the same value to all existing rows.
    This command generates unique UUIDs for each tenant that has the known duplicate UUIDs.
    """

    help = "Fix duplicate role binding UUIDs in TenantMapping table"

    def add_arguments(self, parser):
        """Add command arguments."""
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of TenantMapping records to process in each batch (default: 1000)",
        )

        parser.add_argument(
            "--replicate-removal",
            action="store_true",
            help="Remove the relevant access bindings from relations",
        )

    def _handle_field_duplicates(self, field: str, replicate_removal: bool, batch_size: int):
        duplicate_values = [
            m[field]
            for m in TenantMapping.objects.all()
            .values(field)
            .annotate(field_count=Count(field))
            .filter(field_count__gt=1)
        ]

        self.stderr.write(f"Duplicate values for {field}: {duplicate_values}")

        tenant_query = Tenant.objects.select_for_update().filter(
            tenant_mapping__in=TenantMapping.objects.filter(**{f"{field}__in": duplicate_values})
        )

        # Count total records to process (estimate for progress tracking)
        estimate = tenant_query.count()
        self.stderr.write(f"Estimated {estimate} TenantMapping records to process")

        if estimate == 0:
            self.stderr.write(
                self.style.SUCCESS(
                    f"No (remaining) TenantMapping records found with duplicate UUID in field {field}. Nothing to do."
                )
            )

            return

        # Process in batches using iterator (streaming cursor) - matches bootstrap_tenants pattern
        # This is more efficient than OFFSET-based pagination for large datasets
        processed = 0
        updated = 0

        replicator = OutboxReplicator()
        policy_service = GlobalPolicyIdService()

        # Use iterator() for streaming and batched() for grouping (like bootstrap_tenants command)
        for tenants in itertools.batched(tenant_query.order_by("id").iterator(), batch_size):
            with transaction.atomic():
                # We need to take the full bootstrap lock to prevent concurrent custom default group creation/removal.
                lock_results = try_lock_tenants_for_bootstrap(tenants)

                if replicate_removal:
                    scope_resources_cache = TenantScopeResourcesCache.for_tenants(tenants)

                updated_mappings: list[TenantMapping] = []
                to_remove_batches: list[list[Relationship]] = []

                for tenant in tenants:
                    lock_result = lock_results[tenant]
                    assert lock_result is not None, f"Tenant {tenant} is known to be bootstrapped."

                    mapping = lock_result.tenant_mapping

                    if replicate_removal:
                        resources = scope_resources_cache.resources_for(tenant)

                        def relations_for(access_type: DefaultAccessType):
                            # Only the ROOT and TENANT scope bindings are affected.
                            return default_role_binding_tuples(
                                tenant_mapping=mapping,
                                target_resources=resources,
                                access_type=access_type,
                                policy_service=policy_service,
                                target_scopes=[Scope.ROOT, Scope.TENANT],
                            )

                        to_remove_batches.append(
                            [*relations_for(DefaultAccessType.USER), *relations_for(DefaultAccessType.ADMIN)]
                        )

                    mapping.root_scope_default_role_binding_uuid = uuid.uuid4()
                    mapping.root_scope_default_admin_role_binding_uuid = uuid.uuid4()
                    mapping.tenant_scope_default_admin_role_binding_uuid = uuid.uuid4()
                    mapping.tenant_scope_default_role_binding_uuid = uuid.uuid4()

                    updated_mappings.append(mapping)

                batch_count = len(tenants)
                logger.info(f"Processing batch: {processed + 1}-{processed + batch_count} of ~{estimate}")
                self.stderr.write(f"Processing batch: {processed + 1}-{processed + batch_count} of ~{estimate}")

                # Bulk update for efficiency
                TenantMapping.objects.bulk_update(updated_mappings, _duplicated_fields)

                if to_remove_batches:
                    _replicate_removed_batches(replicator=replicator, to_remove_batches=to_remove_batches)

                processed += batch_count
                updated += batch_count

                # Log progress
                if estimate > 0:
                    progress_pct = (processed / estimate) * 100
                    self.stderr.write(f"Progress: {processed}/{estimate} ({progress_pct:.1f}%)")

        # Final summary
        self.stderr.write(self.style.SUCCESS(f"Successfully updated {updated} TenantMapping records."))

    def handle(self, *args, **options):
        """Execute the command."""
        batch_size = options["batch_size"]
        replicate_removal = options["replicate_removal"]

        self.stderr.write(f"Running with {batch_size=}, {replicate_removal=}")
        self.stderr.write("=" * 80)

        for field in _duplicated_fields:
            self.stderr.write(f"Removing duplicates for field {field}.")
            self._handle_field_duplicates(field=field, replicate_removal=replicate_removal, batch_size=batch_size)

            self.stderr.write()

        self.stderr.write("\nFields updated:")

        for field in _duplicated_fields:
            self.stderr.write(f"  - {field}")
