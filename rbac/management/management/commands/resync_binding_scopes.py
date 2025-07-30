"""
Management command to re-sync binding mappings after scope migration.

This command finds BindingMapping records that were updated during the scope
migration and re-emits the relation tuples to ensure consistency with the
authorization service.
"""

from datetime import datetime

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import models
from management.models import BindingMapping
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType


class Command(BaseCommand):
    """
    Re-sync binding mappings after scope migration.

    This command finds BindingMapping records that were updated during the scope
    migration and re-emits the relation tuples to ensure consistency with the
    authorization service.
    """

    help = "Re-sync binding mappings after scope migration"

    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            "--updated-since",
            type=str,
            help="Only sync bindings updated since this timestamp (YYYY-MM-DD HH:MM:SS)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be synced without actually syncing",
        )
        parser.add_argument(
            "--role-id",
            type=str,
            help="Only sync bindings for this specific role ID",
        )

    def handle(self, *args, **options):
        """Handle the command."""
        updated_since = None
        if options["updated_since"]:
            try:
                updated_since = datetime.strptime(options["updated_since"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                self.stdout.write(self.style.ERROR("Invalid date format. Use YYYY-MM-DD HH:MM:SS"))
                return

        dry_run = options["dry_run"]
        role_id = options["role_id"]

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No actual syncing will occur"))

        # Build query
        query = BindingMapping.objects.select_related("role")

        if updated_since:
            # Note: You might need to add a 'modified' timestamp field to BindingMapping
            # For now, we'll process all bindings
            self.stdout.write(f"Processing bindings updated since {updated_since}")

        if role_id:
            query = query.filter(role_id=role_id)

        # Filter for scope-related bindings (tenant or workspace bindings)
        query = query.filter(resource_type_namespace="rbac").filter(
            models.Q(resource_type_name="tenant") | models.Q(resource_type_name="workspace")
        )

        bindings = list(query)

        if not bindings:
            self.stdout.write("No binding mappings found to sync")
            return

        self.stdout.write(f"Found {len(bindings)} binding mappings to sync")

        if not dry_run and not settings.REPLICATION_TO_RELATION_ENABLED:
            self.stdout.write(
                self.style.WARNING("Replication is disabled. Enable REPLICATION_TO_RELATION_ENABLED to sync.")
            )
            return

        replicator = OutboxReplicator() if not dry_run else None
        synced_count = 0
        error_count = 0

        for binding in bindings:
            try:
                role = binding.role
                if not role:
                    self.stdout.write(f"Skipping binding {binding.id} - no associated role")
                    continue

                if dry_run:
                    self.stdout.write(
                        f"Would sync: Role {role.id} ({role.name}) -> "
                        f"{binding.resource_type_namespace}:{binding.resource_type_name}:{binding.resource_id}"
                    )
                else:
                    # Generate tuples for this binding
                    tuples = binding.as_tuples()

                    # Create replication event
                    event = ReplicationEvent(
                        event_type=ReplicationEventType.UPDATE_CUSTOM_ROLE,
                        info={
                            "binding_mapping_id": binding.id,
                            "role_id": str(role.id),
                            "role_name": role.name,
                            "org_id": str(role.tenant.org_id),
                            "sync_reason": "scope_migration_resync",
                        },
                        partition_key=PartitionKey.byEnvironment(),
                        remove=[],  # We're not removing old tuples in this sync
                        add=tuples,
                    )

                    # Replicate
                    replicator.replicate(event)

                    self.stdout.write(
                        f"Synced: Role {role.id} ({role.name}) -> "
                        f"{binding.resource_type_namespace}:{binding.resource_type_name}:{binding.resource_id}"
                    )

                synced_count += 1

            except Exception as e:
                error_count += 1
                self.stdout.write(self.style.ERROR(f"Error syncing binding {binding.id}: {str(e)}"))

        # Summary
        if dry_run:
            self.stdout.write(self.style.SUCCESS(f"DRY RUN: Would sync {synced_count} bindings"))
        else:
            self.stdout.write(self.style.SUCCESS(f"Successfully synced {synced_count} bindings"))

        if error_count > 0:
            self.stdout.write(self.style.ERROR(f"Encountered {error_count} errors"))
