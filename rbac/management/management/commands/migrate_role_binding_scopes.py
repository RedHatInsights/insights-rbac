"""
Management command to migrate role binding scopes based on permission levels.

This command evaluates existing role binding mappings and updates their scope
(default workspace, root workspace, or tenant) based on the highest permission
level that the role contains.
"""

import logging

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from management.models import BindingMapping, Workspace
from management.permission_scope import (
    Scope,
    highest_scope_for_permissions,
    highest_scope_for_v2_permissions,
    v2_permissions_to_v1,
)
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    ReplicationEvent,
    ReplicationEventType,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Command class for migrating role binding scopes to use permission-based levels."""

    help = "Migrate existing role binding scopes based on permission levels"

    def handle(self, *args, **options):
        """Handle method for command."""
        logger.info("*** Starting role binding scope migration... ***")

        batch_size = 50  # Fixed batch size for safety

        # Process role binding scope migration
        self._migrate_role_binding_scopes(batch_size)
        logger.info("*** Role binding scope migration completed. ***")

    def _migrate_role_binding_scopes(self, batch_size):
        """Migrate role binding scopes based on permission levels."""
        # Get all workspace binding mappings
        all_bindings = (
            BindingMapping.objects.filter(resource_type_namespace="rbac", resource_type_name="workspace")
            .select_related("role", "role__tenant")
            .order_by("id")
        )

        total_bindings = all_bindings.count()
        logger.info(f"Found {total_bindings} workspace bindings to evaluate")

        if total_bindings == 0:
            logger.info("No workspace bindings found")
            return

        # Track migration statistics
        stats = {
            "evaluated": 0,
            "migrated_to_tenant": 0,
            "migrated_to_root": 0,
            "kept_default": 0,
            "errors": 0,
        }

        # Process bindings in batches
        for offset in range(0, total_bindings, batch_size):
            batch_bindings = list(all_bindings[offset : (offset + batch_size)])

            logger.info(
                f"Processing batch {offset // batch_size + 1}: {len(batch_bindings)} bindings "
                f"({offset + 1}-{offset + len(batch_bindings)} of {total_bindings})"
            )

            # Get unique tenants for this batch
            batch_tenants = {binding.role.tenant for binding in batch_bindings if binding.role}

            # Get default and root workspaces for this batch of tenants
            default_workspaces = {
                ws.tenant_id: str(ws.id)
                for ws in Workspace.objects.filter(type=Workspace.Types.DEFAULT, tenant__in=batch_tenants)
            }

            root_workspaces = {
                ws.tenant_id: str(ws.id)
                for ws in Workspace.objects.filter(type=Workspace.Types.ROOT, tenant__in=batch_tenants)
            }

            logger.info(
                f"  Found {len(default_workspaces)} default and {len(root_workspaces)} root workspaces "
                f"for {len(batch_tenants)} tenants in this batch"
            )

            for binding_mapping in batch_bindings:
                try:
                    result = self._migrate_binding_with_cache(binding_mapping, default_workspaces, root_workspaces)
                    stats["evaluated"] += 1
                    stats[result] += 1

                except Exception as e:
                    stats["errors"] += 1
                    logger.error(f"Error migrating binding {binding_mapping.id}: {str(e)}")

        # Print summary
        logger.info("=" * 50)
        logger.info("MIGRATION SUMMARY")
        logger.info("=" * 50)
        logger.info(f'Total evaluated: {stats["evaluated"]}')
        logger.info(f'Migrated to tenant: {stats["migrated_to_tenant"]}')
        logger.info(f'Migrated to root workspace: {stats["migrated_to_root"]}')
        logger.info(f'Kept default workspace: {stats["kept_default"]}')
        logger.info(f'Errors: {stats["errors"]}')

    def _migrate_binding_with_cache(
        self, binding_mapping: BindingMapping, default_workspaces: dict, root_workspaces: dict
    ) -> str:
        """
        Migrate a single binding mapping using cached workspace info.

        Args:
            binding_mapping: The BindingMapping to migrate
            default_workspaces: Dict of {tenant_id: default_workspace_id}
            root_workspaces: Dict of {tenant_id: root_workspace_id}

        Returns:
            str: One of 'migrated_to_tenant', 'migrated_to_root', 'kept_default', indicating the action taken
        """
        role = binding_mapping.role
        if not role:
            return "kept_default"

        tenant = role.tenant

        # Check if this binding is currently pointing to default workspace
        default_workspace_id = default_workspaces.get(tenant.id)
        if not default_workspace_id or str(binding_mapping.resource_id) != default_workspace_id:
            return "kept_default"  # Skip non-default workspace bindings

        # Get permissions based on role type
        if role.system:
            # System roles: get permissions from Access model
            v1_permissions = [access.permission.permission for access in role.access.all() if access.permission]
            if not v1_permissions:
                return "kept_default"
            highest_scope = highest_scope_for_permissions(v1_permissions)
        else:
            # Custom roles: get permissions from mappings
            v2_role_data = binding_mapping.mappings.get("role", {})
            v2_permissions = v2_role_data.get("permissions", [])
            if not v2_permissions:
                return "kept_default"
            highest_scope = highest_scope_for_v2_permissions(v2_permissions)

        # Determine new binding target
        new_resource_type_namespace = "rbac"
        new_resource_type_name = None
        new_resource_id = None
        migration_type = "kept_default"

        if highest_scope == Scope.TENANT:
            # Bind to tenant level
            new_resource_type_name = "tenant"
            new_resource_id = f"{settings.PRINCIPAL_USER_DOMAIN}/{tenant.org_id}"
            migration_type = "migrated_to_tenant"

        elif highest_scope == Scope.ROOT:
            # Bind to root workspace using cached data
            root_workspace_id = root_workspaces.get(tenant.id)
            if root_workspace_id:
                new_resource_type_name = "workspace"
                new_resource_id = root_workspace_id
                migration_type = "migrated_to_root"
            else:
                logger.warning(f"No root workspace found for tenant {tenant.org_id}")
                return "kept_default"
        else:
            return "kept_default"  # Keep default workspace (no change needed)

        # Log the migration
        if role.system:
            log_permissions = v1_permissions[:3]
        else:
            log_permissions = v2_permissions_to_v1(v2_permissions)[:3]

        logger.info(
            f'Role {role.id} ({role.name}): {migration_type.replace("_", " ").title()} '
            f'(permissions: {", ".join(log_permissions)}{"..." if len(log_permissions) > 3 else ""})'
        )

        # Perform the migration
        if new_resource_type_name and new_resource_id:
            with transaction.atomic():
                # Get existing tuples before modification
                relations_to_remove = list(binding_mapping.as_tuples())

                # Update the binding mapping
                binding_mapping.resource_type_namespace = new_resource_type_namespace
                binding_mapping.resource_type_name = new_resource_type_name
                binding_mapping.resource_id = new_resource_id
                binding_mapping.save(update_fields=["resource_type_namespace", "resource_type_name", "resource_id"])

                # Get new tuples after modification
                relations_to_add = list(binding_mapping.as_tuples())

                # Replicate the tuple changes
                replicator = OutboxReplicator()
                replicator.replicate(
                    ReplicationEvent(
                        event_type=ReplicationEventType.MIGRATE_SYSTEM_ROLE_ASSIGNMENT,
                        info={
                            "binding_mapping_id": binding_mapping.id,
                            "role_id": role.id,
                            "migration_type": migration_type,
                            "old_resource": f"rbac/workspace/{default_workspace_id}",
                            "new_resource": f"{new_resource_type_namespace}/{new_resource_type_name}/{new_resource_id}",
                        },
                        partition_key=PartitionKey.byEnvironment(),
                        add=relations_to_add,
                        remove=relations_to_remove,
                    )
                )

        return migration_type
