"""
Management command to migrate role binding scopes based on permission levels.

This command evaluates existing role binding mappings and updates their scope
(default workspace, root workspace, or tenant) based on the highest permission
level that the role contains.
"""

import logging

from django.core.management.base import BaseCommand
from django.db import transaction
from management.models import BindingMapping, Workspace
from management.permission_scope import _implicit_resource_service as permission_service
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    ReplicationEvent,
    ReplicationEventType,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Command class for migrating role binding scopes to use permission levels."""

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
        is_system_role = role.system
        if is_system_role:
            v1_permissions = [a.permission.permission for a in role.access.all() if a.permission]
            if not v1_permissions:
                return "kept_default"
            permissions_for_scope = v1_permissions
        else:
            # Custom roles: get permissions from mappings
            v2_permissions = list(self._collect_v2_permissions_from_mappings(binding_mapping.mappings))
            if not v2_permissions:
                return "kept_default"
            # Convert V2 to V1 names for scope calculation
            permissions_for_scope = [perm.replace("_", ":", 2) for perm in v2_permissions]

        # Create the target resource using the permission service
        root_workspace_id = root_workspaces.get(tenant.id)
        try:
            target_resource = permission_service.create_v2_bound_resource_for_permissions(
                permissions_for_scope,
                tenant_org_id=tenant.org_id,
                default_workspace_id=default_workspace_id,
                root_workspace_id=root_workspace_id,
            )
        except ValueError as e:
            logger.warning(f"Could not create target resource for tenant {tenant.org_id}: {e}")
            return "kept_default"

        # Check if this is actually a migration (resource changed)
        current_resource_key = (
            binding_mapping.resource_type_namespace,
            binding_mapping.resource_type_name,
            binding_mapping.resource_id,
        )
        target_resource_key = (
            target_resource.resource_type[0],
            target_resource.resource_type[1],
            target_resource.resource_id,
        )

        if current_resource_key == target_resource_key:
            return "kept_default"  # No change needed

        # Determine migration type
        if target_resource.resource_type == ("rbac", "tenant"):
            migration_type = "migrated_to_tenant"
        elif (
            target_resource.resource_type == ("rbac", "workspace") and target_resource.resource_id == root_workspace_id
        ):
            migration_type = "migrated_to_root"
        else:
            migration_type = "kept_default"

        # Log the migration
        if is_system_role:
            log_permissions = v1_permissions[:3]
        else:
            log_permissions = v2_permissions[:3]

        logger.info(
            f'Role {role.id} ({role.name}): {migration_type.replace("_", " ").title()} '
            f'(permissions: {", ".join(log_permissions)}{"..." if len(log_permissions) > 3 else ""})'
        )

        # Perform the migration
        with transaction.atomic():
            # Get existing tuples before modification
            relations_to_remove = list(binding_mapping.as_tuples())

            # Update the binding mapping with the new resource
            binding_mapping.resource_type_namespace = target_resource.resource_type[0]
            binding_mapping.resource_type_name = target_resource.resource_type[1]
            binding_mapping.resource_id = target_resource.resource_id
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
                        "new_resource": (
                            f"{target_resource.resource_type[0]}/"
                            f"{target_resource.resource_type[1]}/"
                            f"{target_resource.resource_id}"
                        ),
                    },
                    partition_key=PartitionKey.byEnvironment(),
                    add=relations_to_add,
                    remove=relations_to_remove,
                )
            )

        return migration_type

    def _collect_v2_permissions_from_mappings(self, mappings):
        """
        Extract V2 permissions from binding mappings.

        Args:
            mappings: The mappings field from a BindingMapping (a dictionary containing the role binding data)

        Returns:
            Generator of permission strings in V2 format (e.g., "advisor_recommendation_read")
        """
        if not mappings:
            return

        role_mapping = mappings.get("role")
        if role_mapping and "permissions" in role_mapping:
            for permission in role_mapping["permissions"]:
                yield permission
