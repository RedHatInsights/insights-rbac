"""
Copyright 2025 Red Hat, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging

from django.conf import settings
from django.db import transaction
from management.models import Workspace
from management.permission.scope_service import ImplicitResourceService, bound_model_for_scope
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.model import Role
from management.role.relation_api_dual_write_handler import RelationApiDualWriteHandler
from migration_tool.models import V2boundresource

from api.models import Tenant

logger = logging.getLogger(__name__)


def migrate_role_bindings(role: Role, replicator: RelationReplicator) -> int:
    """
    Migrate all bindings for a role to the correct scope.

    Uses dual write handlers to delete old bindings and create new ones at correct scope.
    Groups and users assigned to the role are preserved.

    NOTE: System roles use SeedingRelationApiDualWriteHandler for role-permission relationships,
    but system role bindings (from custom default groups) are migrated manually to correct scope.

    Args:
        role: Role to migrate bindings for
        replicator: Replicator to use for relation updates

    Returns: Number of bindings migrated (1 if migrated, 0 if no change)
    """
    if role.system:
        # System role: Migrate bindings from custom default groups to correct scope
        # Note: Role-permission relationships (seeding) is handled in a separate process

        # Get all existing bindings for this system role (from custom default groups)
        existing_bindings = role.binding_mappings.all()

        if not existing_bindings:
            logger.info(f"System role {role.uuid} ({role.name}) has no bindings to migrate")
            return 0

        # Has bindings - need to migrate them to correct scope per tenant
        # Replicate each binding separately to avoid exceeding message size limits
        resource_service = ImplicitResourceService.from_settings()
        scope = resource_service.scope_for_role(role)

        bindings_migrated = 0

        for binding in existing_bindings:
            try:
                # Get the tenant for this binding
                if binding.resource_type_name == "workspace":
                    workspace = Workspace.objects.get(id=binding.resource_id)
                    binding_tenant = workspace.tenant
                elif binding.resource_type_name == "tenant":
                    tenant_resource_id = binding.resource_id
                    org_id = Tenant.tenant_resource_id_to_org_id(tenant_resource_id)
                    binding_tenant = Tenant.objects.get(org_id=org_id)
                else:
                    logger.warning(f"Unknown resource type for binding {binding.id}: {binding.resource_type_name}")
                    continue

                # Determine correct scope for this tenant
                root_workspace = Workspace.objects.root(tenant=binding_tenant)
                default_workspace = Workspace.objects.default(tenant=binding_tenant)

                target_model = bound_model_for_scope(
                    scope=scope,
                    tenant=binding_tenant,
                    root_workspace=root_workspace,
                    default_workspace=default_workspace,
                )
                target_resource = V2boundresource.for_model(target_model)

                # Check if already at correct scope
                is_correct_scope = (
                    binding.resource_type_namespace == target_resource.resource_type[0]
                    and binding.resource_type_name == target_resource.resource_type[1]
                    and binding.resource_id == target_resource.resource_id
                )
                if is_correct_scope:
                    logger.debug(f"System role binding {binding.id} already at correct scope")
                    continue

                # Get old and new binding tuples for this single binding
                old_tuples = binding.as_tuples()

                # Update binding to new scope
                binding.resource_type_namespace = target_resource.resource_type[0]
                binding.resource_type_name = target_resource.resource_type[1]
                binding.resource_id = target_resource.resource_id
                binding.save()

                # Get new binding tuples
                new_tuples = binding.as_tuples()

                # Replicate this single binding's changes immediately
                event = ReplicationEvent(
                    event_type=ReplicationEventType.MIGRATE_BINDING_SCOPE,
                    add=new_tuples,
                    remove=old_tuples,
                    partition_key=role,
                    info={"role_uuid": str(role.uuid), "binding_id": binding.id},
                )
                replicator.replicate(event)

                bindings_migrated += 1

                logger.info(
                    f"Migrated system role {role.uuid} binding {binding.id} to "
                    f"{target_resource.resource_type}:{target_resource.resource_id}"
                )

            except Exception as e:
                logger.error(f"Failed to migrate binding {binding.id} for system role {role.uuid}: {e}")
                continue

        logger.info(f"Migrated system role {role.uuid} ({role.name}): {bindings_migrated} bindings updated")
        return 1
    else:
        # Custom role: use RelationApiDualWriteHandler
        dual_write = RelationApiDualWriteHandler(
            role, ReplicationEventType.MIGRATE_BINDING_SCOPE, replicator=replicator
        )

        # Prepare for update: captures current bindings
        dual_write.prepare_for_update()

        # Recreate bindings at correct scope
        dual_write.replicate_new_or_updated_role(role)

        logger.info(f"Migrated custom role {role.uuid} ({role.name}) bindings to correct scope")
        return 1


def migrate_all_role_bindings(replicator: RelationReplicator = OutboxReplicator(), batch_size: int = 100):
    """
    Migrate all role bindings to correct scope.

    Args:
        replicator: Replicator to use for relation updates. Defaults to OutboxReplicator.
        batch_size: Number of roles to process in each batch (default: 100).

    Returns: Tuple of (roles_checked, roles_migrated)
    """
    logger.info(f"Starting role binding scope migration (batch_size={batch_size})")
    logger.info(f"ROOT_SCOPE_PERMISSIONS: {settings.ROOT_SCOPE_PERMISSIONS}")
    logger.info(f"TENANT_SCOPE_PERMISSIONS: {settings.TENANT_SCOPE_PERMISSIONS}")

    # Get all roles that might have incorrect bindings
    # System roles (public tenant) + all custom roles with bindings
    all_roles = Role.objects.filter(binding_mappings__isnull=False).distinct().order_by("pk")

    total_roles = all_roles.count()
    logger.info(f"Found {total_roles} roles with bindings to check")

    total_checked = 0
    total_migrated = 0

    # Get all role IDs for batching
    role_ids = list(all_roles.values_list("pk", flat=True))

    # Process in batches
    for batch_start in range(0, total_roles, batch_size):
        batch_end = min(batch_start + batch_size, total_roles)
        batch_ids = role_ids[batch_start:batch_end]

        batch_num = batch_start // batch_size + 1
        logger.debug(f"Processing batch {batch_num}: roles {batch_start}-{batch_end} of {total_roles}")

        for role_id in batch_ids:
            total_checked += 1

            # Lock and migrate within transaction
            with transaction.atomic():
                # Lock the role
                role = Role.objects.select_for_update().get(pk=role_id)

                try:
                    migrated = migrate_role_bindings(role, replicator)
                    total_migrated += migrated
                except Exception as e:
                    logger.error(f"Failed to migrate bindings for role {role.uuid}: {e}", exc_info=True)
                    # Continue with next role
                    continue

        # Log progress every 10 batches
        if batch_end % (batch_size * 10) == 0 or batch_end == total_roles:
            logger.info(
                f"Progress: processed {batch_end}/{total_roles} roles, "
                f"checked {total_checked}, migrated {total_migrated}"
            )

    logger.info(
        f"Completed role binding scope migration: " f"{total_checked} roles checked, {total_migrated} roles migrated"
    )

    return total_checked, total_migrated
