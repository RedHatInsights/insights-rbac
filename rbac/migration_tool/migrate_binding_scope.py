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
from management.models import BindingMapping, Workspace
from management.permission.scope_service import Scope, default_implicit_resource_service
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.model import Role
from migration_tool.models import V2boundresource
from migration_tool.utils import create_relationship

from api.models import Tenant

logger = logging.getLogger(__name__)


def determine_binding_scope_for_role(role, tenant: Tenant) -> tuple[str, str, str]:
    """
    Determine the appropriate binding scope based on role permissions.

    Uses the ImplicitResourceService to determine scope based on:
    - ROOT_SCOPE_PERMISSIONS configuration
    - TENANT_SCOPE_PERMISSIONS configuration
    - Default scope (default workspace) if no match

    Returns tuple of (resource_type_namespace, resource_type_name, resource_id)
    """
    # Use the scope service to determine the appropriate scope
    scope = default_implicit_resource_service.scope_for_role(role)

    logger.debug(f"Role {role.uuid} ({role.name}) has scope: {scope}")

    # Get workspaces
    try:
        root_workspace = Workspace.objects.root(tenant=tenant)
        default_workspace = Workspace.objects.default(tenant=tenant)
    except Workspace.DoesNotExist as e:
        logger.error(f"Workspace not found for tenant {tenant.org_id}: {e}")
        raise

    # Convert scope to resource
    if scope == Scope.TENANT:
        # Tenant-level binding
        tenant_resource_id = Tenant.org_id_to_tenant_resource_id(tenant.org_id)
        return ("rbac", "tenant", tenant_resource_id)
    elif scope == Scope.ROOT:
        # Root workspace binding
        return ("rbac", "workspace", str(root_workspace.id))
    else:  # Scope.DEFAULT
        # Default workspace binding
        return ("rbac", "workspace", str(default_workspace.id))


def has_explicit_workspace_resource_definition(role, workspace_id: str) -> bool:
    """
    Check if a role has resource definitions that explicitly reference a specific workspace ID.

    Args:
        role: Role to check
        workspace_id: Workspace ID to look for in resource definitions

    Returns True if any resource definition explicitly references this workspace ID
    """
    for access in role.access.all():
        for resource_def in access.resourceDefinitions.all():
            attr_filter = resource_def.attributeFilter
            if not attr_filter:
                continue

            # Check if this is a workspace filter (group.id)
            if attr_filter.get("key") == "group.id":
                value = attr_filter.get("value")
                # Check if this workspace ID is explicitly referenced
                if isinstance(value, list):
                    if workspace_id in value:
                        return True
                elif value == workspace_id:
                    return True

    return False


def should_migrate_binding(binding: BindingMapping, tenant: Tenant) -> bool:
    """
    Determine if a binding should be migrated based on its current resource.

    Returns True if the binding is currently bound to:
    - Tenant level (rbac:tenant)
    - Root workspace
    - Default workspace

    AND the role does NOT have explicit resource definitions referencing this workspace.

    These are the only bindings we want to reconsider, as they may need
    to be moved to a different scope based on the role's permissions.
    """
    # Check if binding is to a workspace
    if binding.resource_type_namespace == "rbac" and binding.resource_type_name == "workspace":
        try:
            workspace = Workspace.objects.get(id=binding.resource_id, tenant=tenant)
            # Only migrate if it's root or default workspace
            if workspace.type in [Workspace.Types.ROOT, Workspace.Types.DEFAULT]:
                # Check if role has explicit resource definitions for this workspace
                if has_explicit_workspace_resource_definition(binding.role, binding.resource_id):
                    logger.debug(
                        f"Binding {binding.id} for role {binding.role.uuid} has explicit resource "
                        f"definition for workspace {binding.resource_id}, skipping migration"
                    )
                    return False

                logger.debug(
                    f"Binding {binding.id} for role {binding.role.uuid} is bound to {workspace.type} workspace"
                )
                return True
        except Workspace.DoesNotExist:
            logger.warning(f"Workspace {binding.resource_id} not found for binding {binding.id}")
            return False

    # Check if binding is to tenant level
    if binding.resource_type_namespace == "rbac" and binding.resource_type_name == "tenant":
        logger.debug(f"Binding {binding.id} for role {binding.role.uuid} is bound to tenant level")
        return True

    return False


def migrate_binding_scope(binding: BindingMapping, tenant: Tenant, replicator: RelationReplicator) -> bool:
    """
    Migrate a binding to the appropriate scope based on its role's permissions.

    Uses the ImplicitResourceService to determine the correct scope based on
    ROOT_SCOPE_PERMISSIONS and TENANT_SCOPE_PERMISSIONS configuration.

    If another binding already exists for the same role at the target scope,
    this binding will be deleted instead of migrated (to avoid duplicates).

    Args:
        binding: BindingMapping to migrate
        tenant: Tenant the binding belongs to
        replicator: Replicator to use for relation updates

    Returns True if the binding was migrated or deleted, False otherwise.
    """
    role = binding.role

    # Determine the new binding scope using the scope service
    new_namespace, new_name, new_resource_id = determine_binding_scope_for_role(role, tenant)

    # Check if migration is needed
    if (
        binding.resource_type_namespace == new_namespace
        and binding.resource_type_name == new_name
        and binding.resource_id == new_resource_id
    ):
        logger.debug(f"Binding {binding.id} for role {role.uuid} is already at correct scope, skipping")
        return False

    # Check if another binding already exists for this role at the target scope
    existing_binding = (
        BindingMapping.objects.filter(
            role=role,
            resource_type_namespace=new_namespace,
            resource_type_name=new_name,
            resource_id=new_resource_id,
        )
        .exclude(pk=binding.pk)
        .first()
    )

    if existing_binding:
        # Another binding already exists at target scope - delete this redundant binding
        logger.info(
            f"Deleting redundant binding {binding.id} for role {role.uuid} ({role.name}) at "
            f"{binding.resource_type_namespace}:{binding.resource_type_name}:{binding.resource_id} "
            f"because binding {existing_binding.id} already exists at target "
            f"{new_namespace}:{new_name}:{new_resource_id}"
        )

        # Remove all relationships for this binding
        relations_to_remove = binding.as_tuples()

        # Delete the binding
        binding.delete()

        # Replicate the deletion
        if replicator:
            event = ReplicationEvent(
                event_type=ReplicationEventType.DELETE_BINDING_MAPPINGS,
                add=[],
                remove=relations_to_remove,
                partition_key=role,
                info={"role_uuid": str(role.uuid), "binding_id": binding.id, "reason": "duplicate"},
            )
            replicator.replicate(event)

        logger.info(f"Successfully deleted redundant binding {binding.id} for role {role.uuid}")
        return True

    # No existing binding at target - migrate this one
    logger.info(
        f"Migrating binding {binding.id} for role {role.uuid} ({role.name}) from "
        f"{binding.resource_type_namespace}:{binding.resource_type_name}:{binding.resource_id} to "
        f"{new_namespace}:{new_name}:{new_resource_id}"
    )

    # Create new resource
    new_resource = V2boundresource(resource_type=(new_namespace, new_name), resource_id=new_resource_id)

    # Calculate tuples to remove (old resource binding) and add (new resource binding)
    relations_to_remove = []
    relations_to_add = []

    # Remove old resource->binding relationship
    relations_to_remove.append(
        create_relationship(
            (binding.resource_type_namespace, binding.resource_type_name),
            binding.resource_id,
            ("rbac", "role_binding"),
            binding.mappings["id"],
            "binding",
        )
    )

    # Add new resource->binding relationship
    relations_to_add.append(
        create_relationship(
            new_resource.resource_type,
            new_resource.resource_id,
            ("rbac", "role_binding"),
            binding.mappings["id"],
            "binding",
        )
    )

    # Update the binding mapping in database
    binding.resource_type_namespace = new_namespace
    binding.resource_type_name = new_name
    binding.resource_id = new_resource_id
    binding.save()

    # Replicate the changes
    if replicator:
        event = ReplicationEvent(
            event_type=ReplicationEventType.MIGRATE_BINDING_SCOPE,
            add=relations_to_add,
            remove=relations_to_remove,
            partition_key=role,
            info={"role_uuid": str(role.uuid), "binding_id": binding.id},
        )
        replicator.replicate(event)

    logger.info(f"Successfully migrated binding {binding.id} for role {role.uuid}")
    return True


def process_binding_batch(binding_ids: list, replicator: RelationReplicator) -> tuple[int, int]:
    """
    Process a batch of binding mappings.

    Args:
        binding_ids: List of binding IDs to process
        replicator: Replicator to use for relation updates

    Returns tuple of (total_checked, total_migrated) for this batch
    """
    total_checked = 0
    total_migrated = 0

    for binding_id in binding_ids:
        total_checked += 1

        # Get binding with role and tenant in one query
        try:
            binding = BindingMapping.objects.select_related("role", "role__tenant").get(pk=binding_id)
        except BindingMapping.DoesNotExist:
            logger.warning(f"Binding {binding_id} not found, skipping")
            continue

        # Tenant is already loaded via select_related
        tenant = binding.role.tenant

        # Check if this binding should be migrated
        if not should_migrate_binding(binding, tenant):
            continue

        # Migrate within a transaction
        with transaction.atomic():
            # Lock the binding
            binding = BindingMapping.objects.select_for_update().get(pk=binding.pk)

            # Also lock the role to prevent concurrent modifications
            role = Role.objects.select_for_update().get(pk=binding.role.pk)
            binding.role = role

            try:
                if migrate_binding_scope(binding, tenant, replicator):
                    total_migrated += 1
            except Exception as e:
                logger.error(f"Failed to migrate binding {binding.id} for role {role.uuid}: {e}", exc_info=True)
                # Continue with next binding
                continue

    return total_checked, total_migrated


def migrate_all_binding_scopes(replicator: RelationReplicator = OutboxReplicator(), batch_size: int = 100):
    """
    Migrate binding scopes for all eligible binding mappings.

    Args:
        replicator: Replicator to use for relation updates. Defaults to OutboxReplicator.
        batch_size: Number of bindings to process in each batch (default: 100).
    """
    # Query binding mappings that are candidates for migration
    # Filter to only workspace and tenant bindings (not specific resources)
    candidate_bindings = (
        BindingMapping.objects.filter(resource_type_namespace="rbac", resource_type_name__in=["workspace", "tenant"])
        .select_related("role", "role__tenant")
        .order_by("pk")
    )

    total_bindings = candidate_bindings.count()

    logger.info(f"Starting binding scope migration (batch_size={batch_size})")
    logger.info(f"ROOT_SCOPE_PERMISSIONS: {settings.ROOT_SCOPE_PERMISSIONS}")
    logger.info(f"TENANT_SCOPE_PERMISSIONS: {settings.TENANT_SCOPE_PERMISSIONS}")
    logger.info(f"Found {total_bindings} candidate bindings to check")

    total_checked = 0
    total_migrated = 0

    # Get all binding IDs first for batching
    binding_ids = list(candidate_bindings.values_list("pk", flat=True))

    # Process in batches
    for batch_start in range(0, total_bindings, batch_size):
        batch_end = min(batch_start + batch_size, total_bindings)
        batch_ids = binding_ids[batch_start:batch_end]

        batch_num = batch_start // batch_size + 1
        logger.debug(f"Processing batch {batch_num}: bindings {batch_start}-{batch_end} of {total_bindings}")

        checked, migrated = process_binding_batch(batch_ids, replicator)
        total_checked += checked
        total_migrated += migrated

        # Log progress every 10 batches
        if batch_end % (batch_size * 10) == 0 or batch_end == total_bindings:
            logger.info(
                f"Progress: processed {batch_end}/{total_bindings} bindings, "
                f"checked {total_checked}, migrated {total_migrated}"
            )

    logger.info(
        f"Completed binding scope migration: " f"{total_checked} bindings checked, {total_migrated} bindings migrated"
    )

    return total_checked, total_migrated
