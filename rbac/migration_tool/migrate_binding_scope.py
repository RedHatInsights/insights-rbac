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
from management.group.model import Group
from management.group.relation_api_dual_write_group_handler import RelationApiDualWriteGroupHandler
from management.models import BindingMapping, Workspace
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


def migrate_custom_role_bindings(role: Role, replicator: RelationReplicator) -> int:
    """
    Migrate all bindings for a custom role to the correct scope.

    Uses RelationApiDualWriteHandler to delete old bindings and create new ones at correct scope.
    Groups and users assigned to the role are preserved.

    Args:
        role: Custom role to migrate bindings for (must not be system role)
        replicator: Replicator to use for relation updates

    Returns: Number of bindings migrated (1 if migrated, 0 if no change)
    """
    if role.system:
        raise ValueError(f"migrate_custom_role_bindings called with system role {role.uuid}")

    # Use RelationApiDualWriteHandler
    dual_write = RelationApiDualWriteHandler(role, ReplicationEventType.MIGRATE_BINDING_SCOPE, replicator=replicator)

    # Prepare for update: captures current bindings
    dual_write.prepare_for_update()

    # Recreate bindings at correct scope
    dual_write.replicate_new_or_updated_role(role)

    logger.info(f"Migrated custom role {role.uuid} ({role.name}) bindings to correct scope")
    return 1


def migrate_system_role_bindings_for_group(group: Group, replicator: RelationReplicator) -> int:
    """
    Migrate system role bindings for a group to correct scope.

    Uses RelationApiDualWriteGroupHandler to rebind system roles at correct scope,
    then removes the group from any wrong-scoped bindings.

    Args:
        group: Group with system role assignments
        replicator: Replicator to use for relation updates

    Returns: Number of bindings cleaned up
    """
    # Get system roles assigned to this group
    system_roles = Role.objects.filter(policies__group=group, system=True).distinct()

    if not system_roles.exists():
        return 0

    # Use group handler to bind/rebind system roles at correct scope
    dual_write_handler = RelationApiDualWriteGroupHandler(
        group, ReplicationEventType.MIGRATE_BINDING_SCOPE, replicator=replicator
    )

    # This will create or update bindings at correct scope for all system roles
    dual_write_handler.generate_relations_reset_roles(system_roles)
    dual_write_handler.replicate()

    # Now clean up: remove this group from any wrong-scoped bindings
    # Get tenant and workspaces once (all bindings are for this group's tenant)
    tenant = group.tenant
    root_ws = Workspace.objects.root(tenant=tenant)
    default_ws = Workspace.objects.default(tenant=tenant)
    tenant_resource_id = Tenant.org_id_to_tenant_resource_id(tenant.org_id)

    service = ImplicitResourceService.from_settings()
    bindings_cleaned = 0

    for role in system_roles:
        scope = service.scope_for_role(role)

        # Determine correct scope for this tenant
        target_model = bound_model_for_scope(scope, tenant, root_ws, default_ws)
        target_resource = V2boundresource.for_model(target_model)

        # Build list of possible resource IDs (all scopes for this tenant)
        possible_resource_ids = [
            tenant_resource_id,  # Tenant resource ID
            str(root_ws.id),  # Root workspace
            str(default_ws.id),  # Default workspace
        ]

        # Find wrong-scoped bindings: exclude the correct one
        wrong_scoped_bindings = BindingMapping.objects.filter(
            role=role, resource_id__in=possible_resource_ids
        ).exclude(
            resource_type_namespace=target_resource.resource_type[0],
            resource_type_name=target_resource.resource_type[1],
            resource_id=target_resource.resource_id,
        )

        # Remove this group from each wrong-scoped binding
        for binding in wrong_scoped_bindings:
            groups_list = binding.mappings.get("groups", [])
            if str(group.uuid) in groups_list:
                # Get old tuples before modification
                old_tuples = binding.as_tuples()

                # Remove this group
                groups_list.remove(str(group.uuid))
                binding.mappings["groups"] = groups_list
                binding.save()

                # TODO: The users for cross account requests are not migrated
                # so we keep the wrong scope binding, will deal with it later.
                if binding.is_unassigned():
                    # No groups/users left - delete the binding
                    new_tuples = []
                    binding.delete()
                    logger.info(
                        f"Deleted empty wrong-scoped binding {binding.id} for role {role.uuid} "
                        f"at {binding.resource_type_name}:{binding.resource_id}"
                    )
                else:
                    # Still has other groups/users - just update tuples
                    new_tuples = binding.as_tuples()
                    logger.info(
                        f"Removed group {group.uuid} from wrong-scoped binding {binding.id} "
                        f"at {binding.resource_type_name}:{binding.resource_id}"
                    )

                # Replicate the change
                event = ReplicationEvent(
                    event_type=ReplicationEventType.MIGRATE_BINDING_SCOPE,
                    add=new_tuples,
                    remove=old_tuples,
                    partition_key=role,
                    info={
                        "role_uuid": str(role.uuid),
                        "group_uuid": str(group.uuid),
                        "binding_id": binding.id,
                        "action": "remove_group_from_wrong_scope",
                    },
                )
                replicator.replicate(event)
                bindings_cleaned += 1

    logger.info(f"Cleaned {bindings_cleaned} wrong-scoped bindings for group {group.uuid} ({group.name})")
    return bindings_cleaned


def migrate_all_role_bindings(replicator: RelationReplicator = OutboxReplicator(), batch_size: int = 100):
    """
    Migrate all role bindings to correct scope.

    - Custom roles: Migrated individually using RelationApiDualWriteHandler
    - System roles: Migrated per group using RelationApiDualWriteGroupHandler

    Args:
        replicator: Replicator to use for relation updates. Defaults to OutboxReplicator.
        batch_size: Number of items to process in each batch (default: 100).

    Returns: Tuple of (items_checked, items_migrated)
    """
    logger.info(f"Starting binding scope migration (batch_size={batch_size})")
    logger.info(f"ROOT_SCOPE_PERMISSIONS: {settings.ROOT_SCOPE_PERMISSIONS}")
    logger.info(f"TENANT_SCOPE_PERMISSIONS: {settings.TENANT_SCOPE_PERMISSIONS}")

    # Part 1: Migrate custom role bindings
    custom_roles = Role.objects.filter(binding_mappings__isnull=False, system=False).distinct().order_by("pk")

    total_custom_roles = custom_roles.count()
    logger.info(f"Found {total_custom_roles} custom roles with bindings to migrate")

    custom_roles_checked = 0
    custom_roles_migrated = 0

    custom_role_ids = list(custom_roles.values_list("pk", flat=True))

    for batch_start in range(0, total_custom_roles, batch_size):
        batch_end = min(batch_start + batch_size, total_custom_roles)
        batch_ids = custom_role_ids[batch_start:batch_end]

        for role_id in batch_ids:
            custom_roles_checked += 1

            with transaction.atomic():
                role = Role.objects.select_for_update().get(pk=role_id)

                try:
                    migrated = migrate_custom_role_bindings(role, replicator)
                    custom_roles_migrated += migrated
                except Exception as e:
                    logger.error(f"Failed to migrate custom role {role.uuid}: {e}", exc_info=True)
                    continue

        if batch_end % (batch_size * 10) == 0 or batch_end == total_custom_roles:
            logger.info(
                f"Progress (custom roles): processed {batch_end}/{total_custom_roles}, "
                f"migrated {custom_roles_migrated}"
            )

    logger.info(f"Completed custom role migration: {custom_roles_checked} checked, {custom_roles_migrated} migrated")

    # Part 2: Migrate system role bindings via groups
    # Get all groups that have system roles
    groups_with_system_roles = (
        Group.objects.filter(policies__roles__system=True)
        .exclude(tenant__tenant_name="public")
        .distinct()
        .order_by("pk")
    )

    total_groups = groups_with_system_roles.count()
    logger.info(f"Found {total_groups} groups with system roles to migrate")

    groups_checked = 0
    groups_migrated = 0

    group_ids = list(groups_with_system_roles.values_list("pk", flat=True))

    for batch_start in range(0, total_groups, batch_size):
        batch_end = min(batch_start + batch_size, total_groups)
        batch_ids = group_ids[batch_start:batch_end]

        for group_id in batch_ids:
            groups_checked += 1

            with transaction.atomic():
                group = Group.objects.select_for_update().select_related("tenant").get(pk=group_id)

                try:
                    migrated = migrate_system_role_bindings_for_group(group, replicator)
                    if migrated > 0:
                        groups_migrated += 1
                except Exception as e:
                    logger.error(f"Failed to migrate system roles for group {group.uuid}: {e}", exc_info=True)
                    continue

        if batch_end % (batch_size * 10) == 0 or batch_end == total_groups:
            logger.info(f"Progress (groups): processed {batch_end}/{total_groups}, " f"migrated {groups_migrated}")

    logger.info(
        f"Completed system role migration via groups: {groups_checked} groups checked, {groups_migrated} migrated"
    )

    total_checked = custom_roles_checked + groups_checked
    total_migrated = custom_roles_migrated + groups_migrated

    logger.info(
        f"Completed binding scope migration: "
        f"{custom_roles_migrated} custom roles + {groups_migrated} groups migrated"
    )

    return total_checked, total_migrated
