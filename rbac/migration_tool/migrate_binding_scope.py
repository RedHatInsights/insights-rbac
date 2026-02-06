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
from typing import Optional

from django.conf import settings
from django.db import transaction
from management.group.model import Group
from management.group.relation_api_dual_write_group_handler import RelationApiDualWriteGroupHandler
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import RelationReplicator, ReplicationEventType
from management.role.v1.model import Role
from management.role.v1.relation_api_dual_write_handler import RelationApiDualWriteHandler

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

    if not dual_write_handler.replication_enabled():
        logger.info(f"Skipping migration for group {group.uuid} ({group.name}) because replication is disabled")
        return 0

    # First remove existing bindings (including wrong-scoped ones) before re-adding correct assignments.
    dual_write_handler.generate_relations_to_remove_roles(system_roles)
    bindings_cleaned = len(dual_write_handler.relations_to_remove)
    dual_write_handler.replicate()

    # Rehydrate handler to reset relation buffers before creating correct bindings.
    dual_write_handler = RelationApiDualWriteGroupHandler(
        group, ReplicationEventType.MIGRATE_BINDING_SCOPE, replicator=replicator
    )
    dual_write_handler.generate_relations_reset_roles(system_roles)
    dual_write_handler.replicate()

    logger.info(f"Processed {bindings_cleaned} binding/group relation removals for group {group.uuid} ({group.name})")
    return bindings_cleaned


def migrate_all_role_bindings(
    replicator: RelationReplicator = OutboxReplicator(),
    tenant: Optional[Tenant] = None,
):
    """
    Migrate all role bindings to correct scope.

    - Custom roles: Migrated individually using RelationApiDualWriteHandler
    - System roles: Migrated per group using RelationApiDualWriteGroupHandler

    Args:
        replicator: Replicator to use for relation updates. Defaults to OutboxReplicator.
        tenant: Optional tenant to filter roles and groups. If None, migrates all tenants.

    Returns: Tuple of (items_checked, items_migrated)
    """
    tenant_info = f" for tenant {tenant.org_id}" if tenant else ""
    logger.info(f"Starting binding scope migration{tenant_info}")
    logger.info(f"ROOT_SCOPE_PERMISSIONS: {settings.ROOT_SCOPE_PERMISSIONS}")
    logger.info(f"TENANT_SCOPE_PERMISSIONS: {settings.TENANT_SCOPE_PERMISSIONS}")

    # Part 1: Migrate custom role bindings
    # Include all custom roles with access (permissions), even if they have no policies (groups) assigned yet.
    # This ensures v2 roles and bindings are created at the correct scope for roles that were created
    # before replication was enabled or before scope configuration was corrected.
    # Roles without access won't have any v2 models created (nothing to migrate).
    custom_roles = Role.objects.filter(system=False).distinct().order_by("pk")
    if tenant:
        custom_roles = custom_roles.filter(tenant=tenant)

    total_custom_roles = custom_roles.count()
    logger.info(f"Found {total_custom_roles} custom roles to migrate")

    custom_roles_checked = 0
    custom_roles_migrated = 0

    for raw_role in custom_roles.iterator():
        custom_roles_checked += 1

        with transaction.atomic():
            role: Optional[Role] = Role.objects.select_for_update().filter(pk=raw_role.pk).first()

            if role is None:
                logger.warning(f"Role vanished before it could be migrated: pk={raw_role.pk!r}")
                continue

            try:
                migrated = migrate_custom_role_bindings(role, replicator)
                custom_roles_migrated += migrated
            except Exception as e:
                logger.error(f"Failed to migrate custom role {role.uuid}: {e}", exc_info=True)
                continue

        if custom_roles_checked % 10 == 0 or custom_roles_checked == total_custom_roles:
            logger.info(
                f"Progress (custom roles): processed {custom_roles_checked}/{total_custom_roles}, "
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
    if tenant:
        groups_with_system_roles = groups_with_system_roles.filter(tenant=tenant)

    total_groups = groups_with_system_roles.count()
    logger.info(f"Found {total_groups} groups with system roles to migrate")

    groups_checked = 0
    groups_migrated = 0

    for raw_group in groups_with_system_roles.iterator():
        groups_checked += 1

        with transaction.atomic():
            group: Optional[Group] = (
                Group.objects.select_for_update().select_related("tenant").filter(pk=raw_group.pk).first()
            )

            if group is None:
                logger.warning(f"Group vanished before it could be migrated: pk={raw_group.pk!r}")
                continue

            try:
                migrated = migrate_system_role_bindings_for_group(group, replicator)
                if migrated > 0:
                    groups_migrated += 1
            except Exception as e:
                logger.error(f"Failed to migrate system roles for group {group.uuid}: {e}", exc_info=True)
                continue

        if groups_checked % 10 == 0 or groups_checked == total_groups:
            logger.info(f"Progress (groups): processed {groups_checked}/{total_groups}, migrated {groups_migrated}")

    logger.info(
        f"Completed system role migration via groups: {groups_checked} groups checked, {groups_migrated} migrated"
    )

    total_checked = custom_roles_checked + groups_checked
    total_migrated = custom_roles_migrated + groups_migrated

    logger.info(
        f"Completed binding scope migration{tenant_info}: "
        f"{custom_roles_migrated} custom roles + {groups_migrated} groups migrated"
    )

    return total_checked, total_migrated
