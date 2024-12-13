"""
Copyright 2019 Red Hat, Inc.

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
from typing import Iterable

from django.conf import settings
from django.db import transaction
from kessel.relations.v1beta1 import common_pb2
from management.group.relation_api_dual_write_group_handler import RelationApiDualWriteGroupHandler
from management.models import Workspace
from management.principal.model import Principal
from management.relation_replicator.logging_replicator import LoggingReplicator
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.relation_replicator.relations_api_replicator import RelationsApiReplicator
from management.role.model import BindingMapping, Role
from migration_tool.models import V2rolebinding
from migration_tool.sharedSystemRolesReplicatedRoleBindings import v1_role_to_v2_bindings
from migration_tool.utils import create_relationship

from api.cross_access.relation_api_dual_write_cross_access_handler import RelationApiDualWriteCrossAccessHandler
from api.models import CrossAccountRequest, Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def get_kessel_relation_tuples(
    v2_role_bindings: Iterable[V2rolebinding],
    default_workspace: Workspace,
) -> list[common_pb2.Relationship]:
    """Generate a set of relationships and BindingMappings for the given set of v2 role bindings."""
    relationships: list[common_pb2.Relationship] = list()

    for v2_role_binding in v2_role_bindings:
        relationships.extend(v2_role_binding.as_tuples())

        bound_resource = v2_role_binding.resource

        # Is this a workspace binding, but not to the root workspace?
        # If so, ensure this workspace is a child of the root workspace.
        # All other resource-resource or resource-workspace relations
        # which may be implied or necessary are intentionally ignored.
        # These should come from the apps that own the resource.
        if bound_resource.resource_type == ("rbac", "workspace") and not bound_resource.resource_id == str(
            default_workspace.id
        ):
            # This is not strictly necessary here and the relation may be a duplicate.
            # Once we have more Workspace API / Inventory Group migration progress,
            # this block can and probably should be removed.
            # One of those APIs will add it themselves.
            relationships.append(
                create_relationship(
                    bound_resource.resource_type,
                    bound_resource.resource_id,
                    ("rbac", "workspace"),
                    str(default_workspace.id),
                    "parent",
                )
            )

    return relationships


def migrate_role(
    role: Role,
    default_workspace: Workspace,
    current_bindings: Iterable[BindingMapping] = [],
) -> tuple[list[common_pb2.Relationship], list[BindingMapping]]:
    """
    Migrate a role from v1 to v2, returning the tuples and mappings.

    The mappings are returned so that we can reconstitute the corresponding tuples for a given role.
    This is needed so we can remove those tuples when the role changes if needed.
    """
    v2_role_bindings = v1_role_to_v2_bindings(role, default_workspace, current_bindings)
    relationships = get_kessel_relation_tuples([m.get_role_binding() for m in v2_role_bindings], default_workspace)
    return relationships, v2_role_bindings


def migrate_groups_for_tenant(tenant: Tenant, replicator: RelationReplicator):
    """Generate user relationships and system role assignments for groups in a tenant."""
    groups = tenant.group_set.all()
    for group in groups:
        principals: list[Principal] = []
        system_roles: list[Role] = []
        if not group.platform_default:
            principals = group.principals.all()
        if group.system is False and group.admin_default is False:
            system_roles = group.roles().filter(system=True)
        if any(True for _ in system_roles) or any(True for _ in principals):
            # The migrator does not generally deal with concurrency control,
            # but we require an atomic block due to use of select_for_update in the dual write handler.
            with transaction.atomic():
                dual_write_handler = RelationApiDualWriteGroupHandler(
                    group, ReplicationEventType.MIGRATE_TENANT_GROUPS, replicator=replicator
                )
                dual_write_handler.generate_relations_to_add_principals(principals)
                dual_write_handler.generate_relations_to_add_roles(system_roles)
                dual_write_handler.replicate()


def migrate_data_for_tenant(tenant: Tenant, exclude_apps: list, replicator: RelationReplicator):
    """Migrate all data for a given tenant."""
    logger.info("Migrating relations of group and user.")

    migrate_groups_for_tenant(tenant, replicator)

    logger.info("Finished migrating relations of group and user.")

    default_workspace = Workspace.objects.get(type=Workspace.Types.DEFAULT, tenant=tenant)

    roles = tenant.role_set.all()
    if exclude_apps:
        roles = roles.exclude(access__permission__application__in=exclude_apps)

    for role in roles:
        logger.info(f"Migrating role: {role.name} with UUID {role.uuid}.")

        tuples, mappings = migrate_role(role, default_workspace)

        # Conflicts are not ignored in order to prevent this from
        # accidentally running concurrently with dual-writes.
        # If migration should be rerun, then the bindings table should be dropped.
        # If changing this to allow updates,
        # always ensure writes are paused before running.
        # This must always be the case, but this should at least start failing you if you forget.
        BindingMapping.objects.bulk_create(mappings, ignore_conflicts=False)

        replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.MIGRATE_CUSTOM_ROLE,
                info={"role_uuid": str(role.uuid)},
                partition_key=PartitionKey.byEnvironment(),
                add=tuples,
            )
        )

        logger.info(f"Migration completed for role: {role.name} with UUID {role.uuid}.")
    logger.info(f"Migrated {roles.count()} roles for tenant: {tenant.org_id}")

    logger.info("Migrating relations of cross account requests.")
    migrate_cross_account_requests(tenant, replicator)
    logger.info("Finished relations of cross account requests.")


# The migrator does not generally deal with concurrency control,
# but we require an atomic block due to use of select_for_update in the dual write handler.
def migrate_cross_account_requests(tenant: Tenant, replicator: RelationReplicator):
    """Migrate approved account requests."""
    cross_account_requests = CrossAccountRequest.objects.filter(status="approved", target_org=tenant.org_id)
    for cross_account_request in cross_account_requests:
        with transaction.atomic():
            cross_account_roles = cross_account_request.roles.all()
            if any(True for _ in cross_account_roles):
                dual_write_handler = RelationApiDualWriteCrossAccessHandler(
                    cross_account_request, ReplicationEventType.MIGRATE_CROSS_ACCOUNT_REQUEST, replicator
                )
                dual_write_handler.generate_relations_to_add_roles(cross_account_request.roles.all())
                dual_write_handler.replicate()


def migrate_data(exclude_apps: list = [], orgs: list = [], write_relationships: str = "False"):
    """Migrate all data for all tenants."""
    # Only run this in maintanence mode or
    # if we don't write relationships (testing out the migration and clean up the created bindingmappings)
    if not settings.READ_ONLY_API_MODE and write_relationships != "False":
        logger.fatal("Read-only API mode is required. READ_ONLY_API_MODE must be set to true.")
        return

    count = 0
    tenants = Tenant.objects.filter(ready=True).exclude(tenant_name="public")
    replicator = _get_replicator(write_relationships)
    if orgs:
        tenants = tenants.filter(org_id__in=orgs)
    total = tenants.count()
    for tenant in tenants.iterator():
        if tenant.org_id is None:
            logger.warning(f"Not migrating tenant, no org id: pk={tenant.id}")
            continue
        else:
            logger.info(f"Migrating data for tenant: {tenant.org_id}")

        try:
            migrate_data_for_tenant(tenant, exclude_apps, replicator)
        except Exception as e:
            logger.error(f"Failed to migrate data for tenant: {tenant.org_id}. Error: {e}")
            raise e
        count += 1
        logger.info(f"Finished migrating data for tenant: {tenant.org_id}. {count} of {total} tenants completed")
    logger.info("Finished migrating data for all tenants")


def _get_replicator(write_relationships: str) -> RelationReplicator:
    option = write_relationships.lower()

    if option == "true" or option == "relations-api":
        return RelationsApiReplicator()

    if option == "outbox":
        return OutboxReplicator()

    return LoggingReplicator()
