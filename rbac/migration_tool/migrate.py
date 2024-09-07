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
from typing import Any, FrozenSet, Optional

from django.conf import settings
from kessel.relations.v1beta1 import common_pb2
from management.role.model import BindingMapping, Role
from management.workspace.model import Workspace
from migration_tool.models import V2rolebinding
from migration_tool.sharedSystemRolesReplicatedRoleBindings import v1_role_to_v2_bindings
from migration_tool.utils import create_relationship, output_relationships

from api.models import Tenant
from .ingest import aggregate_v1_role


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

BindingMappings = dict[str, dict[str, Any]]


def get_kessel_relation_tuples(
    v2_role_bindings: FrozenSet[V2rolebinding],
    default_workspace: str,
) -> tuple[list[common_pb2.Relationship], BindingMappings]:
    """Generate a set of relationships and BindingMappings for the given set of v2 role bindings."""
    relationships: list[common_pb2.Relationship] = list()

    # Dictionary of v2 role binding ID to v2 role UUID and its permissions
    # for the given v1 role.
    binding_mappings: BindingMappings = {}

    for v2_role_binding in v2_role_bindings:
        relationships.append(
            create_relationship("role_binding", v2_role_binding.id, "role", v2_role_binding.role.id, "granted")
        )

        v2_role_data = v2_role_binding.role

        if binding_mappings.get(v2_role_binding.id) is None:
            binding_mappings[v2_role_binding.id] = {}

        binding_mappings[v2_role_binding.id] = {
            "v2_role_uuid": str(v2_role_data.id),
            "permissions": list(v2_role_binding.role.permissions),
        }

        for perm in v2_role_binding.role.permissions:
            relationships.append(create_relationship("role", v2_role_binding.role.id, "user", "*", perm))
        for group in v2_role_binding.groups:
            # These might be duplicate but it is OK, spiceDB will handle duplication through touch
            relationships.append(create_relationship("role_binding", v2_role_binding.id, "group", group.id, "subject"))

        for bound_resource in v2_role_binding.resources:
            # Is this a workspace binding, but not to the root workspace?
            # If so, ensure this workspace is a child of the root workspace.
            # All other resource-resource or resource-workspace relations
            # which may be implied or necessary are intentionally ignored.
            # These should come from the apps that own the resource.
            if bound_resource.resource_type == "workspace" and not bound_resource.resourceId == default_workspace:
                # This is not strictly necessary here and the relation may be a duplicate.
                # Once we have more Workspace API / Inventory Group migration progress,
                # this block can and probably should be removed.
                # One of those APIs will add it themselves.
                relationships.append(
                    create_relationship(
                        bound_resource.resource_type,
                        bound_resource.resourceId,
                        "workspace",
                        default_workspace,
                        "parent",
                    )
                )

            relationships.append(
                create_relationship(
                    bound_resource.resource_type,
                    bound_resource.resourceId,
                    "role_binding",
                    v2_role_binding.id,
                    "user_grant",
                )
            )

    return relationships, binding_mappings


def migrate_role(
    role: Role,
    write_relationships: bool,
    default_workspace: str,
    current_mapping: Optional[BindingMapping] = None,
) -> tuple[list[common_pb2.Relationship], BindingMappings]:
    """
    Migrate a role from v1 to v2, returning the tuples and mappings.

    The mappings are returned so that we can reconstitute the corresponding tuples for a given role.
    This is needed so we can remove those tuples when the role changes if needed.
    """
    v1_role = aggregate_v1_role(role)
    # This is where we wire in the implementation we're using into the Migrator
    v2_role_bindings = [binding for binding in v1_role_to_v2_bindings(v1_role, default_workspace, current_mapping)]
    relationships, mappings = get_kessel_relation_tuples(frozenset(v2_role_bindings), default_workspace)
    output_relationships(relationships, write_relationships)
    return relationships, mappings


def migrate_workspace(tenant: Tenant, write_relationships: bool):
    """Migrate a workspace from v1 to v2."""
    root_workspace = Workspace.objects.create(name="root", description="Root workspace", tenant=tenant)
    # Org id represents the default workspace for now
    relationships = [
        create_relationship("workspace", tenant.org_id, "workspace", str(root_workspace.uuid), "parent"),
        create_relationship("workspace", str(root_workspace.uuid), "tenant", tenant.org_id, "parent"),
    ]
    # Include realm for tenant
    relationships.append(create_relationship("tenant", str(tenant.org_id), "realm", settings.ENV_NAME, "realm"))
    output_relationships(relationships, write_relationships)
    return str(root_workspace.uuid), tenant.org_id


def migrate_users(tenant: Tenant, write_relationships: bool):
    """Write users relationship to tenant."""
    relationships = [
        create_relationship("tenant", str(tenant.org_id), "user", str(principal.uuid), "member")
        for principal in tenant.principal_set.all()
    ]
    output_relationships(relationships, write_relationships)


def migrate_users_for_groups(tenant: Tenant, write_relationships: bool):
    """Write users relationship to groups."""
    relationships = []
    for group in tenant.group_set.all():
        # Explicitly create relationships for platform default group
        user_set = (
            tenant.principal_set.filter(cross_account=False) if group.platform_default else group.principals.all()
        )
        for user in user_set:
            relationships.append(create_relationship("group", str(group.uuid), "user", str(user.uuid), "member"))
    output_relationships(relationships, write_relationships)


def migrate_data_for_tenant(tenant: Tenant, exclude_apps: list, write_relationships: bool):
    """Migrate all data for a given tenant."""
    logger.info("Creating workspace.")
    _, default_workspace = migrate_workspace(tenant, write_relationships)
    logger.info("Workspace migrated.")

    logger.info("Relating users to tenant.")
    migrate_users(tenant, write_relationships)
    logger.info("Finished relationship between users and tenant.")

    logger.info("Migrating relations of group and user.")
    migrate_users_for_groups(tenant, write_relationships)
    logger.info("Finished migrating relations of group and user.")

    roles = tenant.role_set.all()
    if exclude_apps:
        roles = roles.exclude(access__permission__application__in=exclude_apps)

    for role in roles:
        logger.info(f"Migrating role: {role.name} with UUID {role.uuid}.")

        _, mappings = migrate_role(role, write_relationships, default_workspace)

        # Insert is forced with `create` in order to prevent this from
        # accidentally running concurrently with dual-writes.
        # If migration should be rerun, then the bindings table should be dropped.
        # If changing this to update_or_create,
        # always ensure writes are paused before running.
        # Thus must always be the case, but `create` will at least start failing you if you forget.
        BindingMapping.objects.create(role=role, mappings=mappings)

        logger.info(f"Migration completed for role: {role.name} with UUID {role.uuid}.")
    logger.info(f"Migrated {roles.count()} roles for tenant: {tenant.org_id}")


def migrate_data(exclude_apps: list = [], orgs: list = [], write_relationships: bool = False):
    """Migrate all data for all tenants."""
    count = 0
    tenants = Tenant.objects.exclude(tenant_name="public")
    if orgs:
        tenants = tenants.filter(org_id__in=orgs)
    total = tenants.count()
    for tenant in tenants.iterator():
        logger.info(f"Migrating data for tenant: {tenant.org_id}")
        try:
            migrate_data_for_tenant(tenant, exclude_apps, write_relationships)
        except Exception as e:
            logger.error(f"Failed to migrate data for tenant: {tenant.org_id}. Error: {e}")
            raise e
        count += 1
        logger.info(f"Finished migrating data for tenant: {tenant.org_id}. {count} of {total} tenants completed")
    logger.info("Finished migrating data for all tenants")
