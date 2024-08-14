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

import dataclasses
import logging
from typing import FrozenSet

from django.conf import settings
from kessel.relations.v1beta1 import common_pb2
from management.role.model import BindingMapping, Role, V2Role
from management.workspace.model import Workspace
from migration_tool.models import V1group, V2rolebinding
from migration_tool.sharedSystemRolesReplicatedRoleBindings import v1_role_to_v2_mapping
from migration_tool.utils import create_relationship, write_relationships

from api.models import Tenant
from .ingest import extract_info_into_v1_role


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def spicedb_relationships(v2_role_bindings: FrozenSet[V2rolebinding], root_workspace: str):
    """Generate a set of relationships for the given set of v2 role bindings."""
    relationships = list()
    for v2_role_binding in v2_role_bindings:
        relationships.append(
            create_relationship("role_binding", v2_role_binding.id, "role", v2_role_binding.role.id, "granted")
        )
        v2_role_data = v2_role_binding.role
        v1_role = Role.objects.get(uuid=v2_role_binding.originalRole.id)
        v2_role, _ = V2Role.objects.get_or_create(id=v2_role_data.id, is_system=v2_role_data.is_system)
        v2_role.v1_roles.add(v1_role)
        BindingMapping.objects.create(id=v2_role_binding.id, v1_role=v1_role)
        for perm in v2_role_binding.role.permissions:
            relationships.append(create_relationship("role", v2_role_binding.role.id, "user", "*", perm))
        for group in v2_role_binding.groups:
            # These might be duplicate but it is OK, spiceDB will handle duplication through touch
            relationships.append(create_relationship("role_binding", v2_role_binding.id, "group", group.id, "subject"))

        for bound_resource in v2_role_binding.resources:
            parent_relation = "parent" if bound_resource.resource_type == "workspace" else "workspace"
            if not (bound_resource.resource_type == "workspace" and bound_resource.resourceId == root_workspace):
                relationships.append(
                    create_relationship(
                        bound_resource.resource_type,
                        bound_resource.resourceId,
                        "workspace",
                        root_workspace,
                        parent_relation,
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

    return relationships


def stringify_spicedb_relationship(rel: common_pb2.Relationship):
    """Stringify a relationship for logging."""
    return (
        f"{rel.resource.type.name}:{rel.resource.id}#{rel.relation}@{rel.subject.subject.type.name}:"
        f"{rel.subject.subject.id}"
    )


def migrate_role(role: Role, write_db: bool, root_workspace: str, default_workspace: str):
    """Migrate a role from v1 to v2."""
    v1_role = extract_info_into_v1_role(role)
    # With the replicated role bindings algorithm, role bindings are scoped by group, so we need to add groups
    policies = role.policies.all()
    groups = set()
    for policy in policies:
        principals = [str(principal) for principal in policy.group.principals.values_list("uuid", flat=True)]
        groups.add(V1group(str(policy.group.uuid), frozenset(principals)))
    v1_role = dataclasses.replace(v1_role, groups=frozenset(groups))

    # This is where we wire in the implementation we're using into the Migrator
    v2_roles = [v2_role for v2_role in v1_role_to_v2_mapping(v1_role, root_workspace, default_workspace)]
    relationships = spicedb_relationships(frozenset(v2_roles), root_workspace)
    for rel in relationships:
        logger.info(stringify_spicedb_relationship(rel))
    if write_db:
        write_relationships(relationships)


def migrate_workspace(tenant: Tenant, write_db: bool):
    """Migrate a workspace from v1 to v2."""
    root_workspace = Workspace.objects.create(name="root", description="Root workspace", tenant=tenant)
    # Org id represents the default workspace for now
    relationships = [
        create_relationship("workspace", tenant.org_id, "workspace", str(root_workspace.uuid), "parent"),
    ]
    # Include realm for tenant
    relationships.append(create_relationship("tenant", str(tenant.org_id), "realm", settings.ENV_NAME, "realm"))
    if write_db:
        write_relationships(relationships)
    return str(root_workspace.uuid), tenant.org_id


def migrate_users(tenant: Tenant, write_db: bool):
    """Write users relationship to tenant."""
    relationships = [
        create_relationship("tenant", str(tenant.org_id), "user", str(principal.uuid), "member")
        for principal in tenant.principal_set.all()
    ]
    if write_db:
        write_relationships(relationships)


def migrate_users_for_groups(tenant: Tenant, write_db: bool):
    """Write users relationship to groups."""
    relationships = []
    for group in tenant.group_set.all():
        # Explicitly create relationships for platform default group
        user_set = (
            tenant.principal_set.filter(cross_account=False) if group.platform_default else group.principals.all()
        )
        for user in user_set:
            relationships.append(create_relationship("group", str(group.uuid), "user", str(user.uuid), "member"))
    if write_db:
        write_relationships(relationships)


def migrate_data_for_tenant(tenant: Tenant, app_list: list, write_db: bool):
    """Migrate all data for a given tenant."""
    logger.info("Creating workspace.")
    root_workspace, default_workspace = migrate_workspace(tenant, write_db)
    logger.info("Workspace migrated.")

    logger.info("Relating users to tenant.")
    migrate_users(tenant, write_db)
    logger.info("Finished relationship between users and tenant.")

    logger.info("Migrating relations of group and user.")
    migrate_users_for_groups(tenant, write_db)
    logger.info("Finished migrating relations of group and user.")

    roles = tenant.role_set.all()
    if app_list:
        roles = roles.exclude(access__permission__application__in=app_list)

    for role in roles:
        logger.info(f"Migrating role: {role.name} with UUID {role.uuid}.")
        migrate_role(role, write_db, root_workspace, default_workspace)
        logger.info(f"Migration completed for role: {role.name} with UUID {role.uuid}.")
    logger.info(f"Migrated {roles.count()} roles for tenant: {tenant.org_id}")


def migrate_data(exclude_apps: list = [], orgs: list = [], write_db: bool = False):
    """Migrate all data for all tenants."""
    count = 0
    tenants = Tenant.objects.exclude(tenant_name="public")
    if orgs:
        tenants = tenants.filter(org_id__in=orgs)
    total = tenants.count()
    for tenant in tenants.iterator():
        logger.info(f"Migrating data for tenant: {tenant.org_id}")
        try:
            migrate_data_for_tenant(tenant, exclude_apps, write_db)
        except Exception as e:
            logger.error(f"Failed to migrate data for tenant: {tenant.org_id}. Error: {e}")
            raise e
        count += 1
        logger.info(f"Finished migrating data for tenant: {tenant.org_id}. {count} of {total} tenants completed")
    logger.info("Finished migrating data for all tenants")
