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

from management.role.model import Role
from migration_tool.migrator import Migrator
from migration_tool.models import Relationship, V1group, V2rolebinding
from migration_tool.sharedSystemRolesReplicatedRoleBindings import (
    shared_system_role_replicated_role_bindings_v1_to_v2_mapping,
)

from api.models import Tenant
from .ingest import extract_info_into_v1_role

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def spicedb_relationships(v2_role_bindings: FrozenSet[V2rolebinding]):
    """Generate a set of relationships for the given set of v2 role bindings."""
    relationships = set[Relationship]()
    for v2_role_binding in v2_role_bindings:
        relationships.add(
            Relationship(
                "role_binding",
                v2_role_binding.id,
                "granted",
                "role",
                v2_role_binding.role.id,
            )
        )
        relationships.add(
            Relationship("rbac/v1role", v2_role_binding.originalRole.id, "binding", "role_binding", v2_role_binding.id)
        )
        for perm in v2_role_binding.role.permissions:
            relationships.add(Relationship("role", v2_role_binding.role.id, perm, "user", "*"))
        if not v2_role_binding.role.is_system:
            relationships.add(
                Relationship(
                    "rbac/v1role", v2_role_binding.originalRole.id, "customrole", "role", v2_role_binding.role.id
                )
            )
        for group in v2_role_binding.groups:
            # These might be duplicate but it is OK, spiceDB will handle duplication through touch
            for user in group.users:
                relationships.add(Relationship("group", group.id, "member", "user", user))
            relationships.add(
                Relationship(
                    "role_binding",
                    v2_role_binding.id,
                    "member",
                    "group",
                    group.id,
                )
            )

        for bound_resource in v2_role_binding.resources:
            parent_relation = "parent" if bound_resource.resource_type == "workspace" else "workspace"
            # TODO: create root workspace and replace it
            if not bound_resource.resource_type == "workspace" and bound_resource.resourceId == "org_migration_root":
                relationships.add(
                    Relationship(
                        bound_resource.resource_type,
                        bound_resource.resourceId,
                        parent_relation,
                        "workspace",
                        "org_migration_root",
                    )
                )
            relationships.add(
                Relationship(
                    bound_resource.resource_type,
                    bound_resource.resourceId,
                    "user_grant",
                    "role_binding",
                    v2_role_binding.id,
                )
            )

    return relationships


def stringify_spicedb_relationship(rel: Relationship):
    """Stringify a relationship for logging."""
    return (
        rel.resource_type + ":" + rel.resource_id + "#" + rel.relation + "@" + rel.subject_type + ":" + rel.subject_id
    )


def migrate_role(role: Role):
    """Migrate a role from v1 to v2."""
    v1_role = extract_info_into_v1_role(role)
    # With the replicated role bindings algorithm, role bindings are scoped by group, so we need to add groups
    # TODO: replace the hard coded groups
    policies = role.policies.all()
    groups = frozenset(
        {
            V1group(str(policy.group.uuid), frozenset(policy.group.principals.values_list("uuid", flat=True))),
        }
        for policy in policies
    )
    v1_role = dataclasses.replace(v1_role, groups=groups)

    # This is where we wire in the implementation we're using into the Migrator
    v1_to_v2_mapping = shared_system_role_replicated_role_bindings_v1_to_v2_mapping
    permissioned_role_migrator = Migrator(v1_to_v2_mapping)
    v2_roles = [v2_role for v2_role in permissioned_role_migrator.migrate_v1_roles(v1_role)]
    spicedb_rel_summary = spicedb_relationships(frozenset(v2_roles))
    for rel in spicedb_rel_summary:
        logger.info(stringify_spicedb_relationship(rel))


def migrate_roles_for_tenant(tenant: Tenant, app_list: list):
    """Migrate all roles for a given tenant."""
    roles = tenant.role_set.all()
    if app_list:
        roles = roles.exclude(access__permission__application__in=app_list)

    for role in roles:
        logger.info(f"Migrating role: {role.name} with UUID {role.uuid}.")
        migrate_role(role)
        logger.info(f"Migration completed for role: {role.name} with UUID {role.uuid}.")
    logger.info(f"Migrated {roles.count()} roles for tenant: {tenant.org_id}")


def migrate_roles(exclude_apps: list = [], orgs: list = []):
    """Migrate all roles for all tenants."""
    count = 0
    tenants = Tenant.objects.exclude(tenant_name="public")
    if orgs:
        tenants = tenants.filter(org_id__in=orgs)
    total = tenants.count()
    for tenant in tenants.iterator():
        logger.info(f"Migrating roles for tenant: {tenant.org_id}")
        try:
            migrate_roles_for_tenant(tenant, exclude_apps)
        except Exception as e:
            logger.error(f"Failed to migrate roles for tenant: {tenant.org_id}. Error: {e}")
            raise e
        count += 1
        logger.info(f"Finished migrating roles for tenant: {tenant.org_id}. {count} of {total} tenants completed")
    logger.info("Finished migrating roles for all tenants")
