#
# Copyright 2019 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Seeds module."""
import logging

from django.db import connections
from management.cache import AccessCache

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def role_seeding(force_create_relationships=False):
    """Execute role seeding."""
    run_seeds("role", force_create_relationships)


def v2_role_seeding():
    """Execute V2 role seeding."""
    run_seeds("role_v2")


def role_binding_seeding():
    """Execute V2 role binding seeding."""
    run_seeds("role_binding")


def role_binding_group_seeding():
    """Execute V2 role binding group seeding."""
    run_seeds("role_binding_group")


def group_seeding():
    """Execute group seeding."""
    run_seeds("group")


def permission_seeding():
    """Execute permission seeding."""
    run_seeds("permission")


def workspace_seeding():
    """Execute workspace seeding."""
    run_seeds("workspace")


def run_seeds(seed_type, force_create_relationships=False):
    """Update platform objects at startup."""
    # noqa: E402 pylint: disable=C0413
    from management.group.definer import seed_group
    from management.role.definer import (
        seed_permissions,
        seed_role_binding_groups,
        seed_role_bindings,
        seed_roles,
        seed_v2_roles,
    )
    from management.workspace.definer import seed_workspaces

    seed_functions = {
        "role": seed_roles,
        "group": seed_group,
        "permission": seed_permissions,
        "workspace": seed_workspaces,
        "role_v2": seed_v2_roles,
        "role_binding": seed_role_bindings,
        "role_binding_group": seed_role_binding_groups,
    }

    try:
        logger.info(f"Seeding {seed_type} changes.")
        if force_create_relationships:
            seed_functions[seed_type](force_create_relationships)
        else:
            seed_functions[seed_type]()
        logger.info(f"Finished seeding {seed_type}.")
    except Exception as exc:
        logger.error(f"Error encountered during {seed_type} seeding {exc}.")


def purge_cache_for_all_tenants():
    """Explicitly purge the cache."""
    logger.info("Purging policy cache for all tenants.")
    cache = AccessCache("*")
    cache.delete_all_policies_for_tenant()
    connections.close_all()
    logger.info("Finished purging policy cache for all tenants.")
