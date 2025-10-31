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


def role_seeding(force_create_relationships: bool = False, force_update_relationships: bool = False):
    """Execute role seeding."""
    _run_seeds(
        "role",
        force_create_relationships=force_create_relationships,
        force_update_relationships=force_update_relationships,
    )


def group_seeding():
    """Execute group seeding."""
    _run_seeds("group")


def permission_seeding():
    """Execute permission seeding."""
    _run_seeds("permission")


def _run_seeds(seed_type, **kwargs):
    """Update platform objects at startup."""
    # noqa: E402 pylint: disable=C0413
    from management.group.definer import seed_group
    from management.role.definer import seed_roles, seed_permissions

    seed_functions = {"role": seed_roles, "group": seed_group, "permission": seed_permissions}

    try:
        logger.info(f"Seeding {seed_type} changes.")
        seed_functions[seed_type](**kwargs)
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
