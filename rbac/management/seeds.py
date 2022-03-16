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
import concurrent.futures
import logging
from functools import partial

from django.db import connections

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def on_complete(completed_log_message, future):
    """Explicitly close the connection for the thread."""
    connections.close_all()
    logger.info(completed_log_message)


def role_seeding():
    """Execute role seeding."""
    run_seeds("role")


def group_seeding():
    """Execute group seeding."""
    run_seeds("group")


def permission_seeding():
    """Execute permission seeding."""
    run_seeds("permission")


def run_seeds(seed_type):
    """Update platform objects at startup."""
    # noqa: E402 pylint: disable=C0413
    from management.group.definer import seed_group
    from management.role.definer import seed_roles, seed_permissions
    from rbac.settings import MAX_SEED_THREADS

    seed_functions = {"role": seed_roles, "group": seed_group, "permission": seed_permissions}

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SEED_THREADS) as executor:

            logger.info(f"Seeding {seed_type} changes.")
            future = executor.submit(seed_functions[seed_type])
            completed_log_message = f"Finished seeding {seed_type} changes."
            future.add_done_callback(partial(on_complete, completed_log_message))
    except Exception as exc:
        logger.error(f"Error encountered during {seed_type} seeding {exc}.")
