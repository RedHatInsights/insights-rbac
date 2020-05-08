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

from django.db import connections

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def on_complete(future):
    """Explicitly close the connection for the thread."""
    connections.close_all()


def role_seeding():
    """Update any roles at startup."""
    # noqa: E402 pylint: disable=C0413
    from api.models import Tenant
    from management.role.definer import seed_roles
    from rbac.settings import MAX_SEED_THREADS

    logger.info('Start role seed changes check.')
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SEED_THREADS) as executor:
            for tenant in list(Tenant.objects.all()):
                if tenant.schema_name != 'public':
                    logger.info('Checking for role seed changes for tenant %s.', tenant.schema_name)
                    future = executor.submit(seed_roles, tenant, update=True)
                    future.add_done_callback(on_complete)
                    logger.info('Completed role seed changes for tenant %s.', future.result().schema_name)
    except Exception as exc:
        print('bam!!!')
        logger.error('Error encountered during role seeding %s.', exc)


def group_seeding():
    """Update platform group at startup."""
    # noqa: E402 pylint: disable=C0413
    from api.models import Tenant
    from management.group.definer import seed_group
    from rbac.settings import MAX_SEED_THREADS

    logger.info('Start group seed changes check.')
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SEED_THREADS) as executor:
            for tenant in list(Tenant.objects.all()):
                if tenant.schema_name != 'public':
                    logger.info('Checking for group seed changes for tenant %s.', tenant.schema_name)
                    future = executor.submit(seed_group, tenant)
                    future.add_done_callback(on_complete)
                    logger.info('Completed group seed changes for tenant %s.', future.result().schema_name)
    except Exception as exc:
        logger.error('Error encountered during group seeding %s.', exc)
