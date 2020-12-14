#
# Copyright 2019 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

"""Handler for principal clean up."""
import logging

from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from rest_framework import status
from tenant_schemas.utils import tenant_context

from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

proxy = PrincipalProxy()  # pylint: disable=invalid-name


def clean_tenant_principals(tenant):
    """Check if all the principals in the tenant exist, remove non-existent principals."""
    with tenant_context(tenant):
        removed_principals = []
        principals = list(Principal.objects.all())
        logger.info("Running clean up on %d principals for tenant %s.", len(principals), tenant.schema_name)
        for principal in principals:
            logger.debug("Checking for username %s for tenant %s.", principal.username, tenant.schema_name)
            resp = proxy.request_filtered_principals([principal.username])
            status_code = resp.get("status_code")
            data = resp.get("data")
            if status_code == status.HTTP_200_OK and data:
                logger.debug(
                    "Username %s found for tenant %s, no change needed.", principal.username, tenant.schema_name
                )
            elif status_code == status.HTTP_200_OK and not data:
                removed_principals.append(principal.username)
                principal.delete()
                logger.info(
                    "Username %s not found for tenant %s, principal removed.", principal.username, tenant.schema_name
                )
            else:
                logger.warn(
                    "Unknown status %d when checking username %s" " for tenant %s, no change needed.",
                    status_code,
                    principal.username,
                    tenant.schema_name,
                )
        logger.info(
            "Completed clean up of %d principals for tenant %s, %d removed.",
            len(principals),
            tenant.schema_name,
            len(removed_principals),
        )


def clean_tenants_principals():
    """Update any roles at startup."""
    logger.info("Start principal clean up.")

    for tenant in list(Tenant.objects.all()):
        logger.info("Running principal clean up for tenant %s.", tenant.schema_name)
        clean_tenant_principals(tenant)
        logger.info("Completed principal clean up for tenant %s.", tenant.schema_name)
