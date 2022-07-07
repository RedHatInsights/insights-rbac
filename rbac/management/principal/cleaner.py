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

from django.conf import settings
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from management.utils import account_id_for_tenant
from rest_framework import status

from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

proxy = PrincipalProxy()  # pylint: disable=invalid-name


def clean_tenant_principals(tenant):
    """Check if all the principals in the tenant exist, remove non-existent principals."""
    removed_principals = []
    principals = list(Principal.objects.filter(tenant=tenant))
    if settings.AUTHENTICATE_WITH_ORG_ID:
        tenant_id = tenant.org_id
    else:
        tenant_id = tenant.tenant_name
    logger.info("Running clean up on %d principals for tenant %s.", len(principals), tenant_id)
    for principal in principals:
        if principal.cross_account:
            continue
        logger.debug("Checking for username %s for tenant %s.", principal.username, tenant_id)
        account = account_id_for_tenant(tenant)
        org_id = tenant.org_id
        if settings.AUTHENTICATE_WITH_ORG_ID:
            resp = proxy.request_filtered_principals([principal.username], org_id=org_id)
        else:
            resp = proxy.request_filtered_principals([principal.username], account=account)
        status_code = resp.get("status_code")
        data = resp.get("data")
        if status_code == status.HTTP_200_OK and data:
            logger.debug("Username %s found for tenant %s, no change needed.", principal.username, tenant_id)
        elif status_code == status.HTTP_200_OK and not data:
            removed_principals.append(principal.username)
            principal.delete()
            logger.info("Username %s not found for tenant %s, principal removed.", principal.username, tenant_id)
        else:
            logger.warn(
                "Unknown status %d when checking username %s" " for tenant %s, no change needed.",
                status_code,
                principal.username,
                tenant_id,
            )
    logger.info(
        "Completed clean up of %d principals for tenant %s, %d removed.",
        len(principals),
        tenant_id,
        len(removed_principals),
    )


def clean_tenants_principals():
    """Update any roles at startup."""
    logger.info("Start principal clean up.")

    for tenant in list(Tenant.objects.all()):
        logger.info("Running principal clean up for tenant %s.", tenant.tenant_name)
        clean_tenant_principals(tenant)
        logger.info("Completed principal clean up for tenant %s.", tenant.tenant_name)
