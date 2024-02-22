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
from django.db import transaction
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from management.utils import account_id_for_tenant
from rest_framework import status

from api.models import Tenant
from rbac.settings import PRINCIPAL_CLEANUP_DELETION_ENABLED

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

proxy = PrincipalProxy()  # pylint: disable=invalid-name


def clean_tenant_principals(tenant):
    """Check if all the principals in the tenant exist, remove non-existent principals."""
    removed_principals = []
    principals = list(Principal.objects.filter(type="user").filter(tenant=tenant))
    if settings.AUTHENTICATE_WITH_ORG_ID:
        tenant_id = tenant.org_id
    else:
        tenant_id = tenant.tenant_name
    logger.info(
        "clean_tenant_principals: Running clean up on %d principals for tenant %s.", len(principals), tenant_id
    )
    for principal in principals:
        if principal.cross_account:
            continue
        logger.debug("clean_tenant_principals: Checking for username %s for tenant %s.", principal.username, tenant_id)
        account = account_id_for_tenant(tenant)
        org_id = tenant.org_id
        if settings.AUTHENTICATE_WITH_ORG_ID:
            resp = proxy.request_filtered_principals([principal.username], org_id=org_id)
        else:
            resp = proxy.request_filtered_principals([principal.username], account=account)
        status_code = resp.get("status_code")
        data = resp.get("data")
        logger.info("clean_tenant_principals: Response code: %s Data: %s", str(status_code), str(data))
        if status_code == status.HTTP_200_OK and data:
            logger.debug(
                "clean_tenant_principals: Username %s found for tenant %s, no change needed.",
                principal.username,
                tenant_id,
            )
        elif status_code == status.HTTP_200_OK and not data:
            removed_principals.append(principal.username)
            logger.info(
                "clean_tenant_principals: Username %s not found for tenant %s, principal eligible for removal.",
                principal.username,
                tenant_id,
            )
            # we are temporarily disabling the delete
            if PRINCIPAL_CLEANUP_DELETION_ENABLED:
                principal.delete()
                logger.info(
                    "clean_tenant_principals: Username %s removed.",
                    principal.username,
                )
        else:
            logger.warning(
                "clean_tenant_principals: Unknown status %d when checking username %s"
                " for tenant %s, no change needed.",
                status_code,
                principal.username,
                tenant_id,
            )
    removal_message = "clean_tenant_principals: Completed clean up of %d principals for tenant %s, %d eligible for removal: %s."  # noqa E501
    if PRINCIPAL_CLEANUP_DELETION_ENABLED:
        removal_message = "clean_tenant_principals: Completed clean up of %d principals for tenant %s, %d removed: %s."
    logger.info(
        removal_message,
        len(principals),
        tenant_id,
        len(removed_principals),
        str(removed_principals),
    )


def populate_principal_user_ids(tenant):
    """Populate the user_id field for user-based principals."""
    principals = list(Principal.objects.filter(type="user").filter(tenant=tenant).filter(user_id=None))
    if settings.AUTHENTICATE_WITH_ORG_ID:
        tenant_id = tenant.org_id
    else:
        tenant_id = tenant.tenant_name
    logger.info(
        "populate_principal_user_ids: Populating user_id on %d principals for tenant %s.", len(principals), tenant_id
    )
    for principal in principals:
        if principal.cross_account:
            continue
        logger.debug(
            "populate_principal_user_ids: Checking BOP for user_id for username %s for tenant %s.",
            principal.username,
            tenant_id,
        )
        account = account_id_for_tenant(tenant)
        org_id = tenant.org_id
        if settings.AUTHENTICATE_WITH_ORG_ID:
            resp = proxy.request_filtered_principals([principal.username], org_id=org_id)
        else:
            resp = proxy.request_filtered_principals([principal.username], account=account)
        status_code = resp.get("status_code")
        data = resp.get("data")
        logger.info("populate_principal_user_ids: Response code: %s Data: %s", str(status_code), str(data))
        if status_code == status.HTTP_200_OK and data:
            user_id = data.get("id")
            logger.debug(
                "populate_principal_user_ids: user_id %s found for username %s for tenant %s.",
                user_id,
                principal.username,
                tenant_id,
            )
            with transaction.atomic():
                principal.user_id = user_id
                principal.save()
        elif status_code == status.HTTP_200_OK and not data:
            logger.info(
                "populate_principal_user_ids: No data found for username %s for tenant %s.",
                principal.username,
                tenant_id,
            )
        else:
            logger.warning(
                "populate_principal_user_ids: Unknown status %d when checking username %s" " for tenant %s.",
                status_code,
                principal.username,
                tenant_id,
            )
    population_message = (
        "populate_principal_user_ids: Completed user_id population of %d principals for tenant %s."  # noqa E501
    )
    logger.info(population_message, len(principals), tenant_id)


def clean_tenants_principals():
    """Check which principals are eligible for clean up."""
    logger.info("clean_tenant_principals: Start principal clean up.")

    for tenant in list(Tenant.objects.all()):
        logger.info("clean_tenant_principals: Running principal clean up for tenant %s.", tenant.tenant_name)
        clean_tenant_principals(tenant)
        logger.info("clean_tenant_principals: Completed principal clean up for tenant %s.", tenant.tenant_name)

    logger.info("clean_tenant_principals: Principal cleanup complete for all tenants.")


def populate_principals_user_ids():
    """Populate eligible user-principals with user_id."""
    logger.info("populate_principal_user_id: Starting user_id population.")

    for tenant in list(Tenant.objects.all()):
        logger.info("populate_principal_user_id: Running user_id population for tenant %s.", tenant.tenant_name)
        populate_principal_user_ids(tenant)
        logger.info("populate_principal_user_id: Completed user_id population for tenant %s.", tenant.tenant_name)

    logger.info("populate_principal_user_id: user_id population complete for all tenants.")
