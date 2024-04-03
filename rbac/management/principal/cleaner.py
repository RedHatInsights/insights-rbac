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
import os
import ssl

import xmltodict
from celery import shared_task
from django.conf import settings
from management.group.view import TYPE_SERVICE_ACCOUNT
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from management.utils import account_id_for_tenant
from rest_framework import status
from stompest.config import StompConfig
from stompest.protocol import StompSpec
from stompest.sync import Stomp

from api.models import Tenant


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

proxy = PrincipalProxy()  # pylint: disable=invalid-name
CERT_LOC = "/opt/rbac/management/principal/umb_certs/cert.pem"
KEY_LOC = "/opt/rbac/management/principal/umb_certs/key.pem"


# TODO: Rmove the old way to clean the principals
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
            if settings.PRINCIPAL_CLEANUP_DELETION_ENABLED:
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
    if settings.PRINCIPAL_CLEANUP_DELETION_ENABLED:
        removal_message = "clean_tenant_principals: Completed clean up of %d principals for tenant %s, %d removed: %s."
    logger.info(
        removal_message,
        len(principals),
        tenant_id,
        len(removed_principals),
        str(removed_principals),
    )


# TODO: Rmove the old way to clean the principals
def clean_tenants_principals():
    """Check which principals are eligible for clean up."""
    logger.info("clean_tenant_principals: Start principal clean up.")

    for tenant in list(Tenant.objects.all()):
        logger.info("clean_tenant_principals: Running principal clean up for tenant %s.", tenant.tenant_name)
        clean_tenant_principals(tenant)
        logger.info("clean_tenant_principals: Completed principal clean up for tenant %s.", tenant.tenant_name)

    logger.info("clean_tenant_principals: Principal cleanup complete for all tenants.")


ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
if os.path.isfile(CERT_LOC):
    ssl_context.load_cert_chain(CERT_LOC, keyfile=KEY_LOC)

CONFIG = StompConfig(f"ssl://{settings.UMB_HOST}:{settings.UMB_PORT}", sslContext=ssl_context)
QUEUE = f"/queue/Consumer.{settings.SA_NAME}.users-subscription.VirtualTopic.canonical.user"
UMB_CLIENT = Stomp(CONFIG)


def is_umb_deactivate_msg(data_dict):
    """Check if the message is a user deactivation message from UMB."""
    if not data_dict.get("CanonicalMessage"):  # Skip if it is not CanonicalMessage
        return False
    # We only care about disabled user, operation == update and status == Inactive
    operation = data_dict["CanonicalMessage"].get("Header", {}).get("Operation")
    if operation != "update":
        return False
    status = data_dict["CanonicalMessage"].get("Payload", {}).get("Sync").get("User", {}).get("Status", {})
    if status.get("@primary") != "true" or status.get("State") != "Inactive":
        return False

    return True


def clean_principal_umb(data_dict):
    """Delete the principal if it exists."""
    user_principal_login = data_dict["CanonicalMessage"]["Payload"]["Sync"]["User"]["Person"]["Credentials"]["Login"]
    # In case the user is under multiple account
    principals = (
        Principal.objects.filter(username=user_principal_login)
        .exclude(cross_account=True)
        .exclude(type=TYPE_SERVICE_ACCOUNT)
    )
    for principal in principals:
        # Log the group info in case it is needed
        logger.info(f"Principal was under these groups: {principal.group.values_list('name', flat=True)}")
        principal.delete()


@shared_task
def clean_principals_via_umb():
    """Check which principals are eligible for clean up via UMB."""
    if not settings.PRINCIPAL_CLEANUP_DELETION_ENABLED_UMB:
        logger.info("clean_tenant_principals: Principal clean up via UMB disabled.")
        return
    logger.info("clean_tenant_principals: Start principal clean up.")
    UMB_CLIENT.connect()
    UMB_CLIENT.subscribe(QUEUE, {StompSpec.ACK_HEADER: StompSpec.ACK_CLIENT_INDIVIDUAL})
    while UMB_CLIENT.canRead(0):  # Check if queue is empty
        frame = UMB_CLIENT.receiveFrame()
        data_dict = xmltodict.parse(frame.body)
        is_deactivate = is_umb_deactivate_msg(data_dict)
        if not is_deactivate:
            # Drop the message cause it is not useless for us
            UMB_CLIENT.ack(frame)
            continue
        clean_principal_umb(data_dict)
        UMB_CLIENT.ack(frame)  # This will remove the message from the queue
    UMB_CLIENT.disconnect()
    logger.info("clean_tenant_principals: Principal clean up finished.")
