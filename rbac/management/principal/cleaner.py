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
from typing import Optional

import xmltodict
from django.conf import settings
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy, external_principal_to_user
from management.role.relation_api_dual_write_handler import OutboxReplicator
from management.tenant.model import TenantBootstrapService, V2TenantBootstrapService, get_tenant_bootstrap_service
from rest_framework import status
from stompest.config import StompConfig
from stompest.error import StompConnectionError
from stompest.protocol import StompSpec
from stompest.sync import Stomp

from api.models import Tenant, User


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

PROXY = PrincipalProxy()  # pylint: disable=invalid-name
CERT_LOC = "/opt/rbac/rbac/management/principal/umb_certs/cert.pem"
KEY_LOC = "/opt/rbac/rbac/management/principal/umb_certs/key.pem"


def clean_tenant_principals(tenant):
    """Check if all the principals in the tenant exist, remove non-existent principals."""
    removed_principals = []
    principals = list(Principal.objects.filter(type="user").filter(tenant=tenant))
    tenant_id = tenant.org_id
    logger.info(
        "clean_tenant_principals: Running clean up on %d principals for tenant %s.", len(principals), tenant_id
    )
    for principal in principals:
        if principal.cross_account:
            continue
        logger.debug("clean_tenant_principals: Checking for username %s for tenant %s.", principal.username, tenant_id)
        org_id = tenant.org_id
        resp = PROXY.request_filtered_principals([principal.username], org_id=org_id)
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
    removal_message = "clean_tenant_principals: Completed clean up of %d principals for tenant %s, %d removed: %s."
    logger.info(
        removal_message,
        len(principals),
        tenant_id,
        len(removed_principals),
        str(removed_principals),
    )


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
# Cert verification of IT host is failing complains about self-signed cert
# Since hot umb host it is within Red Hat network, we can trust the host
ssl_context.verify_mode = ssl.CERT_NONE
if os.path.isfile(CERT_LOC):
    ssl_context.load_cert_chain(CERT_LOC, keyfile=KEY_LOC)

CONFIG = StompConfig(f"ssl://{settings.UMB_HOST}:{settings.UMB_PORT}", sslContext=ssl_context)
QUEUE = f"/queue/Consumer.{settings.SA_NAME}.users-subscription.VirtualTopic.canonical.user"
UMB_CLIENT = Stomp(CONFIG)


def retrieve_user_info(message) -> User:
    """
    Retrieve user info from the message.

    returns:
        user: User object as of latest known state.
    """
    message_user = message["Payload"]["Sync"]["User"]
    identifiers = message_user["Identifiers"]
    user_id = identifiers["Identifier"]["#text"]

    bop_resp = PROXY.request_filtered_principals([user_id], options={"return_id": True})

    if not bop_resp["data"]:  # User has been deleted
        # Get data from message instead.
        user = User()
        user.user_id = user_id
        user.is_active = False
        user.admin = message_user.get("UserMembership") == {"Name": "admin:org:all"}
        user.username = message_user["Person"]["Credentials"]["Login"]
        for ref in identifiers["Reference"]:
            if ref["@entity-name"] == "Customer":
                user.org_id = ref["#text"]
                break
            if ref["@entity-name"] == "Account":
                user.account = ref["#text"]
                break
        return user

    user_data = bop_resp["data"][0]
    return external_principal_to_user(user_data)


def process_umb_event(frame, umb_client: Stomp, bootstrap_service: TenantBootstrapService):
    """Process each umb frame."""
    data_dict = xmltodict.parse(frame.body)
    canonical_message = data_dict.get("CanonicalMessage")
    if not canonical_message:
        # Message is malformed.
        # Ensure we dont block the entire queue by discarding it.
        umb_client.ack(frame)
        return
    try:
        user = retrieve_user_info(canonical_message)
    except Exception as e:  # Skip processing and leave the it to be processed later
        logger.error("process_umb_event: Error retrieving user info: %s", str(e))
        return

    # By default, only process disabled users.
    # If the setting is enabled, process all users.
    if not user.is_active or settings.PRINCIPAL_CLEANUP_UPDATE_ENABLED_UMB:
        bootstrap_service.update_user(user)
    umb_client.ack(frame)


def process_principal_events_from_umb(bootstrap_service: Optional[TenantBootstrapService] = None):
    """Process principals events from UMB."""
    logger.info("process_tenant_principal_events: Start processing principal events from umb.")
    bootstrap_service = bootstrap_service or get_tenant_bootstrap_service(OutboxReplicator())
    try:
        UMB_CLIENT.connect()
        UMB_CLIENT.subscribe(QUEUE, {StompSpec.ACK_HEADER: StompSpec.ACK_CLIENT_INDIVIDUAL})
    except StompConnectionError as e:
        # Skip if already connected/subscribed
        if not str(e).startswith(("Already connected", "Already subscribed")):
            raise e

    while UMB_CLIENT.canRead(2):  # Check if queue is empty, two sec timeout
        frame = UMB_CLIENT.receiveFrame()
        process_umb_event(frame, UMB_CLIENT, bootstrap_service)
    UMB_CLIENT.disconnect()
    logger.info("process_tenant_principal_events: Principal event processing finished.")
