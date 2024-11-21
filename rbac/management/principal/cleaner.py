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
from django.db import connection, transaction
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy, external_principal_to_user
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.tenant_service import get_tenant_bootstrap_service
from management.tenant_service.tenant_service import TenantBootstrapService
from prometheus_client import Counter
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
LOCK_ID = 42  # For Keith, with Love

METRIC_STOMP_MESSAGE_TOTAL = "stomp_messages_total"
umb_message_processed_count = Counter(
    METRIC_STOMP_MESSAGE_TOTAL,
    "Number of stomp UMB messages processed",
)


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
    instance_id: Optional[str] = None

    if (header := message.get("Header")) is not None:
        if (id := header.get("InstanceId")) is not None:
            instance_id = id

    logger.debug("retrieve_user_info: Processing message with instance_id=%s", instance_id)

    message_user = message["Payload"]["Sync"]["User"]
    identifiers = message_user["Identifiers"]
    user_id: Optional[str] = None

    if isinstance((ids := identifiers["Identifier"]), list):
        for id in ids:  # type: ignore
            if id["@system"] == "WEB" and id["@entity-name"] == "User" and id["@qualifier"] == "id":
                user_id = id["#text"]
                break
    else:
        user_id = identifiers["Identifier"]["#text"]

    if user_id is None:
        raise ValueError("User id not found in message. instance_id=%s", instance_id)

    bop_resp = PROXY.request_filtered_principals([user_id], options={"query_by": "user_id", "return_id": True})

    if not bop_resp["data"]:  # User has been deleted
        # Get data from message instead.
        user = User()
        user.user_id = user_id
        user.is_active = False
        user.username = message_user["Person"]["Credentials"]["Login"]
        # identifiers["Reference"] might be a dict
        if not isinstance((refs := identifiers["Reference"]), list):
            refs = [identifiers["Reference"]]
        for ref in refs:
            if ref["@system"] == "WEB" and ref["@entity-name"] == "Customer" and ref["@qualifier"] == "id":
                user.org_id = ref["#text"]
                break
            if ref["@system"] == "EBS" and ref["@entity-name"] == "Account" and ref["@qualifier"] == "number":
                user.account = ref["#text"]
                break

        return user

    user_data = bop_resp["data"][0]
    return external_principal_to_user(user_data)


def process_umb_event(frame, umb_client: Stomp, bootstrap_service: TenantBootstrapService) -> bool:
    """
    Process each umb frame.

    If the process should continue to listen for more frames, return True. Otherwise, return False.
    """
    with transaction.atomic():
        # This is locked per transaction to ensure another listener process does not run concurrently.
        if not _lock_listener():
            # If there is another listener, let it run and abort this one.
            logger.info("process_umb_event: Another listener is running. Aborting.")
            return False

        data_dict = xmltodict.parse(frame.body)
        canonical_message = data_dict.get("CanonicalMessage")
        if not canonical_message:
            # Message is malformed.
            # Ensure we dont block the entire queue by discarding it.
            umb_client.ack(frame)
            return True
        try:
            user = retrieve_user_info(canonical_message)
        except Exception as e:  # Skip processing and leave the it to be processed later
            logger.error("process_umb_event: Error retrieving user info: %s", str(e))
            return True

        # By default, only process disabled users.
        # If the setting is enabled, process all users.
        if not user.is_active or settings.PRINCIPAL_CLEANUP_UPDATE_ENABLED_UMB:
            bootstrap_service.update_user(user)

    umb_client.ack(frame)
    return True


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

    try:
        while UMB_CLIENT.canRead(15):  # Check if queue is empty, 15 sec timeout
            frame = UMB_CLIENT.receiveFrame()
            if not process_umb_event(frame, UMB_CLIENT, bootstrap_service):
                break
            umb_message_processed_count.inc()
    finally:
        UMB_CLIENT.disconnect()
        logger.info("process_tenant_principal_events: Principal event processing finished.")


def _lock_listener() -> bool:
    """Attempt to acquire a lock for the listener and if acquired return True, else False."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_xact_lock(%s);", [LOCK_ID])
        result = cursor.fetchone()
    if result is None:
        raise Exception("Advisory lock returned none, expected bool.")
    return result[0]  # Returns True if lock acquired, False otherwise
