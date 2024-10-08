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
from django.conf import settings
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from management.principal.utils import (
    create_tenant_relationships,
    create_user_relationships,
    remove_user_relationships,
)
from rest_framework import status
from stompest.config import StompConfig
from stompest.error import StompConnectionError
from stompest.protocol import StompSpec
from stompest.sync import Stomp

from api.models import Tenant


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


def process_principal_deletion(user_data):
    """Process the principal deletion."""
    # TODO: cleanup the relationships in spicedb
    user_id = user_data["user_id"]
    groups = []
    tenant = Tenant.objects.get(org_id=user_data["org_id"])
    principal = Principal.objects.filter(username=user_data["username"], tenant=tenant).first()
    if not principal:  # User not in RBAC
        return

    # Log the group info in case it is needed
    for group in principal.group.all():
        groups.append(group)
        # We have to do the removal explicitly in order to clear the cache,
        # or the console will still show the cached number of members
        group.principals.remove(principal)
    principal.delete()
    remove_user_relationships(tenant, groups, principal, user_data["is_org_admin"])
    if not groups:
        logger.info(f"Principal {user_id} was not under any groups.")
    for group in groups:
        logger.info(f"Principal {user_id} was in group with uuid: {group.uuid}")


def process_principal_edit(user_data):
    """Process the principal update."""
    org_id = user_data["org_id"]
    tenant_name = f"org{org_id}"
    tenant, created = Tenant.objects.get_or_create(org_id=org_id, defaults={"ready": True, "tenant_name": tenant_name})
    if created:
        create_tenant_relationships(tenant)
    principal, created = Principal.objects.get_or_create(
        username=user_data["username"],
        tenant=tenant,
        defaults={"user_id": user_data["user_id"]},
    )
    if created:
        create_user_relationships(principal, user_data["is_org_admin"])


def retrieve_user_info(message):
    """
    Retrieve user info from the message.

    returns:
        user_data
        is_deleted  # Has the user been deleted on IT's side
    """
    user = message["Payload"]["Sync"]["User"]
    identifiers = user["Identifiers"]
    user_id = identifiers["Identifier"]["#text"]

    bop_resp = PROXY.request_filtered_principals([user_id], options={"return_id": True})
    if not bop_resp["data"]:  # User has been deleted
        is_org_admin = user.get("UserMembership") == {"Name": "admin:org:all"}
        user_name = user["Person"]["Credentials"]["Login"]
        for ref in identifiers["Reference"]:
            if ref["@entity-name"] == "Customer":
                org_id = ref["#text"]
                break
        return {"user_id": user_id, "is_org_admin": is_org_admin, "username": user_name, "org_id": org_id}, True
    return bop_resp["data"][0], False


def process_principal_data(user_data, is_deleted):
    """Process the principal data."""
    if is_deleted:
        process_principal_deletion(user_data)
    else:
        process_principal_edit(user_data)


def process_umb_event(frame, umb_client):
    """Process each umb frame."""
    data_dict = xmltodict.parse(frame.body)
    canonical_message = data_dict.get("CanonicalMessage")
    if not canonical_message:
        return
    try:
        user_data, is_deleted = retrieve_user_info(canonical_message)
    except Exception as e:  # Skip processing and leave the it to be processed later
        logger.error("process_umb_event: Error retrieving user info: %s", str(e))
        return

    process_principal_data(user_data, is_deleted)

    umb_client.ack(frame)


def process_principal_events_from_umb():
    """Process principals events from UMB."""
    logger.info("process_tenant_principal_events: Start processing principal events from umb.")
    try:
        UMB_CLIENT.connect()
        UMB_CLIENT.subscribe(QUEUE, {StompSpec.ACK_HEADER: StompSpec.ACK_CLIENT_INDIVIDUAL})
    except StompConnectionError as e:
        # Skip if already connected/subscribed
        if not str(e).startswith(("Already connected", "Already subscribed")):
            raise e

    while UMB_CLIENT.canRead(2):  # Check if queue is empty, two sec timeout
        frame = UMB_CLIENT.receiveFrame()
        process_umb_event(frame, UMB_CLIENT)
    UMB_CLIENT.disconnect()
    logger.info("process_tenant_principal_events: Principal event processing finished.")
