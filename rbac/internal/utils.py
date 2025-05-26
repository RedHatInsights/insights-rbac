#
# Copyright 2022 Red Hat, Inc.
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

"""Utilities for Internal RBAC use."""

import json
import logging

from django.db import transaction
from django.urls import resolve
from management.cache import JWTCache
from management.models import Workspace
from management.relation_replicator.logging_replicator import stringify_spicedb_relationship
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType
from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspaceHandler

from api.models import User


logger = logging.getLogger(__name__)
JWT = JWTCache()


def build_internal_user(request, json_rh_auth):
    """Build user object for internal requests."""
    user = User()
    valid_identity_types = ["Associate", "X509"]
    try:
        identity_type = json_rh_auth["identity"]["type"]
        if identity_type not in valid_identity_types:
            logger.debug(
                f"User identity type is not valid: '{identity_type}'. Valid types are: {valid_identity_types}"
            )
            return None
        user.username = json_rh_auth["identity"].get("associate", {}).get("email", "system")
        user.admin = True
        user.org_id = resolve(request.path).kwargs.get("org_id")
        return user
    except KeyError:
        logger.debug(
            f"Identity object is missing 'identity.type' attribute. Valid options are: {valid_identity_types}"
        )
        return None


def delete_bindings(bindings):
    """
    Delete the provided bindings and replicate the deletion event.

    Args:
        bindings (QuerySet): A Django QuerySet of binding objects to be deleted.

    Returns:
        dict: A dictionary containing information about the deleted bindings, including:
            - mappings (list): A list of mappings for each binding.
            - role_ids (list): A list of role IDs for each binding.
            - resource_ids (list): A list of resource IDs for each binding.
            - resource_types (list): A list of resource type names for each binding.
            - relations (list): A list of tuples representing the relations to be removed.
    """
    replicator = OutboxReplicator()
    info = {
        "mappings": [binding.mappings for binding in bindings],
        "role_ids": [binding.role_id for binding in bindings],
        "resource_ids": [binding.resource_id for binding in bindings],
        "resource_types": [binding.resource_type_name for binding in bindings],
    }
    if bindings:
        with transaction.atomic():
            relations_to_remove = []
            for binding in bindings:
                relations_to_remove.extend(binding.as_tuples())
            replicator.replicate(
                ReplicationEvent(
                    event_type=ReplicationEventType.DELETE_BINDING_MAPPINGS,
                    info=info,
                    partition_key=PartitionKey.byEnvironment(),
                    remove=relations_to_remove,
                ),
            )
            bindings.delete()
        info["relations"] = [stringify_spicedb_relationship(relation) for relation in relations_to_remove]
    return info


def get_jwt_token(conn, grant_type, client_id, client_secret, scopes, url):
    """Retrieve jwt token from Redhat SSO."""
    payload = f"grant_type={grant_type}&client_id={client_id}&client_secret={client_secret}&scope={scopes}"

    headers = {"content-type": "application/x-www-form-urlencoded"}

    conn.request("POST", url, payload, headers)

    res = conn.getresponse()
    data = res.read()
    json_data = json.loads(data)

    token = json_data["access_token"]
    return token


def get_jwt_from_redis(conn, grant_type, client_id, client_secret, scopes, url):
    """Retrieve jwt token from redis or generate from Redhat SSO if not exists in redis."""
    # Test the connection
    if conn is None:
        return None
    try:
        # Try retrieve token from redis
        token = JWT.get_jwt_response()

        # If token not is redis
        if not token:
            token = get_jwt_token(conn, grant_type, client_id, client_secret, scopes, url)
            # Token obtained store it in redis
            if token:
                JWT.set_jwt_response(token)
                logger.info("Token stored in redis.")
            else:
                logger.error("Failed to store jwt token in redis.")
        else:
            # Token exists return it
            logger.info("Token retrieved from redis.")
        return token

    except Exception as e:
        logger.error(f"error occurred when trying to retrieve JWT token. {e}")
        return None


@transaction.atomic
def get_or_create_ungrouped_workspace(tenant: str) -> Workspace:
    """
    Retrieve the ungrouped workspace for the given tenant.

    Args:
        tenant (str): The tenant for which to retrieve the ungrouped workspace.
    Returns:
        Workspace: The ungrouped workspace object for the given tenant.
    """
    # fetch parent only once
    default_ws = Workspace.objects.get(tenant=tenant, type=Workspace.Types.DEFAULT)
    # single select_for_update + get_or_create
    workspace, created = Workspace.objects.select_for_update().get_or_create(
        tenant=tenant,
        type=Workspace.Types.UNGROUPED_HOSTS,
        defaults={"name": Workspace.SpecialNames.UNGROUPED_HOSTS, "parent": default_ws},
    )
    if created:
        RelationApiDualWriteWorkspaceHandler(
            workspace, ReplicationEventType.CREATE_WORKSPACE
        ).replicate_new_workspace()
    return workspace
