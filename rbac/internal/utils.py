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

import logging

from django.db import transaction
from django.urls import resolve
from management.relation_replicator.logging_replicator import stringify_spicedb_relationship
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType

from api.models import User


logger = logging.getLogger(__name__)


def build_internal_user(request, json_rh_auth):
    """Build user object for internal requests."""
    user = User()
    valid_identity_types = ["Associate", "X509"]
    try:
        identity_type = json_rh_auth["identity"]["type"]
        if not identity_type in valid_identity_types:
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
