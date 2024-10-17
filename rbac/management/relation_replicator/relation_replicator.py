#
# Copyright 2024 Red Hat, Inc.
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

"""Class to handle Dual Write API related operations."""
from abc import ABC, abstractmethod
from enum import Enum

from kessel.relations.v1beta1 import common_pb2


class DualWriteException(Exception):
    """DualWrite exception."""

    pass


class ReplicationEventType(str, Enum):
    """Replication event type."""

    CREATE_SYSTEM_ROLE = "create_system_role"
    UPDATE_SYSTEM_ROLE = "update_system_role"
    DELETE_SYSTEM_ROLE = "delete_system_role"
    CREATE_CUSTOM_ROLE = "create_custom_role"
    UPDATE_CUSTOM_ROLE = "update_custom_role"
    DELETE_CUSTOM_ROLE = "delete_custom_role"
    ASSIGN_ROLE = "assign_role"
    UNASSIGN_ROLE = "unassign_role"
    CREATE_GROUP = "create_group"
    UPDATE_GROUP = "update_group"
    DELETE_GROUP = "delete_group"
    ADD_PRINCIPALS_TO_GROUP = "add_principals_to_group"
    REMOVE_PRINCIPALS_FROM_GROUP = "remove_principals_from_group"
    BOOTSTRAP_TENANT = "bootstrap_tenant"
    EXTERNAL_USER_UPDATE = "external_user_update"
    MIGRATE_CUSTOM_ROLE = "migrate_custom_role"
    MIGRATE_TENANT_GROUPS = "migrate_tenant_groups"
    REMOVE_DEFAULT_BINDINGS = "remove_default_bindings"

class ReplicationEvent:
    """What tuples changes to replicate."""

    event_type: ReplicationEventType
    event_info: dict[str, object]
    partition_key: str
    add: list[common_pb2.Relationship]
    remove: list[common_pb2.Relationship]

    def __init__(
        self,
        event_type: ReplicationEventType,
        partition_key: str,
        add: list[common_pb2.Relationship] = [],
        remove: list[common_pb2.Relationship] = [],
        info: dict[str, object] = {},
    ):
        """Initialize ReplicationEvent."""
        self.partition_key = partition_key
        self.event_type = event_type
        self.add = add
        self.remove = remove
        self.event_info = info


class RelationReplicator(ABC):
    """Type responsible for replicating relations to Kessel Relations."""

    @abstractmethod
    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations."""
        pass
