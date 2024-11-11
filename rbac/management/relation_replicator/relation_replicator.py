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

from django.conf import settings
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
    BULK_BOOTSTRAP_TENANT = "bulk_bootstrap_tenant"
    EXTERNAL_USER_UPDATE = "external_user_update"
    BULK_EXTERNAL_USER_UPDATE = "bulk_external_user_update"
    MIGRATE_CUSTOM_ROLE = "migrate_custom_role"
    MIGRATE_TENANT_GROUPS = "migrate_tenant_groups"
    CUSTOMIZE_DEFAULT_GROUP = "customize_default_group"
    MIGRATE_SYSTEM_ROLE_ASSIGMENT = "migrate_system_role_assignment"
    APPROVE_CROSS_ACCOUNT_REQUEST = "approve_cross_account_request"
    EXPIRE_CROSS_ACCOUNT_REQUEST = "expire_cross_account_request"


class ReplicationEvent:
    """What tuples changes to replicate."""

    event_type: ReplicationEventType
    event_info: dict[str, object]
    partition_key: "PartitionKey"
    add: list[common_pb2.Relationship]
    remove: list[common_pb2.Relationship]

    def __init__(
        self,
        event_type: ReplicationEventType,
        partition_key: "PartitionKey",
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


class PartitionKey(ABC):
    """
    Parent type for all partition keys.

    Partition keys define the partitions in which replication events are ordered.
    """

    @staticmethod
    def byEnvironment() -> "PartitionKey":
        """
        Order all events within the environment.

        This makes all changes follow the same order as the database (assuming one database per environment),
        however it means all events can only be processed by a single consumer at a time.
        """
        return EnvironmentPartitionKey()

    # TODO: Eventually we may want to scale out replication via more partitions.
    # To do this we will need a procedure like this:
    # 1. Add a field to the outbox table that can control the topic
    # 3. Add configuration for `route.by.field` in Debezium
    # 4. Start writing events with the new partition key, with a new value for this field.
    #    Events in the WAL with the global key will be routed to the "old" topic,
    #    while events with the new partition key(s) will be routed to a new topic.
    # 5. Let the "old" topic be consumed entirely by the sink.
    #    This maintains order for those with respect to anything new.
    # 6. Once that is empty, switch the sink to the new topic.
    # This just introduces some delay in new access, but otherwise doesn't introduce an outage.

    # Example: byTenant(tenant: Tenant) -> "PartitionKey":
    # ...

    # When partitioning by another key, be mindful of causal relationships between events,
    # and other operations which may change the same tuples.
    # The same tuples MUST only ever be changed with the same partition.

    @abstractmethod
    def __str__(self) -> str:
        """Return the string value of the partition key."""
        pass


class EnvironmentPartitionKey(PartitionKey):
    """Environment partition key globally orders all events within the environment."""

    def __str__(self) -> str:
        """Return the environment name."""
        return settings.ENV_NAME
