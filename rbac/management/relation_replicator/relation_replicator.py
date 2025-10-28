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
import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict

from django.conf import settings
from kessel.relations.v1beta1 import common_pb2

logger = logging.getLogger(__name__)


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
    EXTERNAL_USER_DISABLE = "external_user_disable"
    BULK_EXTERNAL_USER_UPDATE = "bulk_external_user_update"
    MIGRATE_CUSTOM_ROLE = "migrate_custom_role"
    MIGRATE_TENANT_GROUPS = "migrate_tenant_groups"
    CUSTOMIZE_DEFAULT_GROUP = "customize_default_group"
    MIGRATE_SYSTEM_ROLE_ASSIGNMENT = "migrate_system_role_assignment"
    APPROVE_CROSS_ACCOUNT_REQUEST = "approve_cross_account_request"
    DENY_CROSS_ACCOUNT_REQUEST = "deny_cross_account_request"
    EXPIRE_CROSS_ACCOUNT_REQUEST = "expire_cross_account_request"
    MIGRATE_CROSS_ACCOUNT_REQUEST = "migrate_cross_account_request"
    DELETE_BINDING_MAPPINGS = "delete_binding_mappings"
    CREATE_UNGROUPED_HOSTS_WORKSPACE = "create_ungrouped_hosts_workspace"
    WORKSPACE_IMPORT = "workspace_import"
    CREATE_WORKSPACE = "create_workspace"
    UPDATE_WORKSPACE = "update_workspace"
    DELETE_WORKSPACE = "delete_workspace"
    MOVE_WORKSPACE = "move_workspace"


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

    def resource_context(self) -> Dict[str, object] | None:
        """Build context for all replication events that have identifiable resources."""
        # Map event types to (resource_type, id_field) tuples
        event_mapping = {
            # Workspace events
            ReplicationEventType.CREATE_WORKSPACE: ("Workspace", "workspace_id"),
            ReplicationEventType.UPDATE_WORKSPACE: ("Workspace", "workspace_id"),
            ReplicationEventType.DELETE_WORKSPACE: ("Workspace", "workspace_id"),
            ReplicationEventType.MOVE_WORKSPACE: ("Workspace", "workspace_id"),
            ReplicationEventType.CREATE_UNGROUPED_HOSTS_WORKSPACE: ("Workspace", "ungrouped_hosts_id"),
            # System role events
            ReplicationEventType.CREATE_SYSTEM_ROLE: ("SystemRole", "role_uuid"),
            ReplicationEventType.UPDATE_SYSTEM_ROLE: ("SystemRole", "role_uuid"),
            ReplicationEventType.DELETE_SYSTEM_ROLE: ("SystemRole", "v1_role_uuid"),
            ReplicationEventType.MIGRATE_SYSTEM_ROLE_ASSIGNMENT: ("SystemRole", "role_uuid"),
            # Custom role events
            ReplicationEventType.CREATE_CUSTOM_ROLE: ("CustomRole", "role_uuid"),
            ReplicationEventType.UPDATE_CUSTOM_ROLE: ("CustomRole", "role_uuid"),
            ReplicationEventType.DELETE_CUSTOM_ROLE: ("CustomRole", "v1_role_uuid"),
            ReplicationEventType.MIGRATE_CUSTOM_ROLE: ("CustomRole", "role_uuid"),
            # Role assignment events
            ReplicationEventType.ASSIGN_ROLE: ("RoleAssignment", "role_uuid"),
            ReplicationEventType.UNASSIGN_ROLE: ("RoleAssignment", "role_uuid"),
            # Group events
            ReplicationEventType.CREATE_GROUP: ("Group", "group_uuid"),
            ReplicationEventType.UPDATE_GROUP: ("Group", "group_uuid"),
            ReplicationEventType.DELETE_GROUP: ("Group", "group_uuid"),
            ReplicationEventType.ADD_PRINCIPALS_TO_GROUP: ("Group", "group_uuid"),
            ReplicationEventType.REMOVE_PRINCIPALS_FROM_GROUP: ("Group", "group_uuid"),
            ReplicationEventType.CUSTOMIZE_DEFAULT_GROUP: ("Group", "group_uuid"),
            # User events
            ReplicationEventType.EXTERNAL_USER_UPDATE: ("User", "user_id"),
            ReplicationEventType.EXTERNAL_USER_DISABLE: ("User", "user_id"),
            # Tenant events
            ReplicationEventType.BOOTSTRAP_TENANT: ("Tenant", "org_id"),
            # Cross-account events
            ReplicationEventType.APPROVE_CROSS_ACCOUNT_REQUEST: ("CrossAccountRequest", "user_id"),
            ReplicationEventType.DENY_CROSS_ACCOUNT_REQUEST: ("CrossAccountRequest", "user_id"),
            ReplicationEventType.EXPIRE_CROSS_ACCOUNT_REQUEST: ("CrossAccountRequest", "user_id"),
            ReplicationEventType.MIGRATE_CROSS_ACCOUNT_REQUEST: ("CrossAccountRequest", "user_id"),
            # Migration and special events
            ReplicationEventType.MIGRATE_TENANT_GROUPS: ("TenantGroups", "org_id"),
            ReplicationEventType.DELETE_BINDING_MAPPINGS: ("BindingMappings", "org_id"),
            ReplicationEventType.WORKSPACE_IMPORT: ("WorkspaceImport", "org_id"),
        }

        # Handle bulk events separately
        if self.event_type == ReplicationEventType.BULK_BOOTSTRAP_TENANT:
            num = self.event_info.get("num_tenants", 0)
            first = self.event_info.get("first_org_id", "")
            resource_id = f"bulk:{num}:{first}"
            resource_type = "BulkTenant"
        elif self.event_type == ReplicationEventType.BULK_EXTERNAL_USER_UPDATE:
            num = self.event_info.get("num_users", 0)
            first = self.event_info.get("first_user_id", "")
            resource_id = f"bulk:{num}:{first}"
            resource_type = "BulkUser"
        elif self.event_type in event_mapping:
            resource_type, id_field = event_mapping[self.event_type]
            resource_id = str(self.event_info.get(id_field, ""))
        else:
            return None

        if not resource_id:
            logger.warning(
                f"Missing resource_id for {self.event_type.value} event. "
                f"Expected field '{id_field if self.event_type in event_mapping else 'N/A'}' in event_info. "
                f"event_info: {self.event_info}"
            )
            return None

        # Validate org_id exists
        org_id = str(self.event_info.get("org_id", ""))
        if not org_id:
            error_msg = (
                f"Missing required org_id for {self.event_type.value} event. "
                f"resource_type: {resource_type}, resource_id: {resource_id}, event_info: {self.event_info}"
            )

            logger.error(error_msg)
            raise ValueError(error_msg)

        context = ReplicationEventResourceContext(
            resource_type=resource_type,
            resource_id=resource_id,
            org_id=org_id,
            event_type=self.event_type.value,
        )
        return context.to_json()


class ReplicationEventResourceContext:
    """Replication event resource context."""

    resource_type: str
    resource_id: str
    org_id: str
    event_type: str

    def __init__(
        self,
        resource_type: str,
        resource_id: str,
        org_id: str,
        event_type: str,
    ):
        """Initialize ReplicationEventResourceContext."""
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.org_id = org_id
        self.event_type = event_type

    def to_json(self) -> Dict[str, object]:
        """Convert to JSON dictionary."""
        return {
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "org_id": self.org_id,
            "event_type": self.event_type,
        }


class WorkspaceEvent:
    """Workspace event."""

    org_id: str
    account_number: str
    workspace: dict[str, str]
    event_type: ReplicationEventType
    partition_key: "PartitionKey"

    def __init__(
        self,
        org_id: str,
        account_number: str,
        workspace: dict[str, str],
        event_type: ReplicationEventType,
        partition_key: "PartitionKey",
    ):
        """Initialize WorkspaceEvent."""
        self.org_id = org_id
        self.account_number = account_number
        self.workspace = workspace
        self.event_type = event_type
        self.partition_key = partition_key


class AggregateTypes(str, Enum):
    """Aggregate types for outbox events."""

    RELATIONS = "relations-replication-event"
    WORKSPACE = "workspace"


class RelationReplicator(ABC):
    """Type responsible for replicating relations to Kessel Relations."""

    @abstractmethod
    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations."""
        pass

    def replicate_workspace(self, event: WorkspaceEvent):
        """Replicate the given workspace event to Kessel Relations."""
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
