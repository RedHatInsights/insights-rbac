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

"""RelationReplicator which writes to the outbox table."""

import logging
from typing import Any, Dict, List, Optional, Protocol, TypedDict
from uuid import UUID

from django.db import transaction
from google.protobuf import json_format
from kessel.relations.v1beta1.common_pb2 import Relationship
from management.models import Outbox
from management.relation_replicator.relation_replicator import (
    AggregateTypes,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
    WorkspaceEvent,
)
from prometheus_client import Counter


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

relations_replication_event_total = Counter(
    "relations_replication_event_total", "Total count of relations replication events"
)
workspace_replication_event_total = Counter(
    "workspace_replication_event_total", "Total count of workspace replication events"
)

OPERATION_MAPPING = {
    ReplicationEventType.CREATE_WORKSPACE: "create",
    ReplicationEventType.DELETE_WORKSPACE: "delete",
    ReplicationEventType.UPDATE_WORKSPACE: "update",
}


class ReplicationEventPayload(TypedDict):
    """Typed dictionary for ReplicationEvent payload."""

    relations_to_add: List[Dict[str, Any]]
    relations_to_remove: List[Dict[str, Any]]
    resource_context: dict[str, object]


class WorkspaceEventPayload(TypedDict):
    """Typed dictionary for WorkspaceEvent payload."""

    org_id: str
    account_number: str
    workspace: Dict[str, str]
    operation: str


class OutboxReplicator(RelationReplicator):
    """Replicates relations via the outbox table."""

    def __init__(self, log: Optional["OutboxLog"] = None):
        """Initialize the OutboxReplicator with an optional OutboxLog implementation."""
        self._log = log if log is not None else OutboxWAL()

    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations via the Outbox."""
        payload = self._build_replication_event(event.add, event.remove, event.event_info, event.event_type)
        self._save_replication_event(payload, event.event_type, event.event_info, str(event.partition_key))

    def replicate_workspace(self, event: WorkspaceEvent):
        """Replicate the event of workspace."""
        payload = WorkspaceEventPayload(
            org_id=event.org_id,
            account_number=event.account_number,
            workspace=event.workspace,
            operation=OPERATION_MAPPING[event.event_type],
        )
        self._save_workspace_event(payload, event.event_type, str(event.partition_key))

    def _validate_resource_context(
        self, resource_context: dict[str, object], event_type: ReplicationEventType
    ) -> dict[str, object]:
        """
        Validate and extract resource_context fields.

        Checks for the presence of:
        - event_type: The type of replication event
        - org_id: The organization ID (required for most events)
        - Resource-specific identifier: Various UUID fields like group_uuid, workspace_id, v1_role_uuid, etc.

        Returns a dictionary containing the validated fields that exist.
        Logs warnings for missing recommended fields.
        Converts UUID objects to strings for JSON serialization.
        """
        validated: dict[str, object] = {}

        # Add event_type to the validated context
        validated["event_type"] = event_type.value

        # Check for org_id
        if "org_id" in resource_context:
            validated["org_id"] = resource_context["org_id"]
        else:
            logger.debug("[Dual Write] resource_context missing 'org_id' field")

        # Check for resource-specific ID fields
        id_fields = [
            "id",
            "group_uuid",
            "workspace_id",
            "v1_role_uuid",
            "role_uuid",
            "user_id",
            "principal_uuid",
            "ungrouped_hosts_id",
            "default_workspace_id",
            "mapping_id",
            "first_user_id",
            "first_org_id",
            "target_org",
            "roles",
        ]
        found_id = False

        for id_field in id_fields:
            if id_field in resource_context:
                field_value = resource_context[id_field]
                # Convert UUID to string if needed
                if isinstance(field_value, UUID):
                    validated[id_field] = str(field_value)
                elif isinstance(field_value, list):
                    # Convert any UUIDs in the list to strings (e.g., roles list)
                    validated[id_field] = [str(item) if isinstance(item, UUID) else item for item in field_value]
                else:
                    validated[id_field] = field_value
                found_id = True

        if not found_id:
            logger.debug(
                "[Dual Write] resource_context missing resource ID field. " "Expected one of: %s. Available keys: %s",
                ", ".join(id_fields),
                ", ".join(resource_context.keys()),
            )

        # Include any other fields present in resource_context
        for key, value in resource_context.items():
            if key not in validated:
                # Convert UUIDs to strings for JSON serialization
                if isinstance(value, UUID):
                    validated[key] = str(value)
                elif isinstance(value, list):
                    # Convert any UUIDs in the list to strings
                    validated[key] = [str(item) if isinstance(item, UUID) else item for item in value]
                elif isinstance(value, dict):
                    # Convert any UUIDs in dict values to strings
                    validated[key] = {k: str(v) if isinstance(v, UUID) else v for k, v in value.items()}
                else:
                    validated[key] = value

        return validated

    def _build_replication_event(
        self,
        relations_to_add: list[Relationship],
        relations_to_remove: list[Relationship],
        resource_context: dict[str, object],
        event_type: ReplicationEventType,
    ) -> ReplicationEventPayload:
        """Build replication event."""
        add_json: list[dict[str, Any]] = []
        for relation in relations_to_add:
            add_json.append(json_format.MessageToDict(relation))

        remove_json: list[dict[str, Any]] = []
        for relation in relations_to_remove:
            remove_json.append(json_format.MessageToDict(relation))

        # Validate and extract resource_context fields
        validated_context = self._validate_resource_context(resource_context, event_type)

        payload: ReplicationEventPayload = {
            "relations_to_add": add_json,
            "relations_to_remove": remove_json,
            "resource_context": validated_context,
        }

        return payload

    def _save_replication_event(
        self,
        payload: ReplicationEventPayload,
        event_type: ReplicationEventType,
        event_info: dict[str, object],
        aggregateid: str,
    ):
        """Save replication event."""
        # TODO: Can we add these as proper fields for kibana but also get logged in simple formatter?
        logged_info = " ".join([f"info.{key}='{str(value)}'" for key, value in event_info.items()])

        if not payload["relations_to_add"] and not payload["relations_to_remove"]:
            logger.warning(
                "[Dual Write] Skipping empty replication event. "
                "An empty event is always a bug. "
                "Calling code should avoid this and if not obvious, log why there is nothing to replicate. "
                "aggregateid='%s' event_type='%s' %s",
                aggregateid,
                event_type,
                logged_info,
            )
            return

        logger.info(
            "[Dual Write] Publishing replication event. aggregateid='%s' event_type='%s' %s",
            aggregateid,
            event_type,
            logged_info,
        )

        transaction.on_commit(relations_replication_event_total.inc)

        # https://debezium.io/documentation/reference/stable/transformations/outbox-event-router.html#basic-outbox-table
        outbox = Outbox(
            aggregatetype=AggregateTypes.RELATIONS,
            aggregateid=aggregateid,
            event_type=event_type,
            payload=payload,
        )

        self._log.log(outbox)

    def _save_workspace_event(
        self,
        payload: WorkspaceEventPayload,
        event_type: ReplicationEventType,
        aggregateid: str,
    ):
        """Save replication event."""
        transaction.on_commit(workspace_replication_event_total.inc)

        outbox = Outbox(
            aggregatetype=AggregateTypes.WORKSPACE,
            aggregateid=aggregateid,
            event_type=event_type,
            payload=payload,
        )

        self._log.log(outbox)


class OutboxLog(Protocol):
    """Protocol for logging outbox events."""

    def log(self, outbox: Outbox):
        """Log the given outbox event."""
        ...


class OutboxWAL:
    """Writes to the outbox table."""

    def log(self, outbox: Outbox):
        """Log the given outbox event."""
        outbox.save(force_insert=True)
        # Immediately deleted to avoid filling up the table.
        # Keeping outbox records around is not as useful as it may seem,
        # because they will not necessarily be sorted in the order they appear in the WAL.
        outbox.delete()


class InMemoryLog:
    """Logs to memory."""

    def __init__(self):
        """Initialize the InMemoryLog with an empty log."""
        self._log = []

    def __len__(self):
        """Return the number of logged events."""
        return len(self._log)

    def __iter__(self):
        """Return an iterator over the logged events."""
        return iter(self._log)

    def __getitem__(self, index) -> Outbox:
        """Return the logged event at the given index."""
        return self._log[index]

    def first(self) -> Outbox:
        """Return the first logged event."""
        if not self._log:
            raise IndexError("No events logged")
        return self._log[0]

    def latest(self) -> Outbox:
        """Return the latest logged event."""
        if not self._log:
            raise IndexError("No events logged")
        return self._log[-1]

    def log(self, outbox: Outbox):
        """Log the given outbox event."""
        self._log.append(outbox)
