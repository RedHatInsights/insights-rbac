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

from django.db import transaction
from google.protobuf import json_format
from kessel.relations.v1beta1.common_pb2 import Relationship
from management.models import Outbox
from management.relation_replicator.relation_replicator import (
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from prometheus_client import Counter


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

relations_replication_event_total = Counter(
    "relations_replication_event_total", "Total count of relations replication events"
)


class ReplicationEventPayload(TypedDict):
    """Typed dictionary for ReplicationEvent payload."""

    relations_to_add: List[Dict[str, Any]]
    relations_to_remove: List[Dict[str, Any]]


class OutboxReplicator(RelationReplicator):
    """Replicates relations via the outbox table."""

    def __init__(self, log: Optional["OutboxLog"] = None):
        """Initialize the OutboxReplicator with an optional OutboxLog implementation."""
        self._log = log if log is not None else OutboxWAL()

    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations via the Outbox."""
        payload = self._build_replication_event(event.add, event.remove)
        self._save_replication_event(payload, event.event_type, event.event_info, str(event.partition_key))

    def _build_replication_event(
        self, relations_to_add: list[Relationship], relations_to_remove: list[Relationship]
    ) -> ReplicationEventPayload:
        """Build replication event."""
        add_json: list[dict[str, Any]] = []
        for relation in relations_to_add:
            add_json.append(json_format.MessageToDict(relation))

        remove_json: list[dict[str, Any]] = []
        for relation in relations_to_remove:
            remove_json.append(json_format.MessageToDict(relation))

        return {"relations_to_add": add_json, "relations_to_remove": remove_json}

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
            aggregatetype="relations-replication-event",
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
