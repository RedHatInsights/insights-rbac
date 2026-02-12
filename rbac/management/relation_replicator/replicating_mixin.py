#
# Copyright 2026 Red Hat, Inc.
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
"""Mixin for services that need to replicate relations to SpiceDB."""

from django.conf import settings
from management.relation_replicator.noop_replicator import NoopReplicator
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.types import RelationTuple


class ReplicatingServiceMixin:
    """Mixin for services that need to replicate relations to SpiceDB.

    This mixin provides shared plumbing for replication. It accepts domain types
    (RelationTuple) and converts them to infrastructure types (protobuf Relationship)
    before sending to the replicator.
    """

    _replicator: RelationReplicator

    def __init__(self, replicator: RelationReplicator | None = None):
        """Initialize the replicator."""
        if settings.REPLICATION_TO_RELATION_ENABLED:
            self._replicator = replicator if replicator is not None else OutboxReplicator()
        else:
            self._replicator = NoopReplicator()

    def _to_relationships(self, tuples: list[RelationTuple]):
        """Convert domain RelationTuples to protobuf Relationships."""
        return [t.as_message() for t in tuples]

    def replicate_create(
        self,
        event_type: ReplicationEventType,
        info: dict[str, object],
        tuples: list[RelationTuple],
    ):
        """Replicate a CREATE operation - only adds tuples."""
        self._replicator.replicate(
            ReplicationEvent(
                event_type=event_type,
                info=info,
                partition_key=PartitionKey.byEnvironment(),
                add=self._to_relationships(tuples),
            )
        )

    def replicate_update(
        self,
        event_type: ReplicationEventType,
        info: dict[str, object],
        new_tuples: list[RelationTuple],
        old_tuples: list[RelationTuple],
    ):
        """Replicate an UPDATE operation - removes old, adds new."""
        self._replicator.replicate(
            ReplicationEvent(
                event_type=event_type,
                info=info,
                partition_key=PartitionKey.byEnvironment(),
                add=self._to_relationships(new_tuples),
                remove=self._to_relationships(old_tuples),
            )
        )

    def replicate_delete(
        self,
        event_type: ReplicationEventType,
        info: dict[str, object],
        tuples: list[RelationTuple],
    ):
        """Replicate a DELETE operation - only removes tuples."""
        self._replicator.replicate(
            ReplicationEvent(
                event_type=event_type,
                info=info,
                partition_key=PartitionKey.byEnvironment(),
                remove=self._to_relationships(tuples),
            )
        )
