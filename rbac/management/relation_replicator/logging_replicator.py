"""RelationReplicator which writes to the outbox table."""

import logging

from kessel.relations.v1beta1 import common_pb2
from management.relation_replicator.relation_replicator import RelationReplicator, ReplicationEvent


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class LoggingReplicator(RelationReplicator):
    """Just logs relations."""

    def replicate(self, event: ReplicationEvent):
        """Log the event's tuples."""
        for rel in event.add:
            logger.info(stringify_spicedb_relationship(rel))


def stringify_spicedb_relationship(rel: common_pb2.Relationship):
    """Stringify a relationship for logging."""
    return (
        f"{rel.resource.type.name}:{rel.resource.id}#{rel.relation}@{rel.subject.subject.type.name}:"
        f"{rel.subject.subject.id}"
    )
