"""A RelationReplicator which does nothing."""

from management.relation_replicator.relation_replicator import RelationReplicator, ReplicationEvent


class NoopReplicator(RelationReplicator):
    """Noop replicator."""

    def replicate(self, event: ReplicationEvent):
        """Noop."""
        pass
