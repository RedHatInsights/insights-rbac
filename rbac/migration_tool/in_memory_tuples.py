"""This module contains the in-memory representation of a tuple store."""

from typing import Iterable, Set, Tuple


from kessel.relations.v1beta1.common_pb2 import Relationship
from management.role.relation_api_dual_write_handler import RelationReplicator


class InMemoryTuples:
    """In-memory store for relation tuples."""

    def __init__(self):
        """Initialize the store."""
        self.relationships: Set[Tuple] = set()

    def _relationship_key(self, relationship: Relationship):
        return (
            relationship.resource.type.namespace,
            relationship.resource.type.name,
            relationship.resource.id,
            relationship.relation,
            relationship.subject.subject.type.namespace,
            relationship.subject.subject.type.name,
            relationship.subject.subject.id,
            relationship.subject.relation,
        )

    def add(self, relationship: Relationship):
        key = self._relationship_key(relationship)
        self.relationships.add(key)

    def remove(self, relationship: Relationship):
        key = self._relationship_key(relationship)
        self.relationships.discard(key)

    def write(self, add: Iterable[Relationship], remove: Iterable[Relationship]):
        for relationship in add:
            self.add(relationship)
        for relationship in remove:
            self.remove(relationship)


class InMemoryRelationReplicator(RelationReplicator):
    """Replicates relations to an in-memory store."""

    def __init__(self, store: InMemoryTuples = InMemoryTuples()):
        """Initialize the replicator."""
        self.store = store

    def replicate(self, event):
        self.store.write(event.add, event.remove)
