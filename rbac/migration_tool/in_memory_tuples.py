"""This module contains the in-memory representation of a tuple store."""

from collections import namedtuple
from typing import Callable, Iterable, List, Set


from kessel.relations.v1beta1.common_pb2 import Relationship
from management.role.relation_api_dual_write_handler import RelationReplicator


RelationTuple = namedtuple(
    "RelationTuple",
    [
        "resource_type_namespace",
        "resource_type_name",
        "resource_id",
        "relation",
        "subject_type_namespace",
        "subject_type_name",
        "subject_id",
        "subject_relation",
    ],
)


class InMemoryTuples:
    """In-memory store for relation tuples."""

    def __init__(self):
        """Initialize the store."""
        self._tuples: Set[RelationTuple] = set()

    def _relationship_key(self, relationship: Relationship):
        return RelationTuple(
            resource_type_namespace=relationship.resource.type.namespace,
            resource_type_name=relationship.resource.type.name,
            resource_id=relationship.resource.id,
            relation=relationship.relation,
            subject_type_namespace=relationship.subject.subject.type.namespace,
            subject_type_name=relationship.subject.subject.type.name,
            subject_id=relationship.subject.subject.id,
            subject_relation=relationship.subject.relation,
        )

    def add(self, tuple: Relationship):
        """Add a tuple to the store."""
        key = self._relationship_key(tuple)
        self._tuples.add(key)

    def remove(self, tuple: Relationship):
        """Remove a tuple from the store."""
        key = self._relationship_key(tuple)
        self._tuples.discard(key)

    def write(self, add: Iterable[Relationship], remove: Iterable[Relationship]):
        """Add / remove tuples."""
        for relationship in add:
            self.add(relationship)
        for relationship in remove:
            self.remove(relationship)

    def find_like(self, predicates: List[Callable[[RelationTuple], bool]]) -> List[RelationTuple]:
        """
        Find the set of tuples matching given predicates.

        For each predicate in the list, this method finds exactly one relationship
        that matches it, ensuring that no relationship is used for more than one
        predicate. If any predicate does not have a matching relationship, it returns None.

        Returns:
            A list of matching RelationshipTuples if all predicates are satisfied.
            An empty list if any predicate fails to find a match.
        """
        remaining_tuples = set(self._tuples)
        matching_tuples = []

        for predicate in predicates:
            found = False
            for rel in remaining_tuples:
                if predicate(rel):
                    matching_tuples.append(rel)
                    remaining_tuples.remove(rel)
                    found = True
                    break  # Move to next predicate
            if not found:
                return []

        return matching_tuples

    def __str__(self):
        return str(self._tuples)


def all_of(*predicates: Callable[[RelationTuple], bool]) -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if all of the given predicates are true."""

    def predicate(rel: RelationTuple) -> bool:
        return all(p(rel) for p in predicates)

    return predicate


def resource_type(namespace: str, name: str) -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if the resource type matches the given namespace and name."""

    def predicate(rel: RelationTuple) -> bool:
        return rel.resource_type_namespace == namespace and rel.resource_type_name == name

    return predicate


def relation(relation: str) -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if the resource relation matches the given relation."""

    def predicate(rel: RelationTuple) -> bool:
        return rel.relation == relation

    return predicate


class InMemoryRelationReplicator(RelationReplicator):
    """Replicates relations to an in-memory store."""

    def __init__(self, store: InMemoryTuples = InMemoryTuples()):
        """Initialize the replicator."""
        self.store = store

    def replicate(self, event):
        self.store.write(event.add, event.remove)
