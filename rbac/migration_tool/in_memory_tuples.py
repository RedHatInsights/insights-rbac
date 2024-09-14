"""This module contains the in-memory representation of a tuple store."""

from typing import Callable, Hashable, Iterable, List, NamedTuple, Set, Tuple, TypeVar
from collections import namedtuple, defaultdict

from kessel.relations.v1beta1.common_pb2 import Relationship
from management.role.relation_api_dual_write_handler import RelationReplicator


class RelationTuple(NamedTuple):
    """Simple representation of a relation tuple."""

    resource_type_namespace: str
    resource_type_name: str
    resource_id: str
    relation: str
    subject_type_namespace: str
    subject_type_name: str
    subject_id: str
    subject_relation: str


T = TypeVar("T", bound=Hashable)


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
        for tuple in add:
            self.add(tuple)
        for tuple in remove:
            self.remove(tuple)

    def find_like(
        self,
        predicates: List[Callable[[RelationTuple], bool]],
        group_by: Callable[[RelationTuple], T],
        require_full_match: bool = False,
        group_filter: Callable[[T], bool] = lambda _: True,
    ) -> Tuple[dict[T, List[RelationTuple]], dict[T, List[RelationTuple]]]:
        """
        Find groups of tuples matching given predicates, grouped by a key.

        Groups the tuples using the provided `group_by` function and tests the
        predicates against each group independently.

        For each group, this method attempts to find tuples that match all the
        predicates, ensuring that no tuple is used for more than one predicate
        within the group.

        If `require_full_match` is True, the method also ensures that all tuples
        in the group are matched by the predicates (i.e., no unmatched tuples
        remain in the group). If any group does not meet the criteria, it is
        excluded from the results.

        Args:
            predicates: A list of predicates (functions) that each accept a
                RelationTuple and return a bool indicating a match.
            group_by: A function that takes a RelationTuple and returns a key
                to group by (e.g., a resource ID).
            require_full_match: If True, only groups where all tuples are matched
                by the predicates are included in the results.
            group_filter: A predicate that filters the groups to include in the
                results. Useful when you only want to test a subset of tuples e.g.
                a specific resource type.

        Returns:
            A tuple containing two dictionaries:
            - The first dictionary contains the groups that matched all predicates.
            - The second dictionary contains the groups that did not match all predicates.
        """
        # Group the tuples by the specified key
        grouped_tuples: dict[T, List[RelationTuple]] = defaultdict(list)
        for rel in self._tuples:
            key = group_by(rel)
            if group_filter(key):
                grouped_tuples[key].append(rel)

        matching_groups: dict[T, List[RelationTuple]] = {}
        unmatched_groups: dict[T, List[RelationTuple]] = {}

        # Iterate over each group
        for key, group_tuples in grouped_tuples.items():
            remaining_tuples = set(group_tuples)
            matching_tuples = []
            success = True

            # Attempt to match all predicates within the group
            for predicate in predicates:
                found = False
                for rel in remaining_tuples:
                    if predicate(rel):
                        matching_tuples.append(rel)
                        remaining_tuples.remove(rel)
                        found = True
                        break  # Move to next predicate
                if not found:
                    success = False
                    break  # Predicate not satisfied in this group

            if success:
                if require_full_match and remaining_tuples:
                    # Unmatched tuples remain in the group; skip this group
                    unmatched_groups[key] = group_tuples
                    continue  # Skip to the next group
                else:
                    matching_groups[key] = matching_tuples

        return matching_groups, unmatched_groups

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
