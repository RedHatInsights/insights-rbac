"""This module contains the in-memory representation of a tuple store."""

from collections import defaultdict
from typing import Callable, Hashable, Iterable, List, NamedTuple, Set, Tuple, TypeVar

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

    def stringify(self):
        """Display all attributes in one line."""
        return (
            f"{self.resource_type_namespace}/{self.resource_type_name}:{self.resource_id}#{self.relation}"
            f"@{self.subject_type_namespace}/{self.subject_type_name}:{self.subject_id}"
        )


T = TypeVar("T", bound=Hashable)


class InMemoryTuples:
    """In-memory store for relation tuples."""

    def __init__(self, tuples=None):
        """Initialize the store."""
        self._tuples: Set[RelationTuple] = set(tuples) if tuples is not None else set()

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
        for tuple in remove:
            self.remove(tuple)
        for tuple in add:
            self.add(tuple)

    def find_tuples(self, predicate: Callable[[RelationTuple], bool]) -> List[RelationTuple]:
        """Find tuples matching the given predicate."""
        return [rel for rel in self._tuples if predicate(rel)]

    def find_tuples_grouped(
        self, predicate: Callable[[RelationTuple], bool], group_by: Callable[[RelationTuple], T]
    ) -> dict[T, List[RelationTuple]]:
        """Filter tuples and group them by a key."""
        grouped_tuples: dict[T, List[RelationTuple]] = defaultdict(list)
        for rel in self._tuples:
            if predicate(rel):
                key = group_by(rel)
                grouped_tuples[key].append(rel)
        return grouped_tuples

    def find_group_with_tuples(
        self,
        predicates: List[Callable[[RelationTuple], bool]],
        group_by: Callable[[RelationTuple], T],
        group_filter: Callable[[T], bool] = lambda _: True,
        require_full_match: bool = False,
        match_once: bool = True,
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
                by the predicates (i.e. there are no remaining unmatched tuples)
                are included in the results.
            group_filter: A predicate that filters the groups to include in the
                results. Useful when you only want to test a subset of tuples e.g.
                a specific resource type.
            match_once: If True, each predicate is only used once in the matching process.
                Otherwise, each tuple in the group will be tested by each predicate until
                one predicate matches the tuple.

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
            remaining_predicates = list(predicates) if match_once else predicates
            i = 0
            matching_tuples = []
            success = True

            # Attempt to match all predicates within the group
            # Using each predicate only once if requested
            while remaining_predicates and i < len(remaining_predicates):
                predicate = remaining_predicates[i]
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
                if match_once:
                    remaining_predicates.pop(i)
                else:
                    i += 1

            if require_full_match and remaining_tuples or not success:
                unmatched_groups[key] = group_tuples
                continue

            matching_groups[key] = matching_tuples

        return matching_groups, unmatched_groups

    def __str__(self):
        """Return a string representation of the store."""
        return str(self._tuples)

    def __repr__(self):
        """Return a representation of the store."""
        return f"InMemoryTuples({repr(self._tuples)})"


class TuplePredicate:
    """A predicate that can be used to filter relation tuples."""

    def __init__(self, func, repr):
        """Initialize the predicate."""
        self.func = func
        self.repr = repr

    def __call__(self, *args, **kwargs):
        """Call the predicate."""
        return self.func(*args, **kwargs)

    def __repr__(self):
        """Return a representation of the predicate."""
        return self.repr


def all_of(*predicates: Callable[[RelationTuple], bool]) -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if all of the given predicates are true."""

    def predicate(rel: RelationTuple) -> bool:
        return all(p(rel) for p in predicates)

    return TuplePredicate(predicate, f"all_of({', '.join([str(p) for p in predicates])})")


def one_of(*predicates: Callable[[RelationTuple], bool]) -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if any of the given predicates are true."""
    if len(predicates) == 1:
        return predicates[0]

    def predicate(rel: RelationTuple) -> bool:
        return any(p(rel) for p in predicates)

    return TuplePredicate(predicate, f"one_of({', '.join([str(p) for p in predicates])})")


def resource_type(namespace: str, name: str) -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if the resource type matches the given namespace and name."""

    def predicate(rel: RelationTuple) -> bool:
        return rel.resource_type_namespace == namespace and rel.resource_type_name == name

    return TuplePredicate(predicate, f'resource_type("{namespace}", "{name}")')


def resource_id(id: str) -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if the resource ID matches the given ID."""

    def predicate(rel: RelationTuple) -> bool:
        return rel.resource_id == id

    return TuplePredicate(predicate, f'resource_id("{id}")')


def resource(namespace: str, name: str, id: object) -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if the resource matches the given namespace and name."""
    return all_of(resource_type(namespace, name), resource_id(str(id)))


def relation(relation: str) -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if the resource relation matches the given relation."""

    def predicate(rel: RelationTuple) -> bool:
        return rel.relation == relation

    return TuplePredicate(predicate, f'relation("{relation}")')


def subject_type(namespace: str, name: str, relation: str = "") -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if the subject type matches the given namespace and name."""

    def predicate(rel: RelationTuple) -> bool:
        return (
            rel.subject_type_namespace == namespace
            and rel.subject_type_name == name
            and rel.subject_relation == relation
        )

    return TuplePredicate(predicate, f'subject_type("{namespace}", "{name}")')


def subject_id(id: str) -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if the subject ID matches the given ID."""

    def predicate(rel: RelationTuple) -> bool:
        return rel.subject_id == id

    return TuplePredicate(predicate, f'subject_id("{id}")')


def subject(namespace: str, name: str, id: str, relation: str = "") -> Callable[[RelationTuple], bool]:
    """Return a predicate that is true if the subject matches the given namespace and name."""
    return all_of(subject_type(namespace, name, relation), subject_id(id))


class InMemoryRelationReplicator(RelationReplicator):
    """Replicates relations to an in-memory store."""

    def __init__(self, store: InMemoryTuples = InMemoryTuples()):
        """Initialize the replicator."""
        self.store = store

    def replicate(self, event):
        """Replicate the event to the in-memory store."""
        self.store.write(event.add, event.remove)
