"""This module contains the in-memory representation of a tuple store."""

import re
from collections import defaultdict
from typing import Callable, Hashable, Iterable, List, NamedTuple, Set, Tuple, TypeVar, Union

from kessel.relations.v1beta1.common_pb2 import Relationship
from management.relation_replicator.relation_replicator import RelationReplicator


_OBJECT_ID_REGEX = r"^(([a-zA-Z0-9/_|\-=+]{1,})|\*)$"


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
        subject_part = f"{self.subject_type_namespace}/{self.subject_type_name}:{self.subject_id}"
        if self.subject_relation:
            subject_part += f"#{self.subject_relation}"
        return (
            f"{self.resource_type_namespace}/{self.resource_type_name}:{self.resource_id}#{self.relation}"
            f"@{subject_part}"
        )


RelationPredicate = Callable[["RelationTuple"], bool]
T = TypeVar("T", bound=Hashable)


class TupleSet:
    """A set of relation tuples with various utility methods."""

    def __init__(self, full_set: "InMemoryTuples", filtered_set: Set[RelationTuple]):
        """Initialize the store."""
        self._full_set = full_set
        self._set = filtered_set

    def __len__(self):
        """Return the number of tuples in the list."""
        return len(self._set)

    def __iter__(self):
        """Return an iterator over the tuples."""
        return iter(self._set)

    def __contains__(self, item: RelationTuple):
        """Check if a tuple is in the list."""
        return item in self._set

    def __str__(self):
        """Return a string representation of the store."""
        return str(self._set)

    def __repr__(self):
        """Return a representation of the store."""
        return f"TupleSet({repr(self._set)})"

    def count_tuples(self, predicate: RelationPredicate = lambda _: True) -> int:
        """Count tuples matching the given predicate."""
        return len(self.find_tuples(predicate))

    def find_tuples(self, predicate: RelationPredicate = lambda _: True) -> "TupleSet":
        """Find tuples matching the given predicate."""
        return TupleSet(self._full_set, {rel for rel in self._set if predicate(rel)})

    def find_tuples_grouped(
        self, predicate: RelationPredicate, group_by: Callable[[RelationTuple], T]
    ) -> dict[T, "TupleSet"]:
        """Filter tuples and group them by a key."""
        grouped_tuples: dict[T, set[RelationTuple]] = defaultdict(set)
        for rel in self._set:
            if predicate(rel):
                key = group_by(rel)
                grouped_tuples[key].add(rel)
        return {key: TupleSet(self._full_set, value) for key, value in grouped_tuples.items()}

    def find_group_with_tuples(
        self,
        predicates: List[RelationPredicate],
        group_by: Callable[[RelationTuple], T],
        group_filter: Callable[[T], bool] = lambda _: True,
        require_full_match: bool = False,
        match_once: bool = True,
    ) -> Tuple[dict[T, "TupleSet"], dict[T, "TupleSet"]]:
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
        grouped_tuples: dict[T, set[RelationTuple]] = defaultdict(set)
        for rel in self._set:
            key = group_by(rel)
            if group_filter(key):
                grouped_tuples[key].add(rel)

        matching_groups: dict[T, TupleSet] = {}
        unmatched_groups: dict[T, TupleSet] = {}

        # Iterate over each group
        for key, group_tuples in grouped_tuples.items():
            remaining_tuples = set(group_tuples)
            remaining_predicates = list(predicates) if match_once else predicates
            i = 0
            matching_tuples = set()
            success = True

            # Attempt to match all predicates within the group
            # Using each predicate only once if requested
            while remaining_predicates and i < len(remaining_predicates):
                predicate = remaining_predicates[i]
                found = False
                for rel in remaining_tuples:
                    if predicate(rel):
                        matching_tuples.add(rel)
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
                unmatched_groups[key] = TupleSet(self._full_set, group_tuples)
                continue

            matching_groups[key] = TupleSet(self._full_set, matching_tuples)

        return matching_groups, unmatched_groups

    def traverse_subject(
        self,
        predicates: List[RelationPredicate],
        require_full_match: bool = True,
        match_once: bool = True,
    ) -> "TupleSet":
        """
        Traverse through the tuples to find and match tuples where the subject is the resource of the current tuple.

        The returned set contains all tuples that match the predicates
        and have a resource that is the subject of a tuple in this set.

        Args:
            predicates (List[RelationPredicate]):
                A list of predicate functions that take a RelationTuple
                and return a boolean indicating if the tuple matches the condition.
            require_full_match (bool, optional):
                If True, each predicate must be matched at least once. Defaults to True.
            match_once (bool, optional):
                If True, each tuple in the traversed list should be matched by at least one predicate. Defaults to True.
        Returns:
            TupleSet: A set of matched RelationTuples.
        """
        # For each tuple, find all the tuples where the subject is the resource
        # of the current tuple
        matched: set[RelationTuple] = set()

        for tuple in self:
            # Intentionally use full set here to traverse to tuples which may not be in this set
            traversed = self._full_set.find_tuples(
                resource(tuple.subject_type_namespace, tuple.subject_type_name, tuple.subject_id)
            )
            # Now match these if those found match the predicates.
            # Each tuple in the traversed list should be matched by at least one predicate
            # And each predicate must be matched at least once.
            matching, _ = traversed.find_group_with_tuples(
                predicates,
                group_by=lambda t: (t.resource_type_namespace, t.resource_type_name, t.resource_id),
                require_full_match=require_full_match,
                match_once=match_once,
            )

            for in_memory_tuple in matching.values():
                matched.update(in_memory_tuple)

        return TupleSet(self._full_set, matched)


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

        invalid_resource_id = not re.match(_OBJECT_ID_REGEX, key.resource_id)
        invalid_subject_id = not re.match(_OBJECT_ID_REGEX, key.subject_id)

        if invalid_resource_id or invalid_subject_id:
            invalid_fields = []
            if invalid_resource_id:
                invalid_fields.append(f"resource_id: {key.resource_id}")
            if invalid_subject_id:
                invalid_fields.append(f"subject_id: {key.subject_id}")
            raise ValueError(f"Invalid format for: {', '.join(invalid_fields)}.")

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

    def clear(self):
        """Clear all tuples from the store."""
        self._tuples.clear()

    def count_tuples(self, predicate: RelationPredicate = lambda _: True) -> int:
        """Count tuples matching the given predicate."""
        return len(self.find_tuples(predicate))

    def find_tuples(self, predicate: RelationPredicate = lambda _: True) -> "TupleSet":
        """Find tuples matching the given predicate."""
        return TupleSet(self, self._tuples).find_tuples(predicate)

    def find_tuples_grouped(
        self, predicate: RelationPredicate, group_by: Callable[[RelationTuple], T]
    ) -> dict[T, TupleSet]:
        """Filter tuples and group them by a key."""
        return TupleSet(self, self._tuples).find_tuples_grouped(predicate, group_by)

    def find_group_with_tuples(
        self,
        predicates: List[RelationPredicate],
        group_by: Callable[[RelationTuple], T],
        group_filter: Callable[[T], bool] = lambda _: True,
        require_full_match: bool = False,
        match_once: bool = True,
    ) -> Tuple[dict[T, "TupleSet"], dict[T, "TupleSet"]]:
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
        return TupleSet(self, self._tuples).find_group_with_tuples(
            predicates, group_by, group_filter, require_full_match, match_once
        )

    def traverse_subject(
        self,
        predicates: List[RelationPredicate],
        require_full_match: bool = True,
        match_once: bool = True,
    ) -> "TupleSet":
        return TupleSet(self, self._tuples).traverse_subject(predicates, require_full_match, match_once)

    def resource_is_subject_of(self, tuple_matching: RelationPredicate) -> RelationPredicate:
        def predicate(rel: RelationTuple) -> bool:
            count = self.count_tuples(
                all_of(tuple_matching, subject(rel.resource_type_namespace, rel.resource_type_name, rel.resource_id))
            )
            return count > 0

        return TuplePredicate(predicate, f"resource_is_subject_of({predicate})")

    def subject_is_resource_of(
        self,
        tuple_matching: Union[List[RelationPredicate], RelationPredicate],
        only: bool = False,
    ) -> RelationPredicate:
        """
        Create a predicate that tests for tuples whose subject is a resource
        in another tuple matching the given predicate or predicates.

        If [only] is True, the predicate will return True
        only if the matched tuples are the only subjects related to the tested subject.

        Args:
            tuple_matching (RelationPredicate): A function that matches a relation tuple.
            only (bool, optional): If True, the predicate will return True only if the subject matches the tuple and
                                   there are no unmatched tuples. Defaults to False.

        Returns:
            RelationPredicate: A predicate function that takes a RelationTuple and returns a boolean
                                             indicating if the subject is a resource of the given relation tuple.
        """

        predicates = [tuple_matching] if not isinstance(tuple_matching, list) else tuple_matching

        def predicate(rel: RelationTuple) -> bool:
            for predicate in predicates:
                matched = self.count_tuples(
                    all_of(predicate, resource(rel.subject_type_namespace, rel.subject_type_name, rel.subject_id))
                )
                if matched == 0:
                    return False

            if only:
                matched = self.count_tuples(
                    all_of(
                        none_of(*predicates),
                        resource(rel.subject_type_namespace, rel.subject_type_name, rel.subject_id),
                    )
                )
                if matched > 0:
                    return False

            return True

        return TuplePredicate(predicate, f"subject_is_resource_of({predicate}, only={only})")

    def __len__(self):
        """Return the number of tuples in the list."""
        return len(self._tuples)

    def __iter__(self):
        """Return an iterator over the tuples."""
        return iter(self._tuples)

    def __contains__(self, item: RelationTuple):
        """Check if a tuple is in the list."""
        return item in self._tuples

    def __str__(self):
        """Return a string representation of the store."""
        return str(self._tuples)

    def __repr__(self):
        """Return a representation of the store."""
        return f"InMemoryTuples({repr(self._tuples)})"

    def __len__(self):
        """Return the number of tuples in the store."""
        return len(self._tuples)


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


def all_of(*predicates: RelationPredicate) -> RelationPredicate:
    """Return a predicate that is true if all of the given predicates are true."""
    if len(predicates) == 1:
        return predicates[0]

    def predicate(rel: RelationTuple) -> bool:
        return all(p(rel) for p in predicates)

    return TuplePredicate(predicate, f"all_of({', '.join([str(p) for p in predicates])})")


def one_of(*predicates: RelationPredicate) -> RelationPredicate:
    """Return a predicate that is true if any of the given predicates are true."""
    if len(predicates) == 1:
        return predicates[0]

    def predicate(rel: RelationTuple) -> bool:
        return any(p(rel) for p in predicates)

    return TuplePredicate(predicate, f"one_of({', '.join([str(p) for p in predicates])})")


def none_of(*predicates: RelationPredicate) -> RelationPredicate:
    """Return a predicate that is true if none of the given predicates are true."""

    def predicate(rel: RelationTuple) -> bool:
        return not any(p(rel) for p in predicates)

    return TuplePredicate(predicate, f"none_of({', '.join([str(p) for p in predicates])})")


def resource_type(namespace: str, name: str) -> RelationPredicate:
    """Return a predicate that is true if the resource type matches the given namespace and name."""

    def predicate(rel: RelationTuple) -> bool:
        return rel.resource_type_namespace == namespace and rel.resource_type_name == name

    return TuplePredicate(predicate, f'resource_type("{namespace}", "{name}")')


def resource_id(id: str) -> RelationPredicate:
    """Return a predicate that is true if the resource ID matches the given ID."""

    def predicate(rel: RelationTuple) -> bool:
        return rel.resource_id == id

    return TuplePredicate(predicate, f'resource_id("{id}")')


def resource(namespace: str, name: str, id: object) -> RelationPredicate:
    """Return a predicate that is true if the resource matches the given namespace and name."""
    return all_of(resource_type(namespace, name), resource_id(str(id)))


def relation(relation: str) -> RelationPredicate:
    """Return a predicate that is true if the resource relation matches the given relation."""

    def predicate(rel: RelationTuple) -> bool:
        return rel.relation == relation

    return TuplePredicate(predicate, f'relation("{relation}")')


def subject_type(namespace: str, name: str, relation: str = "") -> RelationPredicate:
    """Return a predicate that is true if the subject type matches the given namespace and name."""

    def predicate(rel: RelationTuple) -> bool:
        return (
            rel.subject_type_namespace == namespace
            and rel.subject_type_name == name
            and rel.subject_relation == relation
        )

    return TuplePredicate(predicate, f'subject_type("{namespace}", "{name}")')


def subject_id(id: str) -> RelationPredicate:
    """Return a predicate that is true if the subject ID matches the given ID."""

    def predicate(rel: RelationTuple) -> bool:
        return rel.subject_id == id

    return TuplePredicate(predicate, f'subject_id("{id}")')


def subject(namespace: str, name: str, id: object, relation: str = "") -> RelationPredicate:
    """Return a predicate that is true if the subject matches the given namespace and name."""
    return all_of(subject_type(namespace, name, relation), subject_id(str(id)))


class InMemoryRelationReplicator(RelationReplicator):
    """Replicates relations to an in-memory store."""

    def __init__(self, store: InMemoryTuples = InMemoryTuples()):
        """Initialize the replicator."""
        self.store = store

    def replicate(self, event):
        """Replicate the event to the in-memory store."""
        # TODO: should also track the partition that each event was written to
        # in order to test partitioning logic
        self.store.write(event.add, event.remove)
