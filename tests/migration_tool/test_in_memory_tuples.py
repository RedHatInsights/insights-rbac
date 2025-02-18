import unittest
from kessel.relations.v1beta1.common_pb2 import Relationship, ObjectReference, ObjectType, SubjectReference
from migration_tool.in_memory_tuples import InMemoryTuples, RelationTuple


class TestInMemoryTuples(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryTuples()

    def test_add_tuple(self):
        relationship = Relationship(
            resource=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="res_id"),
            relation="rel",
            subject=SubjectReference(
                subject=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="sub_id"), relation="sub_rel"
            ),
        )
        self.store.add(relationship)
        self.assertEqual(len(self.store._tuples), 1)

    def test_remove_tuple(self):
        relationship = Relationship(
            resource=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="res_id"),
            relation="rel",
            subject=SubjectReference(
                subject=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="sub_id"), relation="sub_rel"
            ),
        )
        self.store.add(relationship)
        self.store.remove(relationship)
        self.assertEqual(len(self.store._tuples), 0)

    def test_clear_tuples(self):
        relationship = Relationship(
            resource=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="res_id"),
            relation="rel",
            subject=SubjectReference(
                subject=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="sub_id"), relation="sub_rel"
            ),
        )
        self.store.add(relationship)
        self.store.clear()
        self.assertEqual(len(self.store._tuples), 0)

    def test_count_tuples(self):
        relationship = Relationship(
            resource=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="res_id"),
            relation="rel",
            subject=SubjectReference(
                subject=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="sub_id"), relation="sub_rel"
            ),
        )
        self.store.add(relationship)
        count = self.store.count_tuples()
        self.assertEqual(count, 1)

    def test_find_tuples(self):
        relationship = Relationship(
            resource=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="res_id"),
            relation="rel",
            subject=SubjectReference(
                subject=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="sub_id"), relation="sub_rel"
            ),
        )
        self.store.add(relationship)
        tuples = self.store.find_tuples(lambda x: x.resource_id == "res_id")
        self.assertEqual(len(tuples), 1)

    def test_find_group_finds_group_with_tuple_that_matches_predicate(self):
        relationship = Relationship(
            resource=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="res_id"),
            relation="rel",
            subject=SubjectReference(
                subject=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="sub_id1"), relation="sub_rel"
            ),
        )
        relationship = Relationship(
            resource=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="res_id"),
            relation="rel",
            subject=SubjectReference(
                subject=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="sub_id2"), relation="sub_rel"
            ),
        )
        self.store.add(relationship)
        tuples, _ = self.store.find_group_with_tuples(
            group_by=lambda x: x.resource_id,
            group_filter=lambda x: x == "res_id",
            predicates=[lambda x: x.resource_id == "res_id"],
        )
        self.assertEqual(len(tuples), 1)

    def test_find_group_does_not_match_group_with_unmatched_predicate(self):
        relationship = Relationship(
            resource=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="res_id"),
            relation="rel",
            subject=SubjectReference(
                subject=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="sub_id1"), relation="sub_rel"
            ),
        )
        relationship = Relationship(
            resource=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="res_id"),
            relation="rel",
            subject=SubjectReference(
                subject=ObjectReference(type=ObjectType(namespace="ns", name="name"), id="sub_id2"), relation="sub_rel"
            ),
        )
        self.store.add(relationship)
        tuples, _ = self.store.find_group_with_tuples(
            group_by=lambda x: x.resource_id,
            group_filter=lambda x: x == "res_id",
            predicates=[lambda x: x.subject_id == "sub_id1", lambda x: x.subject_id == "sub_id3"],
        )
        self.assertEqual(len(tuples), 0)
