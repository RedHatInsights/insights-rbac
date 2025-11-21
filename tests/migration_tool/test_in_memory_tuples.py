import unittest
from kessel.relations.v1beta1.common_pb2 import Relationship, ObjectReference, ObjectType, SubjectReference
from migration_tool.in_memory_tuples import InMemoryTuples, RelationTuple
from migration_tool.utils import create_relationship


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

    def test_write_detects_duplicates_in_single_batch(self):
        """Test that write() raises ValueError when duplicates are found in the same batch."""
        # Create duplicate relationships
        rel1 = create_relationship(("rbac", "role_binding"), "binding-123", ("rbac", "role"), "role-456", "role")
        rel2 = create_relationship(("rbac", "role_binding"), "binding-123", ("rbac", "role"), "role-456", "role")

        # Should raise ValueError for duplicates in the same batch
        with self.assertRaises(ValueError) as context:
            self.store.write([rel1, rel2], [])

        # Verify error message
        error_message = str(context.exception)
        self.assertIn("Duplicate relationship detected", error_message)
        self.assertIn("role_binding:binding-123#role@role:role-456", error_message)
        self.assertIn("single replication event", error_message)

    def test_write_detects_only_duplicates_in_add_list(self):
        """Test that write() only checks for duplicates within the add list, not with existing tuples."""
        # Add a relationship to the store
        rel = create_relationship(("rbac", "role_binding"), "binding-abc", ("rbac", "workspace"), "ws-123", "binding")

        self.store.write([rel], [])

        try:
            # Duplicating a relationship that is already stored should be fine.
            self.store.write([rel], [])
        except ValueError as e:
            self.fail(f"Expected adding a duplicate of an existing relationship to work, but got: {e}")


class TestCreateRelationship(unittest.TestCase):
    """Test the create_relationship utility function."""

    def test_create_relationship_with_valid_ids(self):
        """Test that create_relationship works with valid non-None IDs."""
        rel = create_relationship(
            ("rbac", "workspace"), "workspace-123", ("rbac", "role_binding"), "binding-456", "binding"
        )

        self.assertIsNotNone(rel)
        self.assertEqual(rel.resource.id, "workspace-123")
        self.assertEqual(rel.subject.subject.id, "binding-456")

    def test_create_relationship_raises_error_on_none_resource_id(self):
        """Test that create_relationship raises ValueError when resource_id is None."""
        with self.assertRaises(ValueError) as context:
            create_relationship(
                ("rbac", "workspace"),
                None,  # Invalid: None resource_id
                ("rbac", "role_binding"),
                "binding-456",
                "binding",
            )

        error_message = str(context.exception)
        self.assertIn("Cannot create relationship with None resource_id", error_message)
        self.assertIn("workspace", error_message)
        self.assertIn("None values should have been converted", error_message)

    def test_create_relationship_raises_error_on_none_subject_id(self):
        """Test that create_relationship raises ValueError when subject_id is None."""
        with self.assertRaises(ValueError) as context:
            create_relationship(
                ("rbac", "workspace"),
                "workspace-123",
                ("rbac", "role_binding"),
                None,  # Invalid: None subject_id
                "binding",
            )

        error_message = str(context.exception)
        self.assertIn("Cannot create relationship with None subject_id", error_message)
        self.assertIn("role_binding", error_message)
        self.assertIn("None values should have been converted", error_message)
