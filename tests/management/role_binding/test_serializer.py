#
# Copyright 2025 Red Hat, Inc.
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
"""Test role binding serializers."""

import uuid
from datetime import datetime, timezone
from unittest.mock import Mock

from django.test import TestCase, override_settings

from management.models import Group, Permission, Principal, RoleBinding, RoleBindingGroup, RoleV2
from management.role.v2_service import RoleV2Service
from management.role_binding.serializer import (
    BatchCreateRoleBindingRequestSerializer,
    BatchCreateRoleBindingResponseItemSerializer,
    RoleBindingByGroupSerializer,
    RoleBindingBySubjectFieldSelection,
    RoleBindingFieldSelection,
    RoleBindingListInputSerializer,
    RoleBindingListOutputSerializer,
    UpdateRoleBindingRequestSerializer,
    UpdateRoleBindingResponseSerializer,
)
from management.role_binding.service import UpdateRoleBindingResult
from management.subject.model import SubjectType
from management.utils import FieldSelection
from tests.identity_request import IdentityRequest

# Sentinel value used to signal that a key should be removed from test data.
_REMOVE = object()


class RoleBindingByGroupSerializerTest(IdentityRequest):
    """Test the RoleBindingByGroupSerializer.

    Tests verify the serializer produces output matching the API spec:
    - last_modified: datetime timestamp
    - subject: {id: UUID, type: "group", group: {name, description, user_count}}
    - roles: [{id: UUID, name: string}]
    - resource: {id, name, type}

    Note: sources field is defined in spec but not yet implemented.
    """

    def setUp(self):
        """Set up test data."""
        super().setUp()

        self.permission = Permission.objects.create(
            permission="app:resource:read",
            tenant=self.tenant,
        )

        self.role = RoleV2.objects.create(
            name="test_role",
            tenant=self.tenant,
        )
        self.role.permissions.add(self.permission)

        self.group = Group.objects.create(
            name="test_group",
            description="Test group description",
            tenant=self.tenant,
        )

        self.principal = Principal.objects.create(
            username=self.user_data["username"],
            tenant=self.tenant,
            type=Principal.Types.USER,
        )
        self.group.principals.add(self.principal)

        self.binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        self.binding_group = RoleBindingGroup.objects.create(
            group=self.group,
            binding=self.binding,
        )

    def tearDown(self):
        """Tear down test data."""
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.all().delete()
        self.group.principals.clear()
        Principal.objects.filter(tenant=self.tenant).delete()
        Group.objects.filter(tenant=self.tenant).delete()
        RoleV2.objects.filter(tenant=self.tenant).delete()
        Permission.objects.filter(tenant=self.tenant).delete()
        super().tearDown()

    # get_last_modified tests

    def test_last_modified_returns_modified_from_dict(self):
        """Test get_last_modified with dict containing 'modified' key."""
        modified_time = datetime(2025, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        obj = {"modified": modified_time}

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_last_modified(obj)

        self.assertEqual(result, modified_time)

    def test_last_modified_returns_latest_modified_from_dict(self):
        """Test get_last_modified with dict containing 'latest_modified' key."""
        latest_modified_time = datetime(2025, 1, 20, 14, 0, 0, tzinfo=timezone.utc)
        obj = {"latest_modified": latest_modified_time}

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_last_modified(obj)

        self.assertEqual(result, latest_modified_time)

    def test_last_modified_prefers_modified_over_latest_modified_in_dict(self):
        """Test get_last_modified prefers 'modified' over 'latest_modified' in dict."""
        modified_time = datetime(2025, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        latest_modified_time = datetime(2025, 1, 20, 14, 0, 0, tzinfo=timezone.utc)
        obj = {"modified": modified_time, "latest_modified": latest_modified_time}

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_last_modified(obj)

        self.assertEqual(result, modified_time)

    def test_last_modified_returns_none_for_empty_dict(self):
        """Test get_last_modified with empty dict returns None."""
        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_last_modified({})

        self.assertIsNone(result)

    def test_last_modified_returns_latest_modified_attribute_from_group(self):
        """Test get_last_modified with Group object uses latest_modified attribute."""
        mock_group = Mock(spec=Group)
        mock_group.latest_modified = datetime(2025, 1, 25, 12, 0, 0, tzinfo=timezone.utc)

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_last_modified(mock_group)

        self.assertEqual(result, mock_group.latest_modified)

    def test_last_modified_returns_none_when_group_has_no_latest_modified(self):
        """Test get_last_modified with Group object without latest_modified returns None."""
        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_last_modified(self.group)

        self.assertIsNone(result)

    # get_subject tests

    def test_subject_returns_correct_structure_for_group(self):
        """Test get_subject with Group object returns correct default structure.

        Default behavior (no field_selection) returns only id and type.
        """
        self.group.principalCount = 1

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_subject(self.group)

        # Default behavior: only id and type
        expected = {
            "id": self.group.uuid,
            "type": "group",
        }
        self.assertEqual(result, expected)

    def test_subject_handles_group_with_no_description(self):
        """Test get_subject with Group that has no description.

        Default behavior returns only id and type (no group details).
        """
        group = Group.objects.create(
            name="no_desc_group",
            description=None,
            tenant=self.tenant,
        )
        group.principalCount = 0

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_subject(group)

        # Default behavior: only id and type, no group details
        self.assertEqual(result["id"], group.uuid)
        self.assertEqual(result["type"], "group")
        self.assertNotIn("group", result)

        group.delete()

    def test_subject_includes_correct_user_count_for_multiple_principals(self):
        """Test get_subject with Group having multiple principals.

        Requires field_selection to include group.user_count.
        """
        principal2 = Principal.objects.create(
            username="user2",
            tenant=self.tenant,
            type=Principal.Types.USER,
        )
        self.group.principals.add(principal2)
        self.group.principalCount = 2

        field_selection = RoleBindingFieldSelection.parse("subject(group.user_count)")
        serializer = RoleBindingByGroupSerializer(context={"field_selection": field_selection})
        result = serializer.get_subject(self.group)

        self.assertEqual(result["type"], "group")
        self.assertEqual(result["group"]["user_count"], 2)

        principal2.delete()

    def test_subject_returns_none_for_non_group_object(self):
        """Test get_subject with non-Group object returns None."""
        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_subject({"name": "not a group"})

        self.assertIsNone(result)

    def test_subject_returns_none_for_none_input(self):
        """Test get_subject with None returns None."""
        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_subject(None)

        self.assertIsNone(result)

    # get_roles tests

    def test_roles_returns_roles_list_from_dict(self):
        """Test get_roles with dict containing roles list."""
        roles = [
            {"id": "uuid-1", "name": "Role 1"},
            {"id": "uuid-2", "name": "Role 2"},
        ]
        obj = {"roles": roles}

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_roles(obj)

        self.assertEqual(result, roles)

    def test_roles_returns_empty_list_from_dict_with_empty_roles(self):
        """Test get_roles with dict containing empty roles list."""
        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_roles({"roles": []})

        self.assertEqual(result, [])

    def test_roles_returns_empty_list_from_dict_without_roles_key(self):
        """Test get_roles with dict without roles key."""
        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_roles({})

        self.assertEqual(result, [])

    def test_roles_extracts_roles_from_group_prefetched_bindings(self):
        """Test get_roles with Group having prefetched bindings.

        id is always included.
        """
        mock_binding = Mock()
        mock_binding.role = self.role

        mock_binding_group = Mock()
        mock_binding_group.binding = mock_binding

        mock_group = Mock(spec=Group)
        mock_group.filtered_bindings = [mock_binding_group]

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_roles(mock_group)

        self.assertEqual(len(result), 1)
        # id is always included
        self.assertEqual(result[0]["id"], self.role.uuid)
        # Default behavior: no name included
        self.assertNotIn("name", result[0])

    def test_roles_deduplicates_same_role_from_multiple_bindings(self):
        """Test get_roles deduplicates roles when same role appears multiple times."""
        mock_binding = Mock()
        mock_binding.role = self.role

        mock_binding_group1 = Mock()
        mock_binding_group1.binding = mock_binding

        mock_binding_group2 = Mock()
        mock_binding_group2.binding = mock_binding

        mock_group = Mock(spec=Group)
        mock_group.filtered_bindings = [mock_binding_group1, mock_binding_group2]

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_roles(mock_group)

        self.assertEqual(len(result), 1)

    def test_roles_returns_multiple_different_roles(self):
        """Test get_roles with Group having multiple different roles."""
        role2 = RoleV2.objects.create(name="test_role_2", tenant=self.tenant)

        mock_binding1 = Mock()
        mock_binding1.role = self.role

        mock_binding2 = Mock()
        mock_binding2.role = role2

        mock_binding_group1 = Mock()
        mock_binding_group1.binding = mock_binding1

        mock_binding_group2 = Mock()
        mock_binding_group2.binding = mock_binding2

        mock_group = Mock(spec=Group)
        mock_group.filtered_bindings = [mock_binding_group1, mock_binding_group2]

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_roles(mock_group)

        self.assertEqual(len(result), 2)
        role_ids = {r["id"] for r in result}
        self.assertIn(self.role.uuid, role_ids)
        self.assertIn(role2.uuid, role_ids)

        role2.delete()

    def test_roles_returns_empty_list_when_group_has_no_filtered_bindings(self):
        """Test get_roles with Group without filtered_bindings attribute."""
        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_roles(self.group)

        self.assertEqual(result, [])

    def test_roles_skips_binding_with_no_role(self):
        """Test get_roles with binding that has no role."""
        mock_binding = Mock()
        mock_binding.role = None

        mock_binding_group = Mock()
        mock_binding_group.binding = mock_binding

        mock_group = Mock(spec=Group)
        mock_group.filtered_bindings = [mock_binding_group]

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_roles(mock_group)

        self.assertEqual(result, [])

    def test_roles_skips_binding_group_with_no_binding(self):
        """Test get_roles when binding_group has no binding."""
        mock_binding_group = Mock()
        mock_binding_group.binding = None

        mock_group = Mock(spec=Group)
        mock_group.filtered_bindings = [mock_binding_group]

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_roles(mock_group)

        self.assertEqual(result, [])

    # get_resource tests

    def test_resource_returns_resource_from_dict(self):
        """Test get_resource with dict containing resource data."""
        resource_data = {
            "id": "ws-12345",
            "name": "Test Workspace",
            "type": "workspace",
        }
        obj = {"resource": resource_data}

        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_resource(obj)

        self.assertEqual(result, resource_data)

    def test_resource_returns_empty_dict_from_dict_with_empty_resource(self):
        """Test get_resource with dict containing empty resource."""
        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_resource({"resource": {}})

        self.assertEqual(result, {})

    def test_resource_returns_empty_dict_from_dict_without_resource_key(self):
        """Test get_resource with dict without resource key."""
        serializer = RoleBindingByGroupSerializer()
        result = serializer.get_resource({})

        self.assertEqual(result, {})

    def test_resource_builds_from_context_for_group(self):
        """Test get_resource with Group object and context.

        Default behavior returns only resource id.
        """
        context = {
            "request": Mock(),
            "resource_id": "ws-12345",
            "resource_name": "Test Workspace",
            "resource_type": "workspace",
        }

        serializer = RoleBindingByGroupSerializer(context=context)
        result = serializer.get_resource(self.group)

        # Default behavior: only id
        expected = {"id": "ws-12345"}
        self.assertEqual(result, expected)

    def test_resource_returns_data_when_no_request_in_context(self):
        """Test get_resource with Group returns data even without request in context.

        Default behavior returns only resource id.
        """
        context = {
            "resource_id": "ws-12345",
            "resource_name": "Test Workspace",
            "resource_type": "workspace",
        }

        serializer = RoleBindingByGroupSerializer(context=context)
        result = serializer.get_resource(self.group)

        # Default behavior: only id
        expected = {"id": "ws-12345"}
        self.assertEqual(result, expected)

    def test_resource_returns_none_when_context_is_empty(self):
        """Test get_resource with Group and empty context."""
        serializer = RoleBindingByGroupSerializer(context={})
        result = serializer.get_resource(self.group)

        self.assertIsNone(result)

    def test_resource_handles_partial_context_values(self):
        """Test get_resource with partial context values.

        Default behavior returns only resource id.
        """
        context = {
            "request": Mock(),
            "resource_id": "ws-12345",
        }

        serializer = RoleBindingByGroupSerializer(context=context)
        result = serializer.get_resource(self.group)

        # Default behavior: only id
        expected = {"id": "ws-12345"}
        self.assertEqual(result, expected)

    # Full serialization tests

    def test_full_serialization_with_dict_input(self):
        """Test full serialization with dict input.

        Default behavior returns only basic fields (no last_modified).
        """
        modified_time = datetime(2025, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        obj = {
            "modified": modified_time,
            "roles": [{"id": "550e8400-e29b-41d4-a716-446655440002", "name": "Workspace Admin"}],
            "resource": {
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "name": "Engineering Workspace",
                "type": "workspace",
            },
        }

        serializer = RoleBindingByGroupSerializer(obj)
        data = serializer.data

        # Default behavior: last_modified not included
        self.assertNotIn("last_modified", data)
        self.assertIsNone(data["subject"])
        self.assertEqual(len(data["roles"]), 1)
        # Roles from dict pass through as-is
        self.assertEqual(data["roles"][0]["name"], "Workspace Admin")
        # Resource from dict passes through as-is
        self.assertEqual(data["resource"]["type"], "workspace")

    def test_full_serialization_with_group_and_context(self):
        """Test full serialization with Group object and context.

        Default behavior returns only basic fields:
        - subject: id, type (no group details)
        - roles: id only (no name)
        - resource: id only (no name, type)
        - no last_modified
        """
        self.group.principalCount = 1
        self.group.latest_modified = datetime(2025, 1, 20, 14, 0, 0, tzinfo=timezone.utc)

        mock_binding = Mock()
        mock_binding.role = self.role

        mock_binding_group = Mock()
        mock_binding_group.binding = mock_binding

        self.group.filtered_bindings = [mock_binding_group]

        context = {
            "request": Mock(),
            "resource_id": "ws-12345",
            "resource_name": "Test Workspace",
            "resource_type": "workspace",
        }

        serializer = RoleBindingByGroupSerializer(self.group, context=context)
        data = serializer.data

        # Default behavior: only basic fields
        self.assertNotIn("last_modified", data)
        self.assertEqual(data["subject"]["id"], self.group.uuid)
        self.assertEqual(data["subject"]["type"], "group")
        self.assertNotIn("group", data["subject"])
        self.assertEqual(len(data["roles"]), 1)
        self.assertEqual(data["roles"][0]["id"], self.role.uuid)
        self.assertNotIn("name", data["roles"][0])
        self.assertEqual(data["resource"], {"id": "ws-12345"})

    def test_full_serialization_with_multiple_groups(self):
        """Test serialization of multiple groups.

        Default behavior returns only basic fields (id, type) for each subject.
        """
        group2 = Group.objects.create(
            name="test_group_2",
            description="Second group",
            tenant=self.tenant,
        )
        group2.principalCount = 0
        self.group.principalCount = 1

        context = {
            "request": Mock(),
            "resource_id": "ws-12345",
            "resource_name": "Test Workspace",
            "resource_type": "workspace",
        }

        serializer = RoleBindingByGroupSerializer([self.group, group2], many=True, context=context)
        data = serializer.data

        self.assertEqual(len(data), 2)
        # Default behavior: only id and type, no group details
        self.assertEqual(data[0]["subject"]["id"], self.group.uuid)
        self.assertEqual(data[0]["subject"]["type"], "group")
        self.assertNotIn("group", data[0]["subject"])
        self.assertEqual(data[1]["subject"]["id"], group2.uuid)
        self.assertEqual(data[1]["subject"]["type"], "group")
        self.assertNotIn("group", data[1]["subject"])

        group2.delete()

    def test_serialized_output_matches_expected_structure(self):
        """Test that serialized output matches the expected default structure.

        Default behavior returns only basic fields:
        - subject: id, type (no group details)
        - roles: id only
        - resource: id only
        - no last_modified
        """
        self.group.principalCount = 5
        self.group.latest_modified = datetime(2025, 1, 20, 14, 0, 0, tzinfo=timezone.utc)

        mock_binding = Mock()
        mock_binding.role = self.role

        mock_binding_group = Mock()
        mock_binding_group.binding = mock_binding

        self.group.filtered_bindings = [mock_binding_group]

        context = {
            "request": Mock(),
            "resource_id": "550e8400-e29b-41d4-a716-446655440001",
            "resource_name": "Engineering Workspace",
            "resource_type": "workspace",
        }

        serializer = RoleBindingByGroupSerializer(self.group, context=context)
        data = serializer.data

        # Verify top-level fields (no last_modified by default)
        self.assertNotIn("last_modified", data)
        self.assertIn("subject", data)
        self.assertIn("roles", data)
        self.assertIn("resource", data)

        # Verify subject structure - only id and type by default
        subject = data["subject"]
        self.assertEqual(subject["type"], "group")
        self.assertIn("id", subject)
        self.assertNotIn("group", subject)

        # Verify roles structure - only id by default
        self.assertIsInstance(data["roles"], list)
        if data["roles"]:
            role = data["roles"][0]
            self.assertIn("id", role)
            self.assertNotIn("name", role)

        # Verify resource structure - only id by default
        resource = data["resource"]
        self.assertIn("id", resource)
        self.assertNotIn("name", resource)
        self.assertNotIn("type", resource)


class RoleBindingListInputSerializerTest(TestCase):
    """Test the RoleBindingListInputSerializer.

    Validates query parameter parsing for GET /role-bindings/.
    Uses subTest for parametrized coverage of valid/invalid inputs.
    """

    # --- role_id ---

    def test_role_id_valid_inputs(self):
        """Test that valid UUID formats are accepted for role_id."""
        valid_uuids = [
            ("standard", "550e8400-e29b-41d4-a716-446655440000"),
            ("zeros", "00000000-0000-0000-0000-000000000000"),
            ("generated", str(uuid.uuid4())),
        ]
        for label, value in valid_uuids:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"role_id": value})
                self.assertTrue(s.is_valid(), s.errors)
                self.assertEqual(s.validated_data["role_id"], uuid.UUID(value))

    def test_role_id_invalid_inputs(self):
        """Test that non-UUID values are rejected for role_id."""
        invalid_values = [
            ("not-a-uuid", "not-a-uuid"),
            ("integer", "12345"),
            ("empty", ""),
            ("spaces", "   "),
        ]
        for label, value in invalid_values:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"role_id": value})
                self.assertFalse(s.is_valid())
                self.assertIn("role_id", s.errors)

    def test_role_id_omitted_is_valid(self):
        """Test that omitting role_id is valid (required=False)."""
        s = RoleBindingListInputSerializer(data={})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertNotIn("role_id", s.validated_data)

    # --- fields ---

    def test_fields_valid_inputs(self):
        """Test that valid field selection strings are parsed correctly."""
        valid_fields = [
            ("role_name", "role(name)", {"role"}),
            ("subject_group", "subject(group.name)", {"subject"}),
            ("resource_type", "resource(type)", {"resource"}),
            ("combined", "role(name),resource(type)", {"role", "resource"}),
        ]
        for label, value, expected_nested_keys in valid_fields:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"fields": value})
                self.assertTrue(s.is_valid(), s.errors)
                fs = s.validated_data["fields"]
                self.assertIsNotNone(fs)
                for key in expected_nested_keys:
                    self.assertTrue(len(fs.get_nested(key)) > 0)

    def test_fields_invalid_inputs(self):
        """Test that invalid field selection strings are rejected."""
        invalid_fields = [
            ("unknown_object", "bogus(nope)"),
            ("invalid_role_field", "role(nonexistent)"),
            ("invalid_subject_field", "subject(bad_field)"),
        ]
        for label, value in invalid_fields:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"fields": value})
                self.assertFalse(s.is_valid())
                self.assertIn("fields", s.errors)

    def test_fields_omitted_is_valid(self):
        """Test that omitting fields is valid (required=False)."""
        s = RoleBindingListInputSerializer(data={})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertNotIn("fields", s.validated_data)

    # --- order_by ---

    def test_order_by_valid_inputs(self):
        """Test that valid order_by values pass through."""
        valid_values = [
            ("role_name", "role.name"),
            ("descending", "-role.name"),
            ("role_uuid", "role.uuid"),
        ]
        for label, value in valid_values:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"order_by": value})
                self.assertTrue(s.is_valid(), s.errors)
                self.assertEqual(s.validated_data["order_by"], value)

    def test_order_by_omitted_is_valid(self):
        """Test that omitting order_by is valid (required=False)."""
        s = RoleBindingListInputSerializer(data={})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertNotIn("order_by", s.validated_data)

    # --- resource_id ---

    def test_resource_id_valid_inputs(self):
        """Test that valid UUID formats are accepted for resource_id."""
        valid_uuids = [
            ("standard", "550e8400-e29b-41d4-a716-446655440000"),
            ("zeros", "00000000-0000-0000-0000-000000000000"),
            ("generated", str(uuid.uuid4())),
        ]
        for label, value in valid_uuids:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"resource_id": value, "resource_type": "workspace"})
                self.assertTrue(s.is_valid(), s.errors)
                self.assertEqual(s.validated_data["resource_id"], uuid.UUID(value))

    def test_resource_id_invalid_inputs(self):
        """Test that non-UUID values are rejected for resource_id."""
        invalid_values = [
            ("not-a-uuid", "not-a-uuid"),
            ("integer", "12345"),
            ("empty", ""),
            ("spaces", "   "),
        ]
        for label, value in invalid_values:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"resource_id": value})
                self.assertFalse(s.is_valid())
                self.assertIn("resource_id", s.errors)

    def test_resource_id_omitted_is_valid(self):
        """Test that omitting resource_id is valid (required=False)."""
        s = RoleBindingListInputSerializer(data={})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertNotIn("resource_id", s.validated_data)

    # --- resource_type ---

    def test_resource_type_valid_inputs(self):
        """Test that valid resource_type values are accepted."""
        cases = [
            ("workspace", "workspace"),
            ("custom", "custom_type"),
        ]
        resource_id = "550e8400-e29b-41d4-a716-446655440000"
        for label, value in cases:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"resource_type": value, "resource_id": resource_id})
                self.assertTrue(s.is_valid(), s.errors)
                self.assertEqual(s.validated_data["resource_type"], value)

    def test_resource_type_omitted_is_valid(self):
        """Test that omitting resource_type is valid (required=False)."""
        s = RoleBindingListInputSerializer(data={})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertNotIn("resource_type", s.validated_data)

    def test_resource_id_and_type_together(self):
        """Test that resource_id and resource_type work together."""
        res_uuid = str(uuid.uuid4())
        s = RoleBindingListInputSerializer(data={"resource_id": res_uuid, "resource_type": "workspace"})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertEqual(s.validated_data["resource_id"], uuid.UUID(res_uuid))
        self.assertEqual(s.validated_data["resource_type"], "workspace")

    # --- subject_type ---

    def test_subject_type_valid_inputs(self):
        """Test that valid subject_type values are accepted."""
        cases = [
            ("group", "group"),
            ("user", "user"),
        ]
        for label, value in cases:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"subject_type": value})
                self.assertTrue(s.is_valid(), s.errors)
                self.assertEqual(s.validated_data["subject_type"], value)

    def test_subject_type_omitted_is_valid(self):
        """Test that omitting subject_type is valid (required=False)."""
        s = RoleBindingListInputSerializer(data={})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertNotIn("subject_type", s.validated_data)

    # --- subject_id ---

    def test_subject_id_valid_inputs(self):
        """Test that valid UUID formats are accepted for subject_id."""
        valid_uuids = [
            ("standard", "550e8400-e29b-41d4-a716-446655440000"),
            ("zeros", "00000000-0000-0000-0000-000000000000"),
            ("generated", str(uuid.uuid4())),
        ]
        for label, value in valid_uuids:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"subject_id": value})
                self.assertTrue(s.is_valid(), s.errors)
                self.assertEqual(s.validated_data["subject_id"], uuid.UUID(value))

    def test_subject_id_invalid_inputs(self):
        """Test that non-UUID values are rejected for subject_id."""
        invalid_values = [
            ("not-a-uuid", "not-a-uuid"),
            ("integer", "12345"),
            ("empty", ""),
            ("spaces", "   "),
        ]
        for label, value in invalid_values:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={"subject_id": value})
                self.assertFalse(s.is_valid())
                self.assertIn("subject_id", s.errors)

    def test_subject_id_omitted_is_valid(self):
        """Test that omitting subject_id is valid (required=False)."""
        s = RoleBindingListInputSerializer(data={})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertNotIn("subject_id", s.validated_data)

    # --- NUL byte sanitization ---

    def test_nul_bytes_stripped_from_all_string_params(self):
        """Test that NUL bytes are stripped from all string parameters."""
        test_cases = [
            ("fields", "\x00role(name)\x00", {}),
            ("order_by", "\x00role.name\x00", {}),
            ("resource_type", "\x00workspace\x00", {"resource_id": "550e8400-e29b-41d4-a716-446655440000"}),
            ("subject_type", "\x00group\x00", {}),
        ]
        for label, raw, extra_params in test_cases:
            with self.subTest(label=label):
                s = RoleBindingListInputSerializer(data={label: raw, **extra_params})
                self.assertTrue(s.is_valid(), s.errors)

    def test_nul_bytes_stripped_from_resource_id(self):
        """Test that NUL bytes in resource_id are stripped before UUID validation."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        s = RoleBindingListInputSerializer(data={"resource_id": f"\x00{valid_uuid}\x00", "resource_type": "workspace"})
        self.assertTrue(s.is_valid(), s.errors)

    def test_nul_bytes_stripped_from_role_id(self):
        """Test that NUL bytes in role_id are stripped before UUID validation."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        s = RoleBindingListInputSerializer(data={"role_id": f"\x00{valid_uuid}\x00"})
        self.assertTrue(s.is_valid(), s.errors)

    def test_nul_bytes_stripped_from_subject_id(self):
        """Test that NUL bytes in subject_id are stripped before UUID validation."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        s = RoleBindingListInputSerializer(data={"subject_id": f"\x00{valid_uuid}\x00"})
        self.assertTrue(s.is_valid(), s.errors)

    # --- Combined ---

    def test_all_params_together(self):
        """Test that all parameters work together."""
        s = RoleBindingListInputSerializer(
            data={
                "role_id": str(uuid.uuid4()),
                "resource_id": str(uuid.uuid4()),
                "resource_type": "workspace",
                "subject_type": "group",
                "subject_id": str(uuid.uuid4()),
                "fields": "role(name),resource(type)",
                "order_by": "-role.name",
            }
        )
        self.assertTrue(s.is_valid(), s.errors)
        self.assertIn("role_id", s.validated_data)
        self.assertIn("resource_id", s.validated_data)
        self.assertIn("resource_type", s.validated_data)
        self.assertIn("subject_type", s.validated_data)
        self.assertIn("subject_id", s.validated_data)
        self.assertIsNotNone(s.validated_data["fields"])
        self.assertEqual(s.validated_data["order_by"], "-role.name")


class RoleBindingListOutputSerializerTest(IdentityRequest):
    """Test the RoleBindingListOutputSerializer.

    Tests verify the serializer produces output matching the API spec:
    - role: {id: UUID, name?: string}
    - subject: {id?: UUID, type: "group", group?: {name, description, user_count}}
    - resource: {id: string, type?: string}

    Uses subTest for parametrized field selection coverage.
    """

    def setUp(self):
        """Set up test data."""
        super().setUp()

        self.permission = Permission.objects.create(
            permission="app:resource:read",
            tenant=self.tenant,
        )

        self.role = RoleV2.objects.create(
            name="test_role",
            tenant=self.tenant,
        )
        self.role.permissions.add(self.permission)

        self.group = Group.objects.create(
            name="test_group",
            description="Test group description",
            tenant=self.tenant,
        )

        self.principal = Principal.objects.create(
            username=self.user_data["username"],
            tenant=self.tenant,
            type=Principal.Types.USER,
        )
        self.group.principals.add(self.principal)

        self.binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        self.binding_group = RoleBindingGroup.objects.create(
            group=self.group,
            binding=self.binding,
        )

    def tearDown(self):
        """Tear down test data."""
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.all().delete()
        self.group.principals.clear()
        Principal.objects.filter(tenant=self.tenant).delete()
        Group.objects.filter(tenant=self.tenant).delete()
        RoleV2.objects.filter(tenant=self.tenant).delete()
        Permission.objects.filter(tenant=self.tenant).delete()
        super().tearDown()

    def _serialize(self, obj, field_selection=None):
        """Serialize a RoleBinding with optional field selection."""
        context = {"request": Mock(), "field_selection": field_selection}
        return RoleBindingListOutputSerializer(obj, context=context).data

    # --- Default behavior (no field selection) ---

    def test_default_response_structure(self):
        """Test that default response has role, subject, resource keys only."""
        data = self._serialize(self.binding)

        self.assertIn("role", data)
        self.assertIn("subject", data)
        self.assertIn("resource", data)
        self.assertNotIn("last_modified", data)
        self.assertNotIn("roles", data)

    def test_default_role_returns_id_only(self):
        """Test that default role contains only id."""
        data = self._serialize(self.binding)

        self.assertEqual(data["role"], {"id": self.role.uuid})

    def test_default_subject_returns_id_and_type(self):
        """Test that default subject contains id and type."""
        data = self._serialize(self.binding)

        self.assertEqual(data["subject"]["id"], self.group.uuid)
        self.assertEqual(data["subject"]["type"], "group")
        self.assertNotIn("group", data["subject"])

    def test_default_resource_returns_id_only(self):
        """Test that default resource contains only id."""
        data = self._serialize(self.binding)

        self.assertEqual(data["resource"], {"id": "ws-12345"})

    # --- Edge cases ---

    def test_subject_no_group_entries(self):
        """Test that subject returns type-only when binding has no group entries."""
        # Delete the binding-group relationship
        self.binding_group.delete()

        data = self._serialize(self.binding)

        self.assertEqual(data["subject"], {"type": "group"})

    def test_many_serialization(self):
        """Test serialization of multiple bindings."""
        role2 = RoleV2.objects.create(name="test_role_2", tenant=self.tenant)
        binding2 = RoleBinding.objects.create(
            role=role2,
            resource_type="workspace",
            resource_id="ws-99999",
            tenant=self.tenant,
        )

        context = {"request": Mock(), "field_selection": None}
        data = RoleBindingListOutputSerializer([self.binding, binding2], many=True, context=context).data

        self.assertEqual(len(data), 2)
        role_ids = {item["role"]["id"] for item in data}
        self.assertIn(self.role.uuid, role_ids)
        self.assertIn(role2.uuid, role_ids)

        binding2.delete()
        role2.delete()

    # --- Field selection (parametrized) ---

    def test_field_selection_includes_requested_fields(self):
        """Test that field selection includes the correct fields in response."""
        test_cases = [
            (
                "role_name",
                "role(name)",
                lambda d: ("name" in d["role"] and d["role"]["name"] == "test_role"),
            ),
            (
                "resource_type",
                "resource(type)",
                lambda d: ("type" in d["resource"] and d["resource"]["type"] == "workspace"),
            ),
            (
                "subject_id",
                "subject(id)",
                lambda d: ("id" in d["subject"]),
            ),
            (
                "subject_group_name",
                "subject(group.name)",
                lambda d: (
                    "group" in d["subject"]
                    and d["subject"]["group"]["name"] == "test_group"
                    and "id" not in d["subject"]  # id excluded when not requested
                ),
            ),
            (
                "subject_group_description",
                "subject(group.description)",
                lambda d: (
                    "group" in d["subject"] and d["subject"]["group"]["description"] == "Test group description"
                ),
            ),
        ]
        for label, fields_str, check_fn in test_cases:
            with self.subTest(label=label):
                fs = RoleBindingFieldSelection.parse(fields_str)
                data = self._serialize(self.binding, field_selection=fs)
                self.assertTrue(check_fn(data), f"Check failed for {label}: {data}")

    def test_field_selection_excludes_unrequested_fields(self):
        """Test that unrequested fields are excluded from response."""
        test_cases = [
            ("role_name_only", "role(name)", "resource", lambda d: "type" not in d["resource"]),
            ("resource_type_only", "resource(type)", "role", lambda d: "name" not in d["role"]),
        ]
        for label, fields_str, check_key, check_fn in test_cases:
            with self.subTest(label=label):
                fs = RoleBindingFieldSelection.parse(fields_str)
                data = self._serialize(self.binding, field_selection=fs)
                self.assertTrue(check_fn(data), f"Exclusion check failed for {label}: {data}")

    def test_combined_field_selection(self):
        """Test combined field selection across multiple objects."""
        fs = RoleBindingFieldSelection.parse("role(name),subject(group.name),resource(type)")
        data = self._serialize(self.binding, field_selection=fs)

        # Role includes id (always) + name
        self.assertEqual(data["role"]["id"], self.role.uuid)
        self.assertEqual(data["role"]["name"], "test_role")

        # Subject includes type (always) + group.name, but not id
        self.assertEqual(data["subject"]["type"], "group")
        self.assertNotIn("id", data["subject"])
        self.assertEqual(data["subject"]["group"]["name"], "test_group")

        # Resource includes id (always) + type
        self.assertEqual(data["resource"]["id"], "ws-12345")
        self.assertEqual(data["resource"]["type"], "workspace")


@override_settings(ATOMIC_RETRY_DISABLED=True)
class BatchCreateRequestSerializerTests(IdentityRequest):
    """Tests for BatchCreateRoleBindingRequestSerializer input validation."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.permission = Permission.objects.create(permission="app:resource:read", tenant=self.tenant)
        self.role_service = RoleV2Service()
        self.role = self.role_service.create(
            name="test_role",
            description="Test role",
            permission_data=[{"application": "app", "resource_type": "resource", "operation": "read"}],
            tenant=self.tenant,
        )
        self.group = Group.objects.create(name="test_group", tenant=self.tenant)
        self.mock_request = Mock()
        self.mock_request.tenant = self.tenant

        self.valid_payload = {
            "requests": [
                {
                    "resource": {"id": str(uuid.uuid4()), "type": "workspace"},
                    "subject": {"id": str(self.group.uuid), "type": "group"},
                    "role": {"id": str(self.role.uuid)},
                }
            ],
        }

    def tearDown(self):
        """Tear down test data."""
        RoleBinding.objects.all().delete()
        Group.objects.filter(tenant=self.tenant).delete()
        RoleV2.objects.filter(tenant=self.tenant).delete()
        Permission.objects.filter(tenant=self.tenant).delete()
        super().tearDown()

    def _make_serializer(self, data):
        return BatchCreateRoleBindingRequestSerializer(data=data, context={"request": self.mock_request})

    def test_valid_request_passes_validation(self):
        """Minimal valid payload passes is_valid()."""
        serializer = self._make_serializer(self.valid_payload)
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_rejects_empty_requests_list(self):
        """Empty requests list fails min_length=1."""
        serializer = self._make_serializer({"requests": []})
        self.assertFalse(serializer.is_valid())
        self.assertIn("requests", serializer.errors)

    def test_rejects_missing_requests(self):
        """Missing requests key fails."""
        serializer = self._make_serializer({})
        self.assertFalse(serializer.is_valid())
        self.assertIn("requests", serializer.errors)

    def test_rejects_invalid_subject_type(self):
        """Subject type not in ['user', 'group'] fails."""
        payload = {
            "requests": [
                {
                    "resource": {"id": str(uuid.uuid4()), "type": "workspace"},
                    "subject": {"id": str(uuid.uuid4()), "type": "foo_type"},
                    "role": {"id": str(uuid.uuid4())},
                }
            ],
        }
        serializer = self._make_serializer(payload)
        self.assertFalse(serializer.is_valid())
        self.assertIn("requests", serializer.errors)

    def test_rejects_missing_role_id(self):
        """Request item with missing role.id fails."""
        payload = {
            "requests": [
                {
                    "resource": {"id": str(uuid.uuid4()), "type": "workspace"},
                    "subject": {"id": str(uuid.uuid4()), "type": "group"},
                    "role": {},
                }
            ],
        }
        serializer = self._make_serializer(payload)
        self.assertFalse(serializer.is_valid())
        self.assertIn("requests", serializer.errors)

    def test_rejects_invalid_uuid(self):
        """Non-UUID role.id fails."""
        payload = {
            "requests": [
                {
                    "resource": {"id": str(uuid.uuid4()), "type": "workspace"},
                    "subject": {"id": str(uuid.uuid4()), "type": "group"},
                    "role": {"id": "not-a-uuid"},
                }
            ],
        }
        serializer = self._make_serializer(payload)
        self.assertFalse(serializer.is_valid())
        self.assertIn("requests", serializer.errors)

    def test_rejects_invalid_fields_param(self):
        """Invalid field mask fails validation."""
        payload = {**self.valid_payload, "fields": "unknown(foo)"}
        serializer = self._make_serializer(payload)
        self.assertFalse(serializer.is_valid())
        self.assertIn("fields", serializer.errors)

    def test_valid_fields_param_parsed(self):
        """Valid field mask is parsed into RoleBindingFieldSelection."""
        payload = {**self.valid_payload, "fields": "role(name)"}
        serializer = self._make_serializer(payload)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertIsNotNone(serializer.validated_data["fields"])
        self.assertIn("name", serializer.validated_data["fields"].get_nested("role"))

    def test_rejects_over_max_items_limit(self):
        """101 items exceeds max_length=100 and fails validation."""
        payload = {
            "requests": [
                {
                    "resource": {"id": str(uuid.uuid4()), "type": "workspace"},
                    "subject": {"id": str(self.group.uuid), "type": "group"},
                    "role": {"id": str(self.role.uuid)},
                }
            ]
            * 101,
        }
        serializer = self._make_serializer(payload)
        self.assertFalse(serializer.is_valid())
        self.assertIn("requests", serializer.errors)


@override_settings(ATOMIC_RETRY_DISABLED=True)
class BatchCreateResponseSerializerTests(IdentityRequest):
    """Tests for BatchCreateRoleBindingResponseItemSerializer output formatting."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.role = RoleV2.objects.create(name="test_role", tenant=self.tenant)
        self.group = Group.objects.create(name="test_group", description="Test group", tenant=self.tenant)
        self.principal = Principal.objects.create(
            username="testuser", tenant=self.tenant, user_id="testuser", type=Principal.Types.USER
        )

        self.group_result = {
            "role": self.role,
            "subject_type": "group",
            "subject": self.group,
            "resource_type": "workspace",
            "resource_id": "ws-123",
            "resource_name": "Test Workspace",
        }

    def tearDown(self):
        """Tear down test data."""
        Principal.objects.filter(tenant=self.tenant).delete()
        Group.objects.filter(tenant=self.tenant).delete()
        RoleV2.objects.filter(tenant=self.tenant).delete()
        super().tearDown()

    def test_default_fields(self):
        """Default output includes role.id, subject.id, subject.type, resource.id."""
        serializer = BatchCreateRoleBindingResponseItemSerializer(self.group_result, context={})
        data = serializer.data

        self.assertEqual(data["role"], {"id": self.role.uuid})
        self.assertEqual(data["subject"]["id"], self.group.uuid)
        self.assertEqual(data["subject"]["type"], "group")
        self.assertEqual(data["resource"], {"id": "ws-123"})

    def test_fields_context_filters_response(self):
        """With fields=role(name,id), response includes only role with those sub-fields."""
        fields = RoleBindingFieldSelection.parse("role(name,id)")
        serializer = BatchCreateRoleBindingResponseItemSerializer(
            self.group_result, context={"field_selection": fields}
        )
        data = serializer.data

        self.assertEqual(data["role"]["id"], self.role.uuid)
        self.assertEqual(data["role"]["name"], "test_role")

    def test_fields_context_masks_sub_fields(self):
        """With fields=role(id), only role.id is populated."""
        fields = RoleBindingFieldSelection.parse("role(id)")
        serializer = BatchCreateRoleBindingResponseItemSerializer(
            self.group_result, context={"field_selection": fields}
        )
        data = serializer.data

        self.assertEqual(data["role"], {"id": self.role.uuid})
        self.assertNotIn("name", data["role"])
        self.assertNotIn("subject", data)
        self.assertNotIn("resource", data)

    def test_group_subject_includes_group_details(self):
        """With fields=subject(group.name), group sub-object is included."""
        fields = RoleBindingFieldSelection.parse("subject(group.name)")
        serializer = BatchCreateRoleBindingResponseItemSerializer(
            self.group_result, context={"field_selection": fields}
        )
        data = serializer.data

        self.assertIn("group", data["subject"])
        self.assertEqual(data["subject"]["group"]["name"], "test_group")


class UpdateRoleBindingRequestSerializerTests(IdentityRequest):
    """Tests for UpdateRoleBindingRequestSerializer.

    Organized into parameterized groups:
    - Happy-path valid inputs
    - Missing required fields
    - Invalid input / validation errors
    - NUL byte sanitization
    """

    def setUp(self):
        """Set up test data."""
        super().setUp()

    def _make_valid_data(self, **overrides):
        """Build a valid serializer input dict, with optional field overrides.

        Use ``_REMOVE`` sentinel value to omit a key entirely.
        """
        data = {
            "resource_id": "ws-123",
            "resource_type": "workspace",
            "subject_id": "550e8400-e29b-41d4-a716-446655440000",
            "subject_type": "group",
            "roles": [{"id": "550e8400-e29b-41d4-a716-446655440001"}],
        }
        for key, value in overrides.items():
            if value is _REMOVE:
                data.pop(key, None)
            else:
                data[key] = value
        return data

    # ── Happy-path tests (parameterized) ─────────────────────────────

    def test_valid_inputs(self):
        """Test various valid inputs pass validation."""
        cases = [
            ("group subject type", {}),
            ("user subject type", {"subject_type": "user"}),
            (
                "multiple roles",
                {
                    "roles": [
                        {"id": "550e8400-e29b-41d4-a716-446655440001"},
                        {"id": "550e8400-e29b-41d4-a716-446655440002"},
                    ]
                },
            ),
            ("fields param parsed", {"fields": "subject(group.name)"}),
            ("fields omitted", {"fields": _REMOVE}),
            ("fields blank string", {"fields": ""}),
        ]

        for description, overrides in cases:
            with self.subTest(case=description):
                data = self._make_valid_data(**overrides)
                serializer = UpdateRoleBindingRequestSerializer(data=data)
                self.assertTrue(serializer.is_valid(), f"{description}: {serializer.errors}")

    def test_fields_param_parsed_into_field_selection(self):
        """Test that a valid fields param is parsed into a FieldSelection object."""
        data = self._make_valid_data(fields="subject(group.name)")
        serializer = UpdateRoleBindingRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertIsInstance(serializer.validated_data["fields"], FieldSelection)
        self.assertIn("group.name", serializer.validated_data["fields"].get_nested("subject"))

    def test_fields_omitted_defaults_to_default_selection(self):
        """Test that omitting the fields param applies the default field selection."""
        data = self._make_valid_data(fields=_REMOVE)
        serializer = UpdateRoleBindingRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        field_selection = serializer.validated_data["fields"]
        self.assertIsInstance(field_selection, FieldSelection)
        self.assertIn("id", field_selection.get_nested("resource"))
        self.assertIn("id", field_selection.get_nested("subject"))
        self.assertIn("id", field_selection.get_nested("roles"))

    def test_fields_blank_string_defaults_to_default_selection(self):
        """Test that a blank fields param applies the default field selection."""
        data = self._make_valid_data(fields="")
        serializer = UpdateRoleBindingRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        field_selection = serializer.validated_data["fields"]
        self.assertIsInstance(field_selection, FieldSelection)
        self.assertIn("id", field_selection.get_nested("resource"))
        self.assertIn("id", field_selection.get_nested("subject"))
        self.assertIn("id", field_selection.get_nested("roles"))

    def test_multiple_roles_validated(self):
        """Test that multiple valid role UUIDs are accepted."""
        data = self._make_valid_data(
            roles=[
                {"id": "550e8400-e29b-41d4-a716-446655440001"},
                {"id": "550e8400-e29b-41d4-a716-446655440002"},
            ]
        )
        serializer = UpdateRoleBindingRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(len(serializer.validated_data["roles"]), 2)

    # ── Missing required fields (parameterized) ──────────────────────

    def test_missing_required_field_returns_error(self):
        """Test that omitting any single required field fails validation."""
        required_fields = ["resource_id", "resource_type", "subject_id", "subject_type", "roles"]

        for field in required_fields:
            with self.subTest(missing_field=field):
                data = self._make_valid_data(**{field: _REMOVE})
                serializer = UpdateRoleBindingRequestSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn(field, serializer.errors)

    # ── Validation error tests (parameterized) ───────────────────────

    def test_invalid_input_returns_validation_error(self):
        """Test various invalid inputs are rejected with correct error fields and messages."""
        cases = [
            # (description, overrides, error_field, expected_message_substring)
            (
                "empty roles list",
                {"roles": []},
                "roles",
                "At least one role is required.",
            ),
            (
                "invalid subject type",
                {"subject_type": "invalid_type"},
                "subject_type",
                "Unsupported subject type: 'invalid_type'",
            ),
            (
                "invalid UUID in roles",
                {"roles": [{"id": "not-a-uuid"}]},
                "roles",
                None,  # DRF UUID message varies; just check field presence
            ),
            (
                "missing id in role item",
                {"roles": [{}]},
                "roles",
                None,
            ),
            (
                "invalid fields param",
                {"fields": "bogus_field"},
                "fields",
                "Invalid field(s):",
            ),
        ]

        for description, overrides, error_field, expected_msg in cases:
            with self.subTest(case=description):
                data = self._make_valid_data(**overrides)
                serializer = UpdateRoleBindingRequestSerializer(data=data)
                self.assertFalse(serializer.is_valid(), f"Expected invalid for: {description}")
                self.assertIn(error_field, serializer.errors, f"Expected '{error_field}' in errors for: {description}")
                if expected_msg:
                    error_messages = str(serializer.errors[error_field])
                    self.assertIn(expected_msg, error_messages, f"Expected message for: {description}")

    # ── NUL byte sanitization (parameterized) ────────────────────────

    def test_nul_bytes_sanitized_from_string_fields(self):
        """Test that NUL bytes are stripped from all string fields."""
        cases = [
            ("resource_id", "ws-123\x00", "ws-123"),
            ("resource_type", "work\x00space", "workspace"),
            (
                "subject_id",
                "550e8400-e29b-41d4-a716-446655440000\x00",
                "550e8400-e29b-41d4-a716-446655440000",
            ),
            ("subject_type", "gro\x00up", "group"),
        ]

        for field_name, nul_value, expected_clean in cases:
            with self.subTest(field=field_name):
                data = self._make_valid_data(**{field_name: nul_value})
                serializer = UpdateRoleBindingRequestSerializer(data=data)
                self.assertTrue(serializer.is_valid(), f"NUL in {field_name}: {serializer.errors}")
                self.assertEqual(serializer.validated_data[field_name], expected_clean)


class UpdateRoleBindingResponseSerializerTests(IdentityRequest):
    """Tests for UpdateRoleBindingResponseSerializer field masking.

    Verifies that the response serializer respects field_selection context:
    - Default (no field_selection): subject has id+type, roles have id only,
      resource has id only.
    - With field_selection: only explicitly requested fields appear.
    """

    def setUp(self):
        """Set up test data."""
        super().setUp()

        self.role1 = RoleV2.objects.create(name="role_one", tenant=self.tenant)
        self.role2 = RoleV2.objects.create(name="role_two", tenant=self.tenant)

        self.group = Group.objects.create(
            name="test_group",
            description="A test group",
            tenant=self.tenant,
        )
        self.principal = Principal.objects.create(
            username="testuser",
            tenant=self.tenant,
            type=Principal.Types.USER,
        )
        self.group.principals.add(self.principal)

    def tearDown(self):
        """Tear down test data."""
        self.group.principals.clear()
        Principal.objects.filter(tenant=self.tenant).delete()
        Group.objects.filter(tenant=self.tenant).delete()
        RoleV2.objects.filter(tenant=self.tenant).delete()
        super().tearDown()

    def _make_group_result(self, roles=None):
        """Build an UpdateRoleBindingResult for a group subject."""
        return UpdateRoleBindingResult(
            subject_type=SubjectType.GROUP,
            roles=roles or [self.role1],
            resource_id="ws-123",
            resource_type="workspace",
            subject=self.group,
            resource_name="My Workspace",
        )

    def _make_user_result(self, roles=None):
        """Build an UpdateRoleBindingResult for a user subject."""
        return UpdateRoleBindingResult(
            subject_type=SubjectType.USER,
            roles=roles or [self.role1],
            resource_id="ws-123",
            resource_type="workspace",
            subject=self.principal,
            resource_name="My Workspace",
        )

    # ── Default behaviour (no field_selection) ───────────────────────

    def test_default_group_response(self):
        """Default response for a group subject includes id+type, role id only, resource id only."""
        result = self._make_group_result()
        serializer = UpdateRoleBindingResponseSerializer(result)
        data = serializer.data

        # subject: id + type only
        self.assertEqual(data["subject"], {"id": self.group.uuid, "type": "group"})
        # roles: id only
        self.assertEqual(data["roles"], [{"id": self.role1.uuid}])
        # resource: id only
        self.assertEqual(data["resource"], {"id": "ws-123"})
        # only subject, roles, resource keys
        self.assertEqual(set(data.keys()), {"subject", "roles", "resource"})

    def test_default_user_response(self):
        """Default response for a user subject includes id+type+user details."""
        result = self._make_user_result()
        serializer = UpdateRoleBindingResponseSerializer(result)
        data = serializer.data

        self.assertEqual(
            data["subject"],
            {"id": self.principal.uuid, "type": "user", "user": {"username": "testuser"}},
        )
        self.assertEqual(data["roles"], [{"id": self.role1.uuid}])
        self.assertEqual(data["resource"], {"id": "ws-123"})
        self.assertEqual(set(data.keys()), {"subject", "roles", "resource"})

    def test_default_multiple_roles_returns_id_only(self):
        """Default response with multiple roles returns id for each, no name."""
        result = self._make_group_result(roles=[self.role1, self.role2])
        serializer = UpdateRoleBindingResponseSerializer(result)
        data = serializer.data

        role_ids = {r["id"] for r in data["roles"]}
        self.assertEqual(role_ids, {self.role1.uuid, self.role2.uuid})
        for role in data["roles"]:
            self.assertNotIn("name", role)

    # ── With field_selection ─────────────────────────────────────────

    def test_field_selection_role_name(self):
        """Requesting roles(name) returns only name."""
        result = self._make_group_result()
        field_selection = RoleBindingBySubjectFieldSelection(nested_fields={"roles": {"name"}})
        serializer = UpdateRoleBindingResponseSerializer(result, context={"field_selection": field_selection})
        data = serializer.data

        self.assertEqual(data, {"roles": [{"name": "role_one"}]})

    def test_field_selection_resource_name_and_type(self):
        """Requesting resource(name,type) returns only those."""
        result = self._make_group_result()
        field_selection = RoleBindingBySubjectFieldSelection(nested_fields={"resource": {"name", "type"}})
        serializer = UpdateRoleBindingResponseSerializer(result, context={"field_selection": field_selection})
        data = serializer.data

        self.assertEqual(data, {"resource": {"name": "My Workspace", "type": "workspace"}})

    def test_field_selection_subject_id(self):
        """Requesting subject(id) returns only id."""
        result = self._make_group_result()
        field_selection = RoleBindingBySubjectFieldSelection(nested_fields={"subject": {"id"}})
        serializer = UpdateRoleBindingResponseSerializer(result, context={"field_selection": field_selection})
        data = serializer.data

        self.assertEqual(data, {"subject": {"id": self.group.uuid}})

    def test_field_selection_subject_without_id(self):
        """When only subject(group.name) is requested, only group details appear."""
        result = self._make_group_result()
        field_selection = RoleBindingBySubjectFieldSelection(nested_fields={"subject": {"group.name"}})
        serializer = UpdateRoleBindingResponseSerializer(result, context={"field_selection": field_selection})
        data = serializer.data

        self.assertEqual(data, {"subject": {"group": {"name": "test_group"}}})

    def test_field_selection_group_details(self):
        """Requesting subject(group.name,group.description,group.user_count) returns only those."""
        self.group.principalCount = 3
        result = self._make_group_result()
        field_selection = RoleBindingBySubjectFieldSelection(
            nested_fields={"subject": {"group.name", "group.description", "group.user_count"}}
        )
        serializer = UpdateRoleBindingResponseSerializer(result, context={"field_selection": field_selection})
        data = serializer.data

        self.assertEqual(
            data,
            {"subject": {"group": {"name": "test_group", "description": "A test group", "user_count": 3}}},
        )

    def test_field_selection_user_details(self):
        """Requesting subject(id,user.username) returns only those."""
        result = self._make_user_result()
        field_selection = RoleBindingBySubjectFieldSelection(nested_fields={"subject": {"id", "user.username"}})
        serializer = UpdateRoleBindingResponseSerializer(result, context={"field_selection": field_selection})
        data = serializer.data

        self.assertEqual(
            data,
            {"subject": {"id": self.principal.uuid, "user": {"username": "testuser"}}},
        )

    def test_field_selection_resource_id_only(self):
        """Requesting resource(id) returns only id."""
        result = self._make_group_result()
        field_selection = RoleBindingBySubjectFieldSelection(nested_fields={"resource": {"id"}})
        serializer = UpdateRoleBindingResponseSerializer(result, context={"field_selection": field_selection})
        data = serializer.data

        self.assertEqual(data, {"resource": {"id": "ws-123"}})
