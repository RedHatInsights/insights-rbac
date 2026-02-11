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
"""Test the RoleBindingByGroupSerializer."""

from datetime import datetime, timezone
from unittest.mock import Mock

from management.models import Group, Permission, Principal, RoleBinding, RoleBindingGroup, RoleV2
from management.role_binding.serializer import RoleBindingByGroupSerializer, RoleBindingFieldSelection
from tests.identity_request import IdentityRequest


class RoleBindingByGroupSerializerTest(IdentityRequest):
    """Test the RoleBindingByGroupSerializer.

    Tests verify the serializer produces output matching the API spec:
    - last_modified: datetime timestamp
    - subject: {id: UUID, type: "group", group: {name, description, user_count}}
    - roles: [{id: UUID, name: string}]
    - resource: {id, name, type}

    Note: inherited_from field is defined in spec but not yet implemented.
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

        field_selection = RoleBindingFieldSelection(nested_fields={"subject": {"group.user_count"}})
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
