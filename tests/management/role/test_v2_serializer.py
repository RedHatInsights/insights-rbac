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
"""Test the RoleV2 serializer."""

from django.test import TestCase

from management.models import (
    RoleV2,
    Permission,
)
from management.role.v2_serializer import (
    FieldSelection,
    FieldSelectionValidationError,
    RoleInputSerializer,
    RoleOutputSerializer,
)
from tests.identity_request import IdentityRequest


class FieldSelectionTests(TestCase):
    """Test the FieldSelection class."""

    def test_parse_valid_fields(self):
        """Test parsing valid field names returns correct set."""
        result = FieldSelection.parse("id,name,description")
        self.assertIsNotNone(result)
        self.assertEqual(result.selected_fields, {"id", "name", "description"})

    def test_parse_invalid_fields_raises_error(self):
        """Test parsing invalid field names raises FieldSelectionValidationError."""
        with self.assertRaises(FieldSelectionValidationError) as cm:
            FieldSelection.parse("id,invalid_field,name")
        self.assertIn("invalid_field", cm.exception.message)

    def test_parse_empty_returns_none(self):
        """Test parsing empty/None input returns None (server applies defaults)."""
        self.assertIsNone(FieldSelection.parse(None))
        self.assertIsNone(FieldSelection.parse(""))


class RoleInputSerializerTests(TestCase):
    """Test the RoleInputSerializer for query parameter validation."""

    def test_valid_fields_parameter(self):
        """Test valid fields parameter passes validation."""
        serializer = RoleInputSerializer(data={"fields": "id,name,permissions_count"})
        self.assertTrue(serializer.is_valid())
        field_selection = serializer.validated_data["fields"]
        self.assertIsInstance(field_selection, FieldSelection)
        self.assertEqual(field_selection.selected_fields, {"id", "name", "permissions_count"})

    def test_invalid_fields_parameter(self):
        """Test invalid fields parameter raises validation error."""
        serializer = RoleInputSerializer(data={"fields": "id,foobar_field"})
        self.assertFalse(serializer.is_valid())
        self.assertIn("fields", serializer.errors)
        self.assertIn("foobar_field", str(serializer.errors["fields"]))


class RoleOutputSerializerTests(IdentityRequest):
    """Test the RoleOutputSerializer for role serialization."""

    def setUp(self):
        """Set up the RoleOutputSerializer tests."""
        super().setUp()
        self.permission = Permission.objects.create(permission="inventory:hosts:read", tenant=self.tenant)
        self.role = RoleV2.objects.create(
            name="test_role",
            description="Test role description",
            tenant=self.tenant,
        )
        self.role.permissions.add(self.permission)

    def tearDown(self):
        """Tear down the RoleOutputSerializer tests."""
        super().tearDown()
        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

    def test_default_fields_when_no_field_selection(self):
        """Test that default fields are returned when no fields param is provided."""
        serializer = RoleOutputSerializer(self.role)
        data = serializer.data

        # Should return exactly the default fields
        expected_fields = {"id", "name", "description", "last_modified"}
        self.assertEqual(set(data.keys()), expected_fields)

        self.assertEqual(data["name"], "test_role")
        self.assertEqual(data["description"], "Test role description")
        self.assertEqual(data["id"], self.role.uuid)
        self.assertIsNotNone(data["last_modified"])

    def test_custom_fields_with_field_selection(self):
        """Test that only requested fields are returned with field selection."""
        field_selection = FieldSelection.parse("id,name,permissions_count")
        serializer = RoleOutputSerializer(self.role, context={"field_selection": field_selection})
        data = serializer.data

        self.assertEqual(set(data.keys()), {"id", "name", "permissions_count"})
        self.assertEqual(data["name"], "test_role")
        self.assertEqual(data["permissions_count"], 1)

    def test_permissions_field_returns_permission_objects(self):
        """Test that permissions field returns properly formatted permission objects."""
        field_selection = FieldSelection.parse("id,permissions")
        serializer = RoleOutputSerializer(self.role, context={"field_selection": field_selection})
        data = serializer.data

        self.assertIn("permissions", data)
        self.assertEqual(len(data["permissions"]), 1)

        perm = data["permissions"][0]
        self.assertEqual(perm["application"], "inventory")
        self.assertEqual(perm["resource_type"], "hosts")
        self.assertEqual(perm["operation"], "read")
