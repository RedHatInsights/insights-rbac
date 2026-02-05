#
# Copyright 2026 Red Hat, Inc.
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

from django.db.models import Count

from management.models import (
    RoleV2,
    Permission,
)
from management.role.v2_serializer import RoleFieldSelection, RoleV2InputSerializer, RoleV2ResponseSerializer
from management.role_binding.serializer import FieldSelectionValidationError
from tests.identity_request import IdentityRequest


class RoleV2SerializerTests(IdentityRequest):
    """Test the RoleV2 serializers."""

    def setUp(self):
        """Set up the serializer tests."""
        super().setUp()
        self.permission = Permission.objects.create(permission="inventory:hosts:read", tenant=self.tenant)
        self.role = RoleV2.objects.create(
            name="test_role",
            description="Test role description",
            tenant=self.tenant,
        )
        self.role.permissions.add(self.permission)

    def tearDown(self):
        """Tear down the serializer tests."""
        super().tearDown()
        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

    def _get_annotated_role(self):
        """Get the role with the permissions_count annotation."""
        return RoleV2.objects.annotate(permissions_count_annotation=Count("permissions", distinct=True)).get(
            pk=self.role.pk
        )

    def _build_context(self, fields=None):
        """Build serializer context with resolved field set."""
        if not fields:
            return {"fields": RoleV2InputSerializer.DEFAULT_FIELDS}
        field_selection = RoleFieldSelection.parse(fields)
        resolved = field_selection.root_fields & set(RoleV2ResponseSerializer.Meta.fields)
        return {"fields": resolved or RoleV2InputSerializer.DEFAULT_FIELDS}

    def test_default_fields_when_no_field_selection(self):
        """Test that default fields are returned when no fields param is provided."""
        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role, context=self._build_context())
        data = serializer.data

        # Should return exactly the default fields
        expected_fields = {"id", "name", "description", "last_modified"}
        self.assertEqual(set(data.keys()), expected_fields)

        self.assertEqual(data["name"], "test_role")
        self.assertEqual(data["description"], "Test role description")
        self.assertEqual(data["id"], str(self.role.uuid))
        self.assertIsNotNone(data["last_modified"])

    def test_custom_fields_with_field_selection(self):
        """Test that only requested fields are returned with field selection."""
        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role, context=self._build_context("id,name,permissions_count"))
        data = serializer.data

        self.assertEqual(set(data.keys()), {"id", "name", "permissions_count"})
        self.assertEqual(data["name"], "test_role")
        self.assertEqual(data["permissions_count"], 1)

    def test_permissions_field_returns_permission_objects(self):
        """Test that permissions field returns properly formatted permission objects."""
        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role, context=self._build_context("id,permissions"))
        data = serializer.data

        self.assertIn("permissions", data)
        self.assertEqual(len(data["permissions"]), 1)

        perm = data["permissions"][0]
        self.assertEqual(perm["application"], "inventory")
        self.assertEqual(perm["resource_type"], "hosts")
        self.assertEqual(perm["operation"], "read")

    def test_all_fields_can_be_selected(self):
        """Test that all valid fields can be selected."""
        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(
            role,
            context=self._build_context("id,name,description,permissions_count,last_modified,permissions"),
        )
        data = serializer.data

        expected = {"id", "name", "description", "permissions_count", "last_modified", "permissions"}
        self.assertEqual(set(data.keys()), expected)

    def test_invalid_fields_raise_validation_error(self):
        """Test that invalid field names raise a validation error during parsing."""

        with self.assertRaises(FieldSelectionValidationError):
            RoleFieldSelection.parse("id,invalid_field,name")

    def test_multiple_permissions_serialization(self):
        """Test that role with multiple permissions serializes correctly."""
        # Add more permissions
        perm2 = Permission.objects.create(permission="inventory:hosts:write", tenant=self.tenant)
        perm3 = Permission.objects.create(permission="rbac:roles:read", tenant=self.tenant)
        self.role.permissions.add(perm2, perm3)

        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role, context=self._build_context("id,permissions,permissions_count"))
        data = serializer.data

        self.assertEqual(data["permissions_count"], 3)
        self.assertEqual(len(data["permissions"]), 3)

        # Verify all permissions have correct structure
        for perm in data["permissions"]:
            self.assertIn("application", perm)
            self.assertIn("resource_type", perm)
            self.assertIn("operation", perm)

    def test_role_with_no_permissions(self):
        """Test that role with no permissions returns empty list."""
        self.role.permissions.clear()

        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role, context=self._build_context("id,permissions,permissions_count"))
        data = serializer.data

        self.assertEqual(data["permissions_count"], 0)
        self.assertEqual(data["permissions"], [])

    def test_fields_with_whitespace(self):
        """Test that fields with whitespace around commas are parsed correctly."""
        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role, context=self._build_context("id, name, description"))
        data = serializer.data

        self.assertEqual(set(data.keys()), {"id", "name", "description"})

    def test_fields_with_null_character(self):
        """Test that null characters in fields param are sanitized."""
        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role, context=self._build_context("id,na\x00me,description"))
        data = serializer.data

        # Null character should be removed, "name" should be parsed correctly
        self.assertEqual(set(data.keys()), {"id", "name", "description"})

    def test_fields_with_duplicates(self):
        """Test that duplicate field names are handled."""
        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role, context=self._build_context("id,name,id,name"))
        data = serializer.data

        self.assertEqual(set(data.keys()), {"id", "name"})

    def test_fields_with_empty_entries(self):
        """Test that empty entries between commas are ignored."""
        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role, context=self._build_context("id,,name,,,description"))
        data = serializer.data

        self.assertEqual(set(data.keys()), {"id", "name", "description"})

    def test_only_permissions_count_field(self):
        """Test requesting only permissions_count field."""
        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role, context=self._build_context("permissions_count"))
        data = serializer.data

        self.assertEqual(set(data.keys()), {"permissions_count"})
        self.assertEqual(data["permissions_count"], 1)

    def test_serializer_without_context_returns_all_fields(self):
        """Test that serializer without context keeps all fields."""
        role = self._get_annotated_role()
        serializer = RoleV2ResponseSerializer(role)
        data = serializer.data

        expected = {"id", "name", "description", "permissions_count", "permissions", "last_modified"}
        self.assertEqual(set(data.keys()), expected)
