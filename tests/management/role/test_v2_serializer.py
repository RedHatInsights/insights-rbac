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

from unittest.mock import Mock

from django.db.models import Count

from management.models import (
    RoleV2,
    Permission,
)
from management.role.v2_serializer import RoleSerializer
from tests.identity_request import IdentityRequest


class RoleSerializerTests(IdentityRequest):
    """Test the RoleSerializer for role serialization."""

    def setUp(self):
        """Set up the RoleSerializer tests."""
        super().setUp()
        self.permission = Permission.objects.create(permission="inventory:hosts:read", tenant=self.tenant)
        self.role = RoleV2.objects.create(
            name="test_role",
            description="Test role description",
            tenant=self.tenant,
        )
        self.role.permissions.add(self.permission)

    def tearDown(self):
        """Tear down the RoleSerializer tests."""
        super().tearDown()
        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

    def _get_annotated_role(self):
        """Get the role with the permissions_count annotation."""
        return RoleV2.objects.annotate(permissions_count_annotation=Count("permissions", distinct=True)).get(
            pk=self.role.pk
        )

    def _mock_request(self, fields=None):
        """Create a mock request with query_params."""
        request = Mock()
        request.query_params = {"fields": fields} if fields else {}
        return request

    def test_default_fields_when_no_field_selection(self):
        """Test that default fields are returned when no fields param is provided."""
        role = self._get_annotated_role()
        serializer = RoleSerializer(role, context={"request": self._mock_request()})
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
        serializer = RoleSerializer(role, context={"request": self._mock_request("id,name,permissions_count")})
        data = serializer.data

        self.assertEqual(set(data.keys()), {"id", "name", "permissions_count"})
        self.assertEqual(data["name"], "test_role")
        self.assertEqual(data["permissions_count"], 1)

    def test_permissions_field_returns_permission_objects(self):
        """Test that permissions field returns properly formatted permission objects."""
        role = self._get_annotated_role()
        serializer = RoleSerializer(role, context={"request": self._mock_request("id,permissions")})
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
        serializer = RoleSerializer(
            role,
            context={"request": self._mock_request("id,name,description,permissions_count,last_modified,permissions")},
        )
        data = serializer.data

        expected = {"id", "name", "description", "permissions_count", "last_modified", "permissions"}
        self.assertEqual(set(data.keys()), expected)

    def test_invalid_fields_are_ignored(self):
        """Test that invalid field names are silently ignored."""
        role = self._get_annotated_role()
        serializer = RoleSerializer(role, context={"request": self._mock_request("id,invalid_field,name")})
        data = serializer.data

        # Only valid fields are returned
        self.assertEqual(set(data.keys()), {"id", "name"})
