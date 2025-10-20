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
"""Tests for role binding serializers."""
from datetime import datetime
from django.test import TestCase
from management.role_binding.serializer import (
    DynamicFieldsSerializer,
    RoleBindingBySubjectSerializer,
)


class DynamicFieldsSerializerTest(TestCase):
    """Test the DynamicFieldsSerializer field filtering."""

    def setUp(self):
        """Set up test data."""
        self.sample_data = {
            "modified": datetime(2025, 1, 15, 10, 30, 0),
            "subject": {
                "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                "type": "group",
                "group": {
                    "name": "Engineering Team",
                    "description": "Engineering department group",
                    "principalCount": 25,
                },
            },
            "roles": [
                {"uuid": "550e8400-e29b-41d4-a716-446655440001", "name": "Workspace Admin"},
                {"uuid": "550e8400-e29b-41d4-a716-446655440002", "name": "Workspace Editor"},
            ],
            "resource": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Production Workspace",
                "type": "workspace",
            },
        }

    def test_parse_field_specs_simple(self):
        """Test parsing simple field list."""
        serializer = RoleBindingBySubjectSerializer()
        result = serializer._parse_field_specs("subject,roles")
        self.assertEqual(result, {"subject": None, "roles": None})

    def test_parse_field_specs_nested(self):
        """Test parsing nested fields."""
        serializer = RoleBindingBySubjectSerializer()
        result = serializer._parse_field_specs("subject(id,type,group)")
        self.assertEqual(result, {"subject": ["id", "type", "group"]})

    def test_parse_field_specs_mixed(self):
        """Test parsing mixed simple and nested fields."""
        serializer = RoleBindingBySubjectSerializer()
        result = serializer._parse_field_specs("subject(id,group),roles,resource(name)")
        self.assertEqual(result, {"subject": ["id", "group"], "roles": None, "resource": ["name"]})

    def test_parse_field_specs_with_list(self):
        """Test parsing when fields is already a list."""
        serializer = RoleBindingBySubjectSerializer()
        result = serializer._parse_field_specs(["subject", "roles"])
        self.assertEqual(result, {"subject": None, "roles": None})

    def test_no_fields_filter(self):
        """Test serialization without field filtering."""
        serializer = RoleBindingBySubjectSerializer(instance=self.sample_data)
        data = serializer.data

        self.assertIn("last_modified", data)
        self.assertIn("subject", data)
        self.assertIn("roles", data)
        self.assertIn("resource", data)

    def test_simple_field_filter(self):
        """Test filtering with simple field list."""
        serializer = RoleBindingBySubjectSerializer(instance=self.sample_data, fields="subject,roles")
        data = serializer.data

        self.assertIn("subject", data)
        self.assertIn("roles", data)
        self.assertNotIn("resource", data)
        self.assertNotIn("last_modified", data)

    def test_nested_field_filter(self):
        """Test filtering with nested fields."""
        serializer = RoleBindingBySubjectSerializer(instance=self.sample_data, fields="subject(id,type,group)")
        data = serializer.data

        self.assertIn("subject", data)
        self.assertIn("id", data["subject"])
        self.assertIn("type", data["subject"])
        self.assertIn("group", data["subject"])
        # Should not have user field since it wasn't specified
        self.assertNotIn("user", data["subject"])

    def test_deeply_nested_field_filter(self):
        """Test filtering deeply nested fields."""
        serializer = RoleBindingBySubjectSerializer(instance=self.sample_data, fields="subject(group.name)")
        data = serializer.data

        self.assertIn("subject", data)
        self.assertIn("group", data["subject"])
        self.assertIn("name", data["subject"]["group"])
        # Other group fields should be filtered out
        self.assertNotIn("description", data["subject"]["group"])
        self.assertNotIn("user_count", data["subject"]["group"])

    def test_array_field_filter(self):
        """Test filtering fields in array (many=True)."""
        serializer = RoleBindingBySubjectSerializer(instance=self.sample_data, fields="roles(name)")
        data = serializer.data

        self.assertIn("roles", data)
        self.assertEqual(len(data["roles"]), 2)
        self.assertIn("name", data["roles"][0])
        # UUID should be filtered out
        self.assertNotIn("id", data["roles"][0])

    def test_mixed_field_filter(self):
        """Test filtering with mixed simple and nested fields."""
        serializer = RoleBindingBySubjectSerializer(
            instance=self.sample_data, fields="subject(id,group.name),roles(name),resource"
        )
        data = serializer.data

        # Check subject
        self.assertIn("subject", data)
        self.assertIn("id", data["subject"])
        self.assertIn("group", data["subject"])
        self.assertIn("name", data["subject"]["group"])

        # Check roles
        self.assertIn("roles", data)
        self.assertIn("name", data["roles"][0])

        # Check resource (all fields)
        self.assertIn("resource", data)

    def test_many_true_with_filtering(self):
        """Test field filtering with many=True."""
        data_list = [self.sample_data, self.sample_data.copy()]
        serializer = RoleBindingBySubjectSerializer(instance=data_list, many=True, fields="subject,roles")
        data = serializer.data

        self.assertEqual(len(data), 2)
        for item in data:
            self.assertIn("subject", item)
            self.assertIn("roles", item)
            self.assertNotIn("resource", item)
