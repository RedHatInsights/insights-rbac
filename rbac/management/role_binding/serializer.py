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
"""Serializers for role binding management."""
import re

from rest_framework import serializers


class UserDetailsSerializer(serializers.Serializer):
    """Serializer for user details."""

    username = serializers.CharField(read_only=True)


class GroupDetailsSerializer(serializers.Serializer):
    """Serializer for group details."""

    name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True, allow_null=True)
    user_count = serializers.IntegerField(read_only=True, source="principalCount")


class SubjectSerializer(serializers.Serializer):
    """Polymorphic serializer for subject (user or group)."""

    id = serializers.UUIDField(read_only=True)
    type = serializers.CharField(read_only=True)
    user = UserDetailsSerializer(required=False, allow_null=True)
    group = GroupDetailsSerializer(required=False, allow_null=True)


class RoleSerializer(serializers.Serializer):
    """Serializer for role information."""

    id = serializers.UUIDField(read_only=True, source="uuid")
    name = serializers.CharField(read_only=True)


class ResourceSerializer(serializers.Serializer):
    """Serializer for resource information."""

    id = serializers.UUIDField(read_only=True)
    name = serializers.CharField(read_only=True, required=False)
    type = serializers.CharField(read_only=True, required=False)


class DynamicFieldsSerializer(serializers.Serializer):
    """Base serializer with dynamic field filtering support.

    Supports filtering fields via __init__ parameter following DRF patterns.
    Extends the pattern used in management.role.serializer.DynamicFieldsModelSerializer
    to work with regular Serializers and support nested field specifications.
    """

    def __init__(self, *args, **kwargs):
        """Initialize serializer with optional field filtering."""
        # Extract fields parameter before calling super().__init__
        fields = kwargs.pop("fields", None)
        super().__init__(*args, **kwargs)

        if fields is not None:
            # Parse field specifications
            field_specs = self._parse_field_specs(fields)

            # Remove fields not in the spec
            allowed_fields = set(field_specs.keys())
            existing_fields = set(self.fields.keys())

            for field_name in existing_fields - allowed_fields:
                self.fields.pop(field_name)

            # Apply nested field filtering to remaining fields
            for field_name, nested_spec in field_specs.items():
                if field_name in self.fields and nested_spec:
                    # Pass nested spec to child serializer if it supports it
                    field = self.fields[field_name]
                    if hasattr(field, "child"):
                        # For list fields (many=True)
                        self._apply_nested_filter(field.child, nested_spec)
                    else:
                        # For regular nested serializers
                        self._apply_nested_filter(field, nested_spec)

    def _parse_field_specs(self, fields_str):
        """Parse field specification string into dictionary.

        Supports:
        - Simple: "field1,field2"
        - Nested: "field1(subfield1,subfield2),field2"

        Returns:
            dict: {field_name: [nested_fields] or None}
        """
        if isinstance(fields_str, (list, tuple)):
            # Already parsed as list
            return {field: None for field in fields_str}

        # Parse string with regex for better handling
        result = {}
        # Match: field_name or field_name(nested)
        pattern = r"(\w+)(?:\(([^)]+)\))?"

        for match in re.finditer(pattern, fields_str):
            field_name = match.group(1)
            nested = match.group(2)

            if nested:
                # Split nested fields by comma
                result[field_name] = [f.strip() for f in nested.split(",")]
            else:
                result[field_name] = None

        return result

    def _apply_nested_filter(self, serializer, nested_fields):
        """Apply field filtering to nested serializer.

        Args:
            serializer: Nested serializer instance
            nested_fields: List of field names to include
        """
        if not hasattr(serializer, "fields"):
            return

        # Group fields by their first segment (e.g., "group.name" -> "group": ["name"])
        grouped = {}
        simple_fields = []

        for field_spec in nested_fields:
            if "." in field_spec:
                # Nested field like "group.name"
                parent, child = field_spec.split(".", 1)
                if parent not in grouped:
                    grouped[parent] = []
                grouped[parent].append(child)
            else:
                # Simple field
                simple_fields.append(field_spec)

        # Determine which fields to keep
        allowed = set(simple_fields) | set(grouped.keys())
        existing = set(serializer.fields.keys())

        # Remove fields not in spec
        for field_name in existing - allowed:
            serializer.fields.pop(field_name)

        # Recursively apply to nested serializers
        for field_name, sub_specs in grouped.items():
            if field_name in serializer.fields:
                field = serializer.fields[field_name]
                if hasattr(field, "child"):
                    self._apply_nested_filter(field.child, sub_specs)
                else:
                    self._apply_nested_filter(field, sub_specs)


class RoleBindingBySubjectSerializer(DynamicFieldsSerializer):
    """Serializer for role bindings grouped by subject.

    This serializer works with Group objects that have been annotated with
    role binding information via the _build_group_queryset method.
    """

    last_modified = serializers.DateTimeField(read_only=True, source="latest_modified")
    subject = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def get_subject(self, group):
        """Extract subject information from the Group object."""
        return {
            "id": group.uuid,
            "type": "group",
            "group": {
                "name": group.name,
                "description": group.description,
                "user_count": group.principalCount,
            },
        }

    def get_roles(self, group):
        """Extract roles from the prefetched role bindings."""
        roles = []
        seen_role_ids = set()

        # Access the prefetched filtered_bindings
        if hasattr(group, "filtered_bindings"):
            for binding_group in group.filtered_bindings:
                role = binding_group.binding.role
                if role and role.uuid not in seen_role_ids:
                    roles.append({"uuid": role.uuid, "name": role.name})
                    seen_role_ids.add(role.uuid)

        return roles

    def get_resource(self, group):
        """Extract resource information from the request context."""
        request = self.context.get("request")
        if request:
            return {
                "id": request.resource_id,
                "name": request.resource_name,
                "type": request.resource_type,
            }
        return None
