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

from management.models import Group
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

    This serializer works with both Group and Principal objects that have been
    annotated with role binding information via the _build_group_queryset or
    _build_principal_queryset methods.
    """

    last_modified = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        """Initialize and store field specs for manual filtering."""
        # Store fields before parent pops it, so we can use it in get_* methods
        fields = kwargs.get("fields")
        self._field_specs = self._parse_field_specs(fields) if fields else {}
        super().__init__(*args, **kwargs)

    def _filter_dict(self, data, field_specs):
        """Filter a dictionary based on field specifications.

        Args:
            data: Dictionary to filter
            field_specs: List of field specifications (e.g., ["name", "group.name"])

        Returns:
            Filtered dictionary
        """
        if not field_specs:
            return data

        result = {}
        for spec in field_specs:
            if "." in spec:
                # Nested field like "group.name"
                parent, child = spec.split(".", 1)
                if parent not in result:
                    result[parent] = {}
                if parent in data and isinstance(data[parent], dict):
                    # Get the child value
                    if child in data[parent]:
                        result[parent][child] = data[parent][child]
            else:
                # Simple field
                if spec in data:
                    result[spec] = data[spec]

        return result

    def get_last_modified(self, obj):
        """Extract last modified timestamp."""
        # If obj is a dict (for testing), return modified or latest_modified
        if isinstance(obj, dict):
            return obj.get("modified") or obj.get("latest_modified")
        return getattr(obj, "latest_modified", None)

    def get_subject(self, obj):
        """Extract subject information from the Group or Principal object."""
        # Build the subject data
        if isinstance(obj, dict):
            subject_data = obj.get("subject", {})
        elif isinstance(obj, Group):
            subject_data = {
                "id": obj.uuid,
                "type": "group",
                "group": {
                    "name": obj.name,
                    "description": obj.description,
                    "user_count": obj.principalCount,
                },
            }
        else:
            # This is a Principal (user)
            subject_data = {
                "id": obj.uuid,
                "type": "user",
                "user": {
                    "username": obj.username,
                },
            }

        # Apply field filtering if specified
        if self._field_specs.get("subject"):
            subject_data = self._filter_dict(subject_data, self._field_specs["subject"])

        return subject_data

    def get_roles(self, obj):
        """Extract roles from the prefetched role bindings."""
        # Build the roles list
        if isinstance(obj, dict):
            roles = obj.get("roles", [])
        else:
            roles = []
            seen_role_ids = set()

            # Check if this is a Group or Principal
            if isinstance(obj, Group):
                # Access the prefetched filtered_bindings for groups
                if hasattr(obj, "filtered_bindings"):
                    for binding_group in obj.filtered_bindings:
                        role = binding_group.binding.role
                        if role and role.uuid not in seen_role_ids:
                            roles.append({"id": role.uuid, "name": role.name})
                            seen_role_ids.add(role.uuid)
            else:
                # For principals, get roles from their filtered_groups
                if hasattr(obj, "filtered_groups"):
                    for group in obj.filtered_groups:
                        if hasattr(group, "filtered_bindings"):
                            for binding_group in group.filtered_bindings:
                                role = binding_group.binding.role
                                if role and role.uuid not in seen_role_ids:
                                    roles.append({"id": role.uuid, "name": role.name})
                                    seen_role_ids.add(role.uuid)

        # Apply field filtering if specified (filter each role dict)
        if self._field_specs.get("roles"):
            roles = [self._filter_dict(role, self._field_specs["roles"]) for role in roles]

        return roles

    def get_resource(self, obj):
        """Extract resource information from the request context."""
        # Build the resource data
        if isinstance(obj, dict):
            resource_data = obj.get("resource", {})
        else:
            request = self.context.get("request")
            if request:
                resource_data = {
                    "id": request.resource_id,
                    "name": request.resource_name,
                    "type": request.resource_type,
                }
            else:
                resource_data = None

        # Apply field filtering if specified
        if resource_data and self._field_specs.get("resource"):
            resource_data = self._filter_dict(resource_data, self._field_specs["resource"])

        return resource_data
