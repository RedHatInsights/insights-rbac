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
from management.models import Group
from rest_framework import serializers


class RoleBindingByGroupSerializer(serializers.Serializer):
    """Serializer for role bindings by group.

    This serializer formats Group objects that have been annotated with
    role binding information via the service layer.

    Supports dynamic field selection through the 'field_selection' context parameter.
    Fields are accessed directly on the model using dot notation from the query parameter.

    Field selection syntax:
    - subject(group.name, group.description) - accesses obj.name, obj.description
    - role(name, description) - accesses role.name, role.description
    - resource(name, type) - accesses resource name and type from context
    - last_modified - include root-level field
    """

    last_modified = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def _get_field_selection(self):
        """Get field selection from context."""
        return self.context.get("field_selection")

    def to_representation(self, instance):
        """Override to support field selection."""
        ret = super().to_representation(instance)

        field_selection = self._get_field_selection()
        if field_selection is None:
            # No filter - include all fields (last_modified is already in ret)
            return ret

        # Apply field selection - always include core objects, filter root fields
        filtered = {
            "subject": ret.get("subject"),
            "roles": ret.get("roles"),
            "resource": ret.get("resource"),
        }

        # Include last_modified only if explicitly requested when filtering
        if "last_modified" in field_selection.root_fields:
            filtered["last_modified"] = ret.get("last_modified")

        return filtered

    def get_last_modified(self, obj):
        """Extract last modified timestamp."""
        if isinstance(obj, dict):
            return obj.get("modified") or obj.get("latest_modified")
        return getattr(obj, "latest_modified", None)

    def get_subject(self, obj):
        """Extract subject information from the Group.

        Always includes id and type (required fields).
        Group details are dynamically extracted based on field selection.
        If no field selection specified, includes all group fields.
        """
        if not isinstance(obj, Group):
            return None

        field_selection = self._get_field_selection()

        # Base subject data (always included)
        subject = {
            "id": obj.uuid,
            "type": "group",
        }

        # Determine which fields to include
        if field_selection is None or not field_selection.subject_fields:
            subject["group"] = {
                "name": obj.name,
                "description": obj.description,
                "user_count": getattr(obj, "principalCount", 0),
            }
        else:
            # Extract field names from "group.X" paths
            fields_to_include = set()
            for field_path in field_selection.subject_fields:
                if field_path.startswith("group."):
                    fields_to_include.add(field_path[6:])  # Remove "group." prefix
                else:
                    fields_to_include.add(field_path)

            # Dynamically extract requested fields from the object
            group_details = {}
            for field_name in fields_to_include:
                # Handle special case for user_count -> principalCount
                if field_name == "user_count":
                    group_details[field_name] = getattr(obj, "principalCount", 0)
                else:
                    value = getattr(obj, field_name, None)
                    if value is not None:
                        group_details[field_name] = value

            if group_details:
                subject["group"] = group_details

        return subject

    def get_roles(self, obj):
        """Extract roles from the prefetched role bindings.

        Always includes role id (required field).
        Other role fields are dynamically extracted based on field selection.
        If no field selection specified, includes all role fields.
        """
        if isinstance(obj, dict):
            return obj.get("roles", [])

        if not isinstance(obj, Group) or not hasattr(obj, "filtered_bindings"):
            return []

        field_selection = self._get_field_selection()
        include_all = field_selection is None or not field_selection.role_fields

        roles = []
        seen_role_ids = set()

        for binding_group in obj.filtered_bindings:
            if not hasattr(binding_group, "binding") or not binding_group.binding:
                continue

            role = binding_group.binding.role
            if not role or role.uuid in seen_role_ids:
                continue

            if include_all:
                # No filter - include default role fields per OpenAPI spec
                role_data = {
                    "id": role.uuid,
                    "name": role.name,
                }
            else:
                # Always include id
                role_data = {"id": role.uuid}

                # Dynamically extract requested fields from the role
                for field_name in field_selection.role_fields:
                    value = getattr(role, field_name, None)
                    if value is not None:
                        role_data[field_name] = value

            roles.append(role_data)
            seen_role_ids.add(role.uuid)

        return roles

    def get_resource(self, obj):
        """Extract resource information from the request context.

        Always includes resource id (required field).
        Other resource fields are dynamically extracted based on field selection.
        If no field selection specified, includes all resource fields.
        Returns None if context has no resource information.
        """
        if isinstance(obj, dict):
            return obj.get("resource", {})

        # Check if context has any resource information
        resource_id = self.context.get("resource_id")
        resource_name = self.context.get("resource_name")
        resource_type = self.context.get("resource_type")

        if not any([resource_id, resource_name, resource_type]):
            return None

        field_selection = self._get_field_selection()
        include_all = field_selection is None or not field_selection.resource_fields

        if include_all:
            # No filter - include all resource fields
            return {
                "id": resource_id,
                "name": resource_name,
                "type": resource_type,
            }

        # Always include id
        resource_data = {"id": resource_id}

        # Map field names to values
        field_values = {
            "name": resource_name,
            "type": resource_type,
        }

        # Dynamically extract requested fields
        for field_name in field_selection.resource_fields:
            value = field_values.get(field_name)
            if value is not None:
                resource_data[field_name] = value

        return resource_data
