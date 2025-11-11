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
    role binding information via the _build_group_queryset method.
    """

    last_modified = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def get_last_modified(self, obj):
        """Extract last modified timestamp."""
        # If obj is a dict (for testing), return modified or latest_modified
        if isinstance(obj, dict):
            return obj.get("modified") or obj.get("latest_modified")
        return getattr(obj, "latest_modified", None)

    def get_subject(self, obj):
        """Extract subject information from the Group."""
        if isinstance(obj, Group):
            return {
                "id": obj.uuid,
                "type": "group",
                "group": {
                    "name": obj.name,
                    "description": obj.description,
                    "user_count": obj.principalCount,
                },
            }
        return None

    def get_roles(self, obj):
        """Extract roles from the prefetched role bindings."""
        # Build the roles list
        if isinstance(obj, dict):
            roles = obj.get("roles", [])
        else:
            roles = []
            seen_role_ids = set()

            # Check if this is a Group object
            if isinstance(obj, Group):
                # Access the prefetched filtered_bindings for groups
                if hasattr(obj, "filtered_bindings"):
                    for binding_group in obj.filtered_bindings:
                        if hasattr(binding_group, "binding") and binding_group.binding:
                            role = binding_group.binding.role
                            if role and role.uuid not in seen_role_ids:
                                roles.append({"id": role.uuid, "name": role.name})
                                seen_role_ids.add(role.uuid)
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
                    "id": getattr(request, "resource_id", None),
                    "name": getattr(request, "resource_name", None),
                    "type": getattr(request, "resource_type", None),
                }
            else:
                resource_data = None

        return resource_data
