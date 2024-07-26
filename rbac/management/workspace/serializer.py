#
# Copyright 2019 Red Hat, Inc.
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

"""Serializer for workspace management."""
from rest_framework import serializers

from .model import Workspace


class WorkspaceSerializer(serializers.ModelSerializer):
    """Serializer for the Workspace model."""

    name = serializers.CharField(required=False, max_length=255)
    uuid = serializers.UUIDField(read_only=True, required=False)
    parent = serializers.UUIDField(allow_null=True, required=False)

    class Meta:
        """Metadata for the serializer."""

        model = Workspace
        fields = ("name", "uuid", "parent", "description")

    def create(self, validated_data):
        """Create the workspace object in the database."""
        name = validated_data.pop("name")
        description = validated_data.pop("description", "")
        tenant = self.context["request"].tenant
        parent = validated_data.pop("parent", "")

        workspace = Workspace.objects.create(name=name, description=description, parent=parent, tenant=tenant)
        return workspace
