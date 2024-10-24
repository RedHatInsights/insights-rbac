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
    description = serializers.CharField(allow_null=True, required=False, max_length=255)
    parent_uuid = serializers.UUIDField(allow_null=True, required=False)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)
    type = serializers.CharField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Workspace
        fields = (
            "name",
            "uuid",
            "parent_uuid",
            "description",
            "created",
            "modified",
            "type",
        )

    def create(self, validated_data):
        """Create the workspace object in the database."""
        validated_data["tenant"] = self.context["request"].tenant

        workspace = Workspace.objects.create(**validated_data)
        return workspace


class WorkspaceAncestrySerializer(serializers.ModelSerializer):
    """Serializer for the Workspace ancestry."""

    name = serializers.CharField(required=False, max_length=255)
    uuid = serializers.UUIDField(read_only=True, required=False)
    parent_uuid = serializers.UUIDField(allow_null=True, required=False)

    class Meta:
        """Metadata for the serializer."""

        model = Workspace
        fields = ("name", "uuid", "parent_uuid")


class WorkspaceWithAncestrySerializer(WorkspaceSerializer):
    """Serializer for the Workspace model with ancestry."""

    ancestry = serializers.SerializerMethodField()

    class Meta:
        """Metadata for the serializer."""

        model = Workspace
        fields = WorkspaceSerializer.Meta.fields + ("ancestry",)

    def get_ancestry(self, obj):
        """Serialize the workspace's ancestors."""
        ancestors = obj.ancestors().only("name", "uuid", "parent_id")
        return WorkspaceAncestrySerializer(ancestors, many=True).data
