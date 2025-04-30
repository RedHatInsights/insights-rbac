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

from management.workspace.service import WorkspaceService

from .model import Workspace


class WorkspaceSerializer(serializers.ModelSerializer):
    """Serializer for the Workspace model."""

    id = serializers.UUIDField(read_only=True, required=False)
    name = serializers.CharField(required=True, max_length=255)
    description = serializers.CharField(allow_null=True, required=False, max_length=255)
    parent_id = serializers.UUIDField(required=False)
    created = serializers.DateTimeField(read_only=True)
    modified = serializers.DateTimeField(read_only=True)
    type = serializers.CharField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Workspace
        fields = (
            "name",
            "id",
            "parent_id",
            "description",
            "created",
            "modified",
            "type",
        )

    @property
    def _service(self) -> WorkspaceService:
        return self.context["view"]._service

    def create(self, validated_data):
        """Create the workspace object in the database."""
        tenant = self.context["request"].tenant
        return self._service.create(validated_data, tenant)

    def validate(self, attrs):
        from django.core.exceptions import ValidationError

        """Validate on POST, PUT and PATCH."""
        request = self.context.get("request")
        type = request.data.get("type", Workspace.Types.STANDARD)
        parent_id = attrs.get("parent_id")
        tenant = request.tenant

        if type != Workspace.Types.STANDARD:
            raise ValidationError({"type": [f"Only workspace type '{Workspace.Types.STANDARD}' is allowed."]})

        if parent_id and tenant:
            if not Workspace.objects.filter(id=parent_id, tenant=tenant).exists():
                raise ValidationError({"parent_id": (f"Parent workspace '{parent_id}' does not exist in tenant.")})

        return attrs

    def update(self, instance, validated_data):
        """Update the workspace object in the database."""
        return self._service.update(instance, validated_data)


class WorkspaceAncestrySerializer(serializers.ModelSerializer):
    """Serializer for the Workspace ancestry."""

    id = serializers.UUIDField(read_only=True, required=False)
    name = serializers.CharField(required=False, max_length=255)
    parent_id = serializers.UUIDField(allow_null=True, required=False)

    class Meta:
        """Metadata for the serializer."""

        model = Workspace
        fields = ("name", "id", "parent_id")


class WorkspaceWithAncestrySerializer(WorkspaceSerializer):
    """Serializer for the Workspace model with ancestry."""

    ancestry = serializers.SerializerMethodField()

    class Meta:
        """Metadata for the serializer."""

        model = Workspace
        fields = WorkspaceSerializer.Meta.fields + ("ancestry",)

    def get_ancestry(self, obj):
        """Serialize the workspace's ancestors."""
        ancestors = obj.ancestors().only("name", "id", "parent_id")
        return WorkspaceAncestrySerializer(ancestors, many=True).data


class WorkspaceEventSerializer(serializers.ModelSerializer):
    """Serializer for the Workspace model for sending event."""

    id = serializers.UUIDField()
    name = serializers.CharField()
    type = serializers.CharField()
    created = serializers.DateTimeField()
    modified = serializers.DateTimeField()

    class Meta:
        """Metadata for the serializer."""

        model = Workspace
        fields = (
            "name",
            "id",
            "created",
            "modified",
            "type",
        )
        read_only_fields = (
            "name",
            "id",
            "created",
            "modified",
            "type",
        )
