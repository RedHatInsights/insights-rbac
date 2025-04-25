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
from django.db import transaction
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspacepHandler
from rest_framework import serializers

from .model import Workspace


class WorkspaceSerializer(serializers.ModelSerializer):
    """Serializer for the Workspace model."""

    id = serializers.UUIDField(read_only=True, required=False)
    name = serializers.CharField(required=True, max_length=255)
    description = serializers.CharField(allow_null=True, required=False, max_length=255)
    parent_id = serializers.UUIDField(required=True)
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

    def create(self, validated_data):
        """Create the workspace object in the database."""
        validated_data["tenant"] = self.context["request"].tenant

        with transaction.atomic():
            workspace = Workspace.objects.create(**validated_data)
            dual_write_handler = RelationApiDualWriteWorkspacepHandler(
                workspace, ReplicationEventType.CREATE_WORKSPACE
            )
            dual_write_handler.replicate_new_workspace()
        return workspace

    def validate(self, attrs):
        """Validate on POST, PUT and PATCH."""
        pass
        # request = self.context.get("request")
        # type = request.data.get("type", Workspace.Types.STANDARD)

        # WorkspaceValidationService.validate_type(type)
        # WorkspaceValidationService.validate_parent_id(tenant=request.tenant, parent_id=attrs.get("parent_id"))

        # return attrs

    def update(self, instance, validated_data):
        """Update the workspace object in the database."""
        with transaction.atomic():
            # Lock the data
            instance = Workspace.objects.select_for_update().filter(id=instance.id).get()
            previous_parent = instance.parent
            instance = super().update(instance, validated_data)
            dual_write_handler = RelationApiDualWriteWorkspacepHandler(instance, ReplicationEventType.UPDATE_WORKSPACE)
            dual_write_handler.replicate_updated_workspace(previous_parent)
        return instance


class WorkspacePatchSerializer(WorkspaceSerializer):
    """Serializer for patching the Workspace model."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in ["name", "parent_id"]:
            self.fields[field].required = False


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
