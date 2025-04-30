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
"""Service for workspace management."""
from django.core.exceptions import ValidationError
from django.db import transaction
from rest_framework import serializers
from management.models import Workspace
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspacepHandler


class WorkspaceService:
    """Workspace service"""

    def __init__(self, replicator=None):
        self._replicator = replicator

    def create(self, validated_data, tenant) -> Workspace:
        with transaction.atomic():
            try:
                workspace = Workspace.objects.create(**validated_data, tenant=tenant)
                dual_write_handler = RelationApiDualWriteWorkspacepHandler(
                    workspace, ReplicationEventType.CREATE_WORKSPACE
                )
                dual_write_handler.replicate_new_workspace()

                return workspace
            except ValidationError as e:
                if "__all__" in e.message_dict:
                    for msg in e.message_dict["__all__"]:
                        if "unique_workspace_name_per_parent" in msg:
                            raise serializers.ValidationError(
                                "Can't create workspace with same name within same parent workspace"
                            )

    def update(self, instance: Workspace, validated_data: dict) -> Workspace:
        for attr, value in validated_data.items():
            # TODO(RHCLOUD-35415): check attr that parent is not changed here
            setattr(instance, attr, value)
        instance.save()
        dual_write_handler = RelationApiDualWriteWorkspacepHandler(instance, ReplicationEventType.UPDATE_WORKSPACE)
        dual_write_handler.replicate_updated_workspace(instance.parent)
        return instance

    def destroy(self, instance: Workspace) -> None:
        if instance.type != Workspace.Types.STANDARD:
            raise serializers.ValidationError(f"Unable to delete {instance.type} workspace")
        if Workspace.objects.filter(parent=instance, tenant=instance.tenant).exists():
            raise serializers.ValidationError("Unable to delete due to workspace dependencies")

        dual_write_handler = RelationApiDualWriteWorkspacepHandler(
            instance, ReplicationEventType.DELETE_WORKSPACE, replicator=self._replicator
        )
        dual_write_handler.replicate_deleted_workspace()
        instance.delete()
