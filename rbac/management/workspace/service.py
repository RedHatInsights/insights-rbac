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
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from management.models import Workspace
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspaceHandler
from rest_framework import serializers

from api.models import Tenant


class WorkspaceService:
    """Workspace service."""

    def create(self, validated_data: dict, request_tenant: Tenant) -> Workspace:
        """Create workspace."""
        with transaction.atomic():
            try:
                parent_id = validated_data.get("parent_id")
                if parent_id is None:
                    default = Workspace.objects.default(tenant=request_tenant)
                    parent_id = default.id
                parent = Workspace.objects.get(id=parent_id)
                self._enforce_hierarchy_depth(parent_id, request_tenant)
                workspace = Workspace.objects.create(**validated_data, tenant=parent.tenant)
                dual_write_handler = RelationApiDualWriteWorkspaceHandler(
                    workspace, ReplicationEventType.CREATE_WORKSPACE
                )
                dual_write_handler.replicate_new_workspace()

                return workspace
            except ValidationError as e:
                message = e.message_dict
                if hasattr(e, "error_dict") and "__all__" in e.error_dict:
                    for error in e.error_dict["__all__"]:
                        for msg in error.messages:
                            if "unique_workspace_name_per_parent" in msg:
                                message = "Can't create workspace with same name within same parent workspace"
                                break
                raise serializers.ValidationError(message)

    def update(self, instance: Workspace, validated_data: dict) -> Workspace:
        """Update workspace."""
        if instance.type in (Workspace.Types.ROOT, Workspace.Types.UNGROUPED_HOSTS):
            raise serializers.ValidationError(f"The {instance.type} workspace cannot be updated.")
        parent_id = None
        for attr, value in validated_data.items():
            if attr == "parent_id":
                parent_id = value
            if self._parent_id_attr_update(attr, value, instance):
                raise serializers.ValidationError("Can't update the 'parent_id' on a workspace directly")
            setattr(instance, attr, value)
        if parent_id is not None:
            self._enforce_hierarchy_depth(parent_id, instance.tenant)
        try:
            instance.save()
            dual_write_handler = RelationApiDualWriteWorkspaceHandler(instance, ReplicationEventType.UPDATE_WORKSPACE)
            dual_write_handler.replicate_updated_workspace(instance.parent)
        except ValidationError as e:
            message = e.message_dict
            if hasattr(e, "error_dict") and "__all__" in e.error_dict:
                for error in e.error_dict["__all__"]:
                    for msg in error.messages:
                        if "unique_workspace_name_per_parent" in msg:
                            name = validated_data.get("name")
                            message = f"A workspace with the name '{name}' already exists under same parent."
                            break
            raise serializers.ValidationError(message)
        return instance

    def destroy(self, instance: Workspace) -> None:
        """Destroy workspace."""
        if instance.type != Workspace.Types.STANDARD:
            raise serializers.ValidationError(f"Unable to delete {instance.type} workspace")
        if Workspace.objects.filter(parent=instance, tenant=instance.tenant).exists():
            raise serializers.ValidationError("Unable to delete due to workspace dependencies")

        dual_write_handler = RelationApiDualWriteWorkspaceHandler(instance, ReplicationEventType.DELETE_WORKSPACE)
        dual_write_handler.replicate_deleted_workspace()
        instance.delete()

    def _enforce_hierarchy_depth(self, target_parent_id: uuid.UUID, tenant: Tenant) -> None:
        """Enforce hierarchy depth limits on workspaces."""
        if self._exceeds_depth_limit(target_parent_id, tenant):
            message = f"Workspaces may only nest {settings.WORKSPACE_HIERARCHY_DEPTH_LIMIT} levels deep."
            error = {"workspace": [message]}
            raise serializers.ValidationError(error)
        if self._violates_peer_restrictions(target_parent_id, tenant):
            message = "Sub-workspaces may only be created under the default workspace."
            error = {"workspace": [message]}
            raise serializers.ValidationError(error)

    def _parent_id_attr_update(self, attr: str, value: str, instance: Workspace) -> bool:
        """Determine if the attribute being updated is parent_id."""
        return attr == "parent_id" and instance.parent_id != value

    def _violates_peer_restrictions(self, target_parent_id: uuid.UUID, tenant: Tenant) -> bool:
        """Determine if peer restrictions are violated."""
        target_root_workspace = Workspace.objects.root(tenant=tenant)
        if settings.WORKSPACE_RESTRICT_DEFAULT_PEERS and str(target_root_workspace.id) == str(target_parent_id):
            return True
        return False

    def _exceeds_depth_limit(self, target_parent_id: uuid.UUID, tenant: Tenant) -> bool:
        """Determine if depth limit is exceeded."""
        target_parent_workspace = Workspace.objects.get(id=target_parent_id, tenant=tenant)
        max_depth_for_workspace = len(target_parent_workspace.ancestors()) + 1
        return max_depth_for_workspace > settings.WORKSPACE_HIERARCHY_DEPTH_LIMIT
