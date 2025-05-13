#
# Copyright 2024 Red Hat, Inc.
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

"""Class to handle Dual Write API related operations."""
import logging
from typing import Optional

from management.models import Workspace
from management.relation_replicator.relation_replicator import (
    DualWriteException,
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
    WorkspaceEvent,
)
from management.role.relation_api_dual_write_handler import BaseRelationApiDualWriteHandler
from migration_tool.utils import create_relationship


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationApiDualWriteWorkspacepHandler(BaseRelationApiDualWriteHandler):
    """Class to handle Dual Write for group bindings and membership."""

    workspace: Workspace

    def __init__(
        self,
        workspace: Workspace,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
    ):
        """Initialize RelationApiDualWriteGroupHandler."""
        if not self.replication_enabled():
            return

        try:
            self.workspace = workspace
            self.event_type = event_type
            self.relations_to_add = []
            self.relations_to_remove = []
            super().__init__(replicator)
        except Exception as e:
            raise DualWriteException(e)

    def replicate_new_workspace(self):
        """Replicate new principals into group."""
        if not self.replication_enabled():
            return
        self.generate_relations_to_add_workspace()
        self._replicate()

    def replicate_updated_workspace(self, previous_parent):
        """Replicate updated principals into group."""
        if not self.replication_enabled():
            return
        self.generate_relations_to_update_workspace(previous_parent)
        self._replicate()

    def replicate_deleted_workspace(self):
        """Replicate deleted principals into group."""
        if not self.replication_enabled():
            return
        self.generate_relations_to_remove_workspace()
        self._replicate()

    def _replicate(self):
        # To avoid Circular Dependency
        from management.workspace.serializer import WorkspaceEventSerializer

        if not self.replication_enabled():
            return
        try:
            if self.relations_to_remove or self.relations_to_add:
                self._replicator.replicate(
                    ReplicationEvent(
                        event_type=self.event_type,
                        info={"workspace_id": str(self.workspace.id), "org_id": str(self.workspace.tenant.org_id)},
                        partition_key=PartitionKey.byEnvironment(),
                        remove=self.relations_to_remove,
                        add=self.relations_to_add,
                    ),
                )
            self._replicator.replicate_workspace(
                WorkspaceEvent(
                    account_number=self.workspace.tenant.account_id,
                    org_id=str(self.workspace.tenant.org_id),
                    workspace=WorkspaceEventSerializer(self.workspace).data,
                    event_type=self.event_type,
                    partition_key=PartitionKey.byEnvironment(),
                )
            )
        except Exception as e:
            raise DualWriteException(e)

    def _get_workspace_relationship(self, workspace: Workspace, parent: Workspace):
        """Get the relationship for the workspace."""
        return create_relationship(
            ("rbac", "workspace"),
            str(workspace.id),
            ("rbac", "workspace"),
            str(parent.id),
            "parent",
        )

    def generate_relations_to_add_workspace(self):
        """Generate relations to add workspace."""
        if not self.replication_enabled():
            return

        self.relations_to_add.append(self._get_workspace_relationship(self.workspace, self.workspace.parent))

    def generate_relations_to_update_workspace(self, previous_parent):
        """Generate relations to update workspace."""
        if not self.replication_enabled():
            return

        if self.workspace.parent == previous_parent:
            return
        self.relations_to_remove.append(self._get_workspace_relationship(self.workspace, previous_parent))
        self.relations_to_add.append(self._get_workspace_relationship(self.workspace, self.workspace.parent))

    def generate_relations_to_remove_workspace(self):
        """Reset the relationships for the workspace."""
        if not self.replication_enabled():
            return
        # Remove parent relationship
        self.relations_to_remove.append(self._get_workspace_relationship(self.workspace, self.workspace.parent))

    def replicate(self):
        """Replicate generated relations."""
        if not self.replication_enabled():
            return

        self._replicate()
