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
from typing import Callable, Iterable, Optional
from uuid import uuid4

from django.conf import settings
from management.group.relation_api_dual_write_subject_handler import RelationApiDualWriteSubjectHandler
from management.models import Workspace
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    DualWriteException,
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.model import BindingMapping, Role
from migration_tool.models import V2boundresource, V2role, V2rolebinding

from api.models import CrossAccountRequest

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationApiDualWriteCrossAccessHandler(RelationApiDualWriteSubjectHandler):
    """Class to handle Dual Write for cross account access bindings."""

    def __init__(
        self,
        cross_account_request: CrossAccountRequest,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
    ):
        """Initialize RelationApiDualWriteCrossAccessHandler."""
        if not self.replication_enabled():
            return

        try:
            self.cross_account_request = cross_account_request
            default_workspace = Workspace.objects.get(
                tenant__org_id=self.cross_account_request.target_org, type=Workspace.Types.DEFAULT
            )
            super().__init__(default_workspace, event_type, replicator)
        except Exception as e:
            raise DualWriteException(e)

    def _replicate(self):
        if not self.replication_enabled():
            return
        try:
            self._replicator.replicate(
                ReplicationEvent(
                    event_type=self.event_type,
                    info={
                        "user_id": str(self.cross_account_request.user_id),
                        "roles": [role.uuid for role in self.cross_account_request.roles.all()],
                        "target_org": self.cross_account_request.target_org,
                    },
                    partition_key=PartitionKey.byEnvironment(),
                    remove=self.relations_to_remove,
                    add=self.relations_to_add,
                ),
            )
        except Exception as e:
            raise DualWriteException(e)

    def _create_default_mapping_for_system_role(self, system_role: Role):
        """Create default mapping."""
        return super()._create_default_mapping_for_system_role(
            system_role, users=frozenset([str(self.cross_account_request.user_id)])
        )

    def generate_relations_to_add_roles(self, roles: Iterable[Role]):
        """Generate relations to add roles."""
        if not self.replication_enabled():
            return

        def add_principal_to_binding(mapping: BindingMapping):
            self.relations_to_add.append(mapping.add_user_to_bindings(str(self.cross_account_request.user_id)))

        for role in roles:
            self._update_mapping_for_system_role(
                role,
                update_mapping=add_principal_to_binding,
                create_default_mapping_for_system_role=lambda: self._create_default_mapping_for_system_role(role),
            )

    def replicate(self):
        """Replicate added role."""
        if not self.replication_enabled():
            return

        self._replicate()

    def generate_relations_to_remove_roles(self, roles: Iterable[Role]):
        """Replicate removed role."""
        if not self.replication_enabled():
            return

        def remove_principal_from_binding(mapping: BindingMapping):
            self.relations_to_remove.append(mapping.remove_user_from_bindings(str(self.cross_account_request.user_id)))

        for role in roles:
            self._update_mapping_for_system_role(
                role, update_mapping=remove_principal_from_binding, create_default_mapping_for_system_role=None
            )
