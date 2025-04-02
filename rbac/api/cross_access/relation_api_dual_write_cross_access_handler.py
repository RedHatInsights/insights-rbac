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
from typing import Iterable, Optional

from management.group.relation_api_dual_write_subject_handler import RelationApiDualWriteSubjectHandler
from management.models import Workspace
from management.relation_replicator.relation_replicator import (
    DualWriteException,
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.model import BindingMapping, Role, SourceKey

from api.models import CrossAccountRequest, Tenant

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
            tenant = Tenant.objects.get(org_id=self.cross_account_request.target_org)
            default_workspace = Workspace.objects.default(tenant=tenant)
            super().__init__(default_workspace, event_type, replicator)
        except Exception as e:
            logger.error("Error occurred intializing RelationApiDualWriteCrossAccessHandler", e)
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
            logger.error("Error occurred in cross account replicate event", e)
            raise DualWriteException(e)

    def generate_relations_to_add_roles(self, roles: Iterable[Role]):
        """Generate relations to add roles."""
        if not self.replication_enabled():
            return
        source_key = SourceKey(self.cross_account_request, self.cross_account_request.source_pk())
        user_id = str(self.cross_account_request.user_id)

        def add_principal_to_binding(mapping: BindingMapping):
            self.relations_to_add.append(mapping.assign_user_to_bindings(user_id, source_key))

        for role in roles:
            self._update_mapping_for_system_role(
                role,
                update_mapping=add_principal_to_binding,
                create_default_mapping_for_system_role=lambda: self._create_default_mapping_for_system_role(
                    role, users={str(source_key): user_id}
                ),
            )

    def generate_relations_reset_roles(self, roles: Iterable[Role]):
        """Generate relations to add roles."""
        if not self.replication_enabled():
            return
        source_key = SourceKey(self.cross_account_request, self.cross_account_request.source_pk())
        user_id = str(self.cross_account_request.user_id)

        def add_principal_to_binding(mapping: BindingMapping):
            mapping.update_data_format_for_user(self.relations_to_remove)
            self.relations_to_add.append(mapping.assign_user_to_bindings(user_id, source_key))

        for role in roles:
            self._update_mapping_for_system_role(
                role,
                update_mapping=add_principal_to_binding,
                create_default_mapping_for_system_role=lambda: self._create_default_mapping_for_system_role(
                    role, users={str(source_key): user_id}
                ),
            )

    def replicate(self):
        """Replicate generated relations."""
        if not self.replication_enabled():
            return

        self._replicate()

    def generate_relations_to_remove_roles(self, roles: Iterable[Role]):
        """Generate relations to remove roles."""
        if not self.replication_enabled():
            return
        source_key = SourceKey(self.cross_account_request, self.cross_account_request.source_pk())
        user_id = str(self.cross_account_request.user_id)

        def remove_principal_from_binding(mapping: BindingMapping):
            removal = mapping.unassign_user_from_bindings(user_id, source=source_key)
            if removal is not None:
                self.relations_to_remove.append(removal)

        for role in roles:
            self._update_mapping_for_system_role(
                role, update_mapping=remove_principal_from_binding, create_default_mapping_for_system_role=None
            )
