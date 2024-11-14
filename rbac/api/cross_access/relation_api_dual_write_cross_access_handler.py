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
from management.models import Principal, Workspace
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


class RelationApiDualWriteCrossAccessHandler:
    """Class to handle Dual Write API related operations."""

    def __init__(
        self,
        cross_account_request: CrossAccountRequest,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
    ):
        """Initialize RelationApiDualWriteGroupHandler."""
        if not self.replication_enabled():
            return

        try:
            self.relations_to_add = []
            self.relations_to_remove = []
            self.cross_account_request = cross_account_request
            self.default_workspace = Workspace.objects.get(
                tenant__org_id=self.cross_account_request.target_org, type=Workspace.Types.DEFAULT
            )
            self.event_type = event_type
            self._replicator = replicator if replicator else OutboxReplicator()
        except Exception as e:
            raise DualWriteException(e)

    def replication_enabled(self):
        """Check whether replication enabled."""
        return settings.REPLICATION_TO_RELATION_ENABLED is True

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
        assert system_role.system is True, "Expected system role. Mappings for custom roles must already be created."
        binding = V2rolebinding(
            str(uuid4()),
            # Assumes same role UUID for V2 system role equivalent.
            V2role.for_system_role(str(system_role.uuid)),
            V2boundresource(("rbac", "workspace"), str(self.default_workspace.id)),
            users=frozenset([str(self.cross_account_request.user_id)]),
        )
        mapping = BindingMapping.for_role_binding(binding, system_role)
        self.relations_to_add.extend(mapping.as_tuples())
        return mapping

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
                role, update_mapping=remove_principal_from_binding, create_default_mapping_for_system_role=lambda: None
            )

    def _update_mapping_for_system_role(
        self,
        role: Role,
        update_mapping: Callable[[BindingMapping], None],
        create_default_mapping_for_system_role: Callable[[], Optional[BindingMapping]],
    ):
        if role.system is False:
            raise DualWriteException("System roles cannot be replicated for a cross-account request.")

        try:
            # We lock the binding here because we cannot lock the Role for system roles,
            # as they are used platform-wide,
            # and their permissions do not refer to specific resources,
            # so they can be changed concurrently safely.
            mapping = (
                BindingMapping.objects.select_for_update()
                .filter(
                    role=role,
                    resource_type_namespace="rbac",
                    resource_type_name="workspace",
                    resource_id=str(self.default_workspace.id),
                )
                .get()
            )

            update_mapping(mapping)

            if mapping.is_unassigned():
                self.relations_to_remove.extend(mapping.as_tuples())
                mapping.delete()
            else:
                mapping.save(force_update=True)
        except BindingMapping.DoesNotExist:
            # create_default_mapping_for_system_role returns None for removing system roles
            mapping = create_default_mapping_for_system_role()
            if mapping is not None:
                mapping.save(force_insert=True)
