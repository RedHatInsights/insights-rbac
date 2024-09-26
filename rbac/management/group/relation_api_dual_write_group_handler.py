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
from uuid import uuid4

from django.conf import settings
from management.principal.model import Principal
from management.role.model import BindingMapping, Role
from management.role.relation_api_dual_write_handler import (
    DualWriteException,
    OutboxReplicator,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from migration_tool.utils import create_relationship
from migration_tool.models import V2boundresource, V2role, V2rolebinding

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationApiDualWriteGroupHandler:
    """Class to handle Dual Write API related operations."""

    def __init__(
        self,
        group,
        event_type: ReplicationEventType,
        principals: list[Principal],
        replicator: Optional[RelationReplicator] = None,
    ):
        """Initialize RelationApiDualWriteGroupHandler."""
        if not self.replication_enabled():
            return
        try:
            self.group_relations_to_add = []
            self.group_relations_to_remove = []
            self.principals = principals
            self.group = group
            self.event_type = event_type
            self._replicator = replicator if replicator else OutboxReplicator(group)
        except Exception as e:
            raise DualWriteException(e)

    def replication_enabled(self):
        """Check whether replication enabled."""
        return settings.REPLICATION_TO_RELATION_ENABLED is True

    def _generate_relations(self):
        """Generate user-groups relations."""
        relations = []
        for principal in self.principals:
            relations.append(
                create_relationship(
                    ("rbac", "group"), str(self.group.uuid), ("rbac", "user"), str(principal.uuid), "member"
                )
            )

        return relations

    def replicate_new_principals(self):
        """Replicate new principals into group."""
        if not self.replication_enabled():
            return
        logger.info("[Dual Write] Generate new relations from Group(%s): '%s'", self.group.uuid, self.group.name)

        self.group_relations_to_add = self._generate_relations()
        self._replicate()

    def replicate_removed_principals(self):
        """Replicate removed principals from group."""
        if not self.replication_enabled():
            return
        logger.info("[Dual Write] Generate new relations from Group(%s): '%s'", self.group.uuid, self.group.name)

        self.group_relations_to_remove = self._generate_relations()

        self._replicate()

    def _replicate(self):
        if not self.replication_enabled():
            return
        try:
            self._replicator.replicate(
                ReplicationEvent(
                    type=self.event_type,
                    # TODO: need to think about partitioning
                    # Maybe resource id
                    partition_key="rbactodo",
                    remove=self.group_relations_to_remove,
                    add=self.group_relations_to_add,
                ),
            )
        except Exception as e:
            raise DualWriteException(e)

    def replicate_added_role(self, role: Role):
        """Replicate added role. role needs to be locked"""
        if not self.replication_enabled():
            return

        if role.system:
            try:
                mapping = (
                    BindingMapping.objects.select_for_update()
                    .filter(
                        role=role,
                        resource_type_namespace="rbac",
                        resource_type_name="workspace",
                        # TODO: don't use org id once we have workspace built ins
                        resource_id=self.group.tenant.org_id,
                    )
                    .get()
                )
                self.group_relations_to_add.append(mapping.add_group_to_bindings(str(self.group.uuid)))
                mapping.save(force_update=True)
            except BindingMapping.DoesNotExist:
                mapping = BindingMapping.for_group_and_role(role, str(self.group.uuid), self.group.tenant.org_id)
                mapping.save(force_insert=True)
                self.group_relations_to_add.extend(mapping.as_tuples())
        else:
            # Intentionally queried this way to avoid use of cached binding_mappings
            # There is a risk of phantom reads here, but this is why we lock the custom Role
            bindings: Iterable[BindingMapping] = BindingMapping.objects.filter(role=role).select_for_update()

            for mapping in bindings:
                self.group_relations_to_add.append(mapping.add_group_to_bindings(str(self.group.uuid)))
                mapping.save(force_update=True)
        self._replicate()

    def replicate_removed_role(self, role: Role):
        if not self.replication_enabled():
            return
        # This logic can be the same for system vs custom b/c we'd never create a binding in this path
        bindings: Iterable[BindingMapping] = role.binding_mappings.select_for_update().all()
        for binding in bindings:
            relations = binding.remove_group_from_bindings(str(self.group.uuid))
            self.group_relations_to_remove.append(relations)
            if role.system:
                self.group_relations_to_remove.extend(binding.as_tuples())
                binding.delete()
            else:
                binding.save()
        self._replicate()
