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
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional

from django.conf import settings
from kessel.relations.v1beta1 import common_pb2
from management.models import Outbox
from management.role.model import BindingMapping
from migration_tool.migrate import migrate_role
from migration_tool.utils import relationship_to_json


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class DualWriteException(Exception):
    """DualWrite exception."""

    pass


class ReplicationEventType(str, Enum):
    """Replication event type."""

    CREATE_SYSTEM_ROLE = "create_system_role"
    UPDATE_SYSTEM_ROLE = "update_system_role"
    DELETE_SYSTEM_ROLE = "delete_system_role"
    CREATE_CUSTOM_ROLE = "create_custom_role"
    UPDATE_CUSTOM_ROLE = "update_custom_role"
    DELETE_CUSTOM_ROLE = "delete_custom_role"
    ASSIGN_ROLE = "assign_role"
    UNASSIGN_ROLE = "unassign_role"
    CREATE_GROUP = "create_group"
    UPDATE_GROUP = "update_group"
    DELETE_GROUP = "delete_group"


class ReplicationEvent:
    """What tuples changes to replicate."""

    type: ReplicationEventType
    partition_key: str
    add: list[common_pb2.Relationship]
    remove: list[common_pb2.Relationship]

    def __init__(
        self,
        type: ReplicationEventType,
        partition_key: str,
        add: list[common_pb2.Relationship] = [],
        remove: list[common_pb2.Relationship] = [],
    ):
        """Initialize ReplicationEvent."""
        self.partition_key = partition_key
        self.type = type
        self.add = add
        self.remove = remove


class RelationReplicator(ABC):
    """Type responsible for replicating relations to Kessel Relations."""

    @abstractmethod
    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations."""
        pass


class OutboxReplicater(RelationReplicator):
    """Replicates relations via the outbox table."""

    def __init__(self, role):
        """Initialize OutboxReplicater."""
        self.role = role

    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations via the Outbox."""
        payload = self._build_replication_event(event.add, event.remove)
        self._save_replication_event(payload, event.type, event.partition_key)

    def _build_replication_event(self, relations_to_add, relations_to_remove):
        """Build replication event."""
        logger.info("[Dual Write] Build Replication event for role(%s): '%s'", self.role.uuid, self.role.name)
        add_json = []
        for relation in relations_to_add:
            add_json.append(relationship_to_json(relation))

        remove_json = []
        for relation in relations_to_remove:
            remove_json.append(relationship_to_json(relation))

        replication_event = {"relations_to_add": add_json, "relations_to_remove": remove_json}
        return replication_event

    def _save_replication_event(self, payload, event_type, aggregateid):
        """Save replication event."""
        logger.info(
            "[Dual Write] Save replication event into outbox table for role(%s): '%s'", self.role.uuid, self.role.name
        )
        logger.info("[Dual Write] Replication event: %s for role(%s): '%s'", payload, self.role.uuid, self.role.name)
        # https://debezium.io/documentation/reference/stable/transformations/outbox-event-router.html#basic-outbox-table
        outbox_record = Outbox.objects.create(
            aggregatetype="RelationReplicationEvent",
            aggregateid=aggregateid,
            event_type=event_type,
            payload=payload,
        )
        outbox_record.delete()


class NoopReplicator(RelationReplicator):
    """Noop replicator."""

    def replicate(self, event: ReplicationEvent):
        """Noop."""
        pass


class RelationApiDualWriteHandler:
    """Class to handle Dual Write API related operations."""

    # TODO: add resource as parameter
    def __init__(self, role, event_type: ReplicationEventType, replicator: Optional[RelationReplicator] = None):
        """Initialize RelationApiDualWriteHandler."""
        if not self.replication_enabled():
            self._replicator = NoopReplicator()
            return
        try:
            self._replicator = replicator if replicator else OutboxReplicater(role)
            self.role_relations: list[common_pb2.Relationship] = []
            self.current_role_relations: list[common_pb2.Relationship] = []
            self.role = role
            self.binding_mapping = None
            self.tenant_id = role.tenant_id
            self.org_id = role.tenant.org_id
            self.event_type = event_type
        except Exception as e:
            raise DualWriteException(e)

    def replication_enabled(self):
        """Check whether replication enabled."""
        return settings.REPLICATION_TO_RELATION_ENABLED is True

    def load_relations_from_current_state_of_role(self):
        """Generate relations from current state of role and UUIDs for v2 role and role binding from database."""
        if not self.replication_enabled():
            return
        try:
            logger.info(
                "[Dual Write] Generate relations from current state of role(%s): '%s'", self.role.uuid, self.role.name
            )

            self.binding_mapping = self.role.binding_mapping

            relations, _ = migrate_role(
                self.role,
                write_relationships=False,
                default_workspace=self.org_id,
                current_mapping=self.binding_mapping,
            )

            self.current_role_relations = relations
        except BindingMapping.DoesNotExist:
            logger.warning(
                "[Dual Write] Binding mapping not found for role(%s): '%s'. "
                "Assuming no current relations exist. "
                "If this is NOT the case, relations are inconsistent!",
                self.role.uuid,
                self.role.name,
            )
        except Exception as e:
            raise DualWriteException(e)

    def replicate_new_or_updated_role(self, role):
        """Generate replication event to outbox table."""
        if not self.replication_enabled():
            return
        self.role = role
        self._generate_relations_and_mappings_for_role()
        self._replicate()

    def replicate_deleted_role(self):
        """Replicate removal of current role state."""
        if not self.replication_enabled():
            return
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
                    remove=self.current_role_relations,
                    add=self.role_relations,
                ),
            )
        except Exception as e:
            raise DualWriteException(e)

    def _generate_relations_and_mappings_for_role(self):
        """Generate relations and mappings for a role with new UUIDs for v2 role and role bindings."""
        if not self.replication_enabled():
            return []
        try:
            logger.info("[Dual Write] Generate new relations from role(%s): '%s'", self.role.uuid, self.role.name)

            relations, mappings = migrate_role(
                self.role,
                write_relationships=False,
                default_workspace=self.org_id,
                current_mapping=self.binding_mapping,
            )

            self.role_relations = relations

            if self.binding_mapping is None:
                self.binding_mapping = BindingMapping.objects.create(role=self.role, mappings=mappings)
            else:
                self.binding_mapping.mappings = mappings
                self.binding_mapping.save(force_update=True)

            return relations
        except Exception as e:
            raise DualWriteException(e)
