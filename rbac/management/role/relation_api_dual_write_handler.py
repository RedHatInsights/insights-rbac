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
from google.protobuf import json_format
from kessel.relations.v1beta1 import common_pb2
from management.models import Outbox
from management.role.model import BindingMapping, Role
from migration_tool.migrate import migrate_role


from api.models import Tenant


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
    ADD_PRINCIPALS_TO_GROUP = "add_principals_to_group"
    REMOVE_PRINCIPALS_FROM_GROUP = "remove_principals_from_group"


class ReplicationEvent:
    """What tuples changes to replicate."""

    event_type: ReplicationEventType
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
        self.event_type = type
        self.add = add
        self.remove = remove


class RelationReplicator(ABC):
    """Type responsible for replicating relations to Kessel Relations."""

    @abstractmethod
    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations."""
        pass


class OutboxReplicator(RelationReplicator):
    """Replicates relations via the outbox table."""

    def __init__(self, record):
        """Initialize OutboxReplicator."""
        self.record = record

    def _record_name(self):
        """Return record name."""
        return self.record.name

    def _record_uuid(self):
        """Return record uuid."""
        return self.record.uuid

    def _record_class(self):
        """Return record class."""
        return self.record.__class__.__name__

    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations via the Outbox."""
        payload = self._build_replication_event(event.add, event.remove)
        self._save_replication_event(payload, event.event_type, event.partition_key)

    def _build_replication_event(self, relations_to_add, relations_to_remove):
        """Build replication event."""
        logger.info(
            "[Dual Write] Build Replication event for %s(%s): '%s'",
            self._record_class(),
            self._record_uuid(),
            self._record_name()
        )
        add_json = []
        for relation in relations_to_add:
            add_json.append(json_format.MessageToDict(relation))

        remove_json = []
        for relation in relations_to_remove:
            remove_json.append(json_format.MessageToDict(relation))

        replication_event = {"relations_to_add": add_json, "relations_to_remove": remove_json}
        return replication_event

    def _save_replication_event(self, payload, event_type, aggregateid):
        """Save replication event."""
        logger.info(
            "[Dual Write] Save replication event into outbox table for %s(%s): '%s'",
            self._record_class(),
            self._record_uuid(),
            self._record_name()
        )
        logger.info(
            "[Dual Write] Replication event: %s for %s(%s): '%s'",
            payload,
            self._record_class(),
            self._record_uuid(),
            self._record_name()
        )
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

    @classmethod
    def for_system_role_event(
        cls,
        role: Role,
        # TODO: may want to include Policy instead?
        tenant: Tenant,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
    ):
        """Create a RelationApiDualWriteHandler for assigning / unassigning a system role for a group."""
        return cls(role, event_type, replicator, tenant)

    def __init__(
        self,
        role: Role,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
        tenant: Optional[Tenant] = None,
    ):
        """Initialize RelationApiDualWriteHandler."""
        if not self.replication_enabled():
            self._replicator = NoopReplicator()
            return
        try:
            self._replicator = replicator if replicator else OutboxReplicator(role)
            self.event_type = event_type
            self.role_relations: list[common_pb2.Relationship] = []
            self.current_role_relations: list[common_pb2.Relationship] = []
            self.role = role
            self.binding_mappings: dict[str, BindingMapping] = {}

            binding_tenant = tenant if tenant is not None else role.tenant

            if binding_tenant.tenant_name == "public":
                raise DualWriteException(
                    "Cannot bind role to public tenant. "
                    "Expected the role to have non-public tenant, or for a non-public tenant to be provided. "
                    f"Role: {role.uuid} "
                    f"Tenant: {binding_tenant.id}"
                )

            self.tenant_id = binding_tenant.id
            self.org_id = binding_tenant.org_id
        except Exception as e:
            raise DualWriteException(e)

    def replication_enabled(self):
        """Check whether replication enabled."""
        return settings.REPLICATION_TO_RELATION_ENABLED is True

    def prepare_for_update(self):
        """Generate relations from current state of role and UUIDs for v2 role and role binding from database."""
        if not self.replication_enabled():
            return
        try:
            logger.info(
                "[Dual Write] Generate relations from current state of role(%s): '%s'", self.role.uuid, self.role.name
            )

            self.binding_mappings = {m.id: m for m in self.role.binding_mappings.select_for_update().all()}

            if not self.binding_mappings:
                logger.warning(
                    "[Dual Write] Binding mappings not found for role(%s): '%s'. "
                    "Assuming no current relations exist. "
                    "If this is NOT the case, relations are inconsistent!",
                    self.role.uuid,
                    self.role.name,
                )
                return

            relations, _ = migrate_role(
                self.role,
                write_relationships=False,
                default_workspace=self.org_id,
                current_bindings=self.binding_mappings.values(),
            )

            self.current_role_relations = relations
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
                current_bindings=self.binding_mappings.values(),
            )

            prior_mappings = self.binding_mappings

            self.role_relations = relations
            self.binding_mappings = {m.id: m for m in mappings}

            # Create or update mappings as needed
            for mapping in mappings:
                if mapping.id is not None:
                    prior_mappings.pop(mapping.id)
                mapping.save()

            # Delete any mappings to resources this role no longer gives access to
            for mapping in prior_mappings.values():
                mapping.delete()

            return relations
        except Exception as e:
            raise DualWriteException(e)
