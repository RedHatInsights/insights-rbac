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

"""RelationReplicator which writes to the outbox table."""

import logging

from google.protobuf import json_format
from management.models import Outbox
from management.relation_replicator.relation_replicator import RelationReplicator, ReplicationEvent


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class OutboxReplicator(RelationReplicator):
    """Replicates relations via the outbox table."""

    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations via the Outbox."""
        payload = self._build_replication_event(event.add, event.remove)
        self._save_replication_event(payload, event.event_type, event.event_info, event.partition_key)

    def _build_replication_event(self, relations_to_add, relations_to_remove):
        """Build replication event."""
        add_json = []
        for relation in relations_to_add:
            add_json.append(json_format.MessageToDict(relation))

        remove_json = []
        for relation in relations_to_remove:
            remove_json.append(json_format.MessageToDict(relation))

        replication_event = {"relations_to_add": add_json, "relations_to_remove": remove_json}
        return replication_event

    def _save_replication_event(self, payload, event_type, event_info: dict[str, object], aggregateid):
        """Save replication event."""
        # TODO: Can we add these as proper fields for kibana but also get logged in simple formatter?
        logger.info(
            "[Dual Write] Publishing replication event. event_type='%s' %s",
            event_type,
            " ".join([f"info.{key}='{str(value)}'" for key, value in event_info.items()]),
        )
        # https://debezium.io/documentation/reference/stable/transformations/outbox-event-router.html#basic-outbox-table
        outbox_record = Outbox.objects.create(
            aggregatetype="relations-replication-event",
            aggregateid=aggregateid,
            event_type=event_type,
            payload=payload,
        )
        outbox_record.delete()
