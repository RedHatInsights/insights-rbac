#
# Copyright 2019 Red Hat, Inc.
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

"""Notification handlers of object change."""
import json
import logging
import os
from datetime import datetime

from core.kafka import RBACProducer
from django.conf import settings


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
sync_producer = RBACProducer()
sync_topic = settings.EXTERNAL_SYNC_TOPIC

with open(os.path.join(settings.BASE_DIR, "internal", "integration", "message_template.json")) as template:
    message_template = json.load(template)


def build_sync_message(event_type, payload, account_id=None, org_id=None):
    """Create message based on template."""
    message = message_template
    if settings.AUTHENTICATE_WITH_ORG_ID:
        message["org_id"] = org_id
    message["event_type"] = event_type
    message["timestamp"] = datetime.now().isoformat()
    message["account_id"] = account_id
    message["events"][0]["payload"] = payload
    return message


def send_sync_message(event_type, payload, account_id=None, org_id=None):
    """Build and send external service sync message."""

    logger.info("Kafka message %s - ", event_type)

    sync_message = build_sync_message(event_type, payload, account_id, org_id)
    sync_producer.send_kafka_message(sync_topic, sync_message)
