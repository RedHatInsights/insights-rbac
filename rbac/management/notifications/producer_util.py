#
# Copyright 2019 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Producer to send messages to kafka server."""
import json
import os
import pickle
from datetime import datetime
from uuid import uuid4

from django.conf import settings
from kafka import KafkaProducer


with open(os.path.join(settings.BASE_DIR, "management", "notifications", "message_template.json")) as template:
    message_template = json.load(template)


def create_message(event_type, account_id, payload):
    """Create message based on template."""
    message = message_template
    message["event_type"] = event_type
    message["timestamp"] = datetime.now().isoformat()
    message["account_id"] = account_id
    message["events"][0]["payload"] = payload
    return message


producer = KafkaProducer(bootstrap_servers=settings.KAFKA_SERVER)
notification_topic = "platform.notifications.ingress"


def send_kafka_message(event_type, account_id, payload):
    """Send message to kafka server."""
    message = create_message(event_type, account_id, payload)
    serialized_data = pickle.dumps(message)

    producer.send(notification_topic, value=serialized_data, headers=[("rh-message-id", uuid4().bytes)])


"""
This consumer could be used for local testing.
def consume_message():
    from kafka import KafkaConsumer
    consumer = KafkaConsumer(notification_topic,
            bootstrap_servers=[settings.KAFKA_SERVER],
        )
    for message in consumer:
        deserialized_data = pickle.loads(message.value)
        print(deserialized_data)
"""
