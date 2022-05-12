#
# Copyright 2022 Red Hat, Inc.
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
from datetime import datetime
from uuid import uuid4

from django.conf import settings
from kafka import KafkaProducer


with open(os.path.join(settings.BASE_DIR, "management", "notifications", "message_template.json")) as template:
    message_template = json.load(template)


class FakeKafkaProducer:
    """Fake kafaka producer to enable local development without kafka server."""

    def send(self, topic, value=None, headers=None):
        """No operation method."""
        pass


notification_topic = "platform.notifications.ingress"


class NotificationProducer:
    """Kafka message producer to emit events to notification service."""

    def get_producer(self):
        """Init method to return fake kafka when flag is set to false."""
        if hasattr(self, "producer"):
            return self.producer

        if settings.NOTIFICATIONS_ENABLED:
            self.producer = KafkaProducer(bootstrap_servers=settings.KAFKA_SERVER)
        else:
            self.producer = FakeKafkaProducer()
        return self.producer

    def create_message(self, event_type, account_id, payload):
        """Create message based on template."""
        message = message_template
        message["event_type"] = event_type
        message["timestamp"] = datetime.now().isoformat()
        message["account_id"] = account_id
        message["events"][0]["payload"] = payload
        return message

    def send_kafka_message(self, event_type, account_id, payload):
        """Send message to kafka server."""
        producer = self.get_producer()
        message = self.create_message(event_type, account_id, payload)
        json_data = json.dumps(message).encode("utf-8")

        producer.send(notification_topic, value=json_data, headers=[("rh-message-id", str(uuid4()).encode("utf-8"))])


"""
This consumer could be used for local testing.
def consume_message():
    from kafka import KafkaConsumer
    consumer = KafkaConsumer(notification_topic,
            bootstrap_servers=[settings.KAFKA_SERVER],
        )
    for message in consumer:
        deserialized_data = pickle.loads(message.value)
        print(json.dumps(deserialized_data, indent=4, sort_keys=True)
"""
