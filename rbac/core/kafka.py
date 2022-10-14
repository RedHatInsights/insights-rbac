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

from django.conf import settings
from kafka import KafkaProducer


class FakeKafkaProducer:
    """Fake kafaka producer to enable local development without kafka server."""

    def send(self, topic, value=None, headers=None):
        """No operation method."""
        pass


class RBACProducer:
    """Kafka message producer to emit events to notification service."""

    def get_producer(self):
        """Init method to return fake kafka when flag is set to false."""
        if not hasattr(self, "producer"):
            if settings.DEVELOPMENT or not settings.KAFKA_ENABLED:
                self.producer = FakeKafkaProducer()
            else:
                if settings.KAFKA_AUTH:
                    self.producer = KafkaProducer(**settings.KAFKA_AUTH)
                else:
                    self.producer = KafkaProducer(bootstrap_servers=settings.KAFKA_SERVER)
        return self.producer

    def send_kafka_message(self, topic, message, headers=None):
        """Send message to kafka server."""
        producer = self.get_producer()
        json_data = json.dumps(message).encode("utf-8")
        if headers and not isinstance(headers, list):
            headers = [headers]
        producer.send(topic, value=json_data, headers=headers)


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
