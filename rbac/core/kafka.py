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

from confluent_kafka import Producer
from django.conf import settings

class FakeKafkaProducer:
    """Fake kafaka producer to enable local development without kafka server."""

    def send(self, topic, value=None, headers=None):
        """No operation method."""
        pass

    def produce(self, topic, key=None, value=None, headers=None):
        """No operation method."""
        pass


class RBACProducer:
    """Kafka message producer to emit events to notification service."""
    def get_producer(self):
        with open('filename.txt', 'a') as f:
            f.write('get_producer\n')
        """Init method to return fake kafka when flag is set to false."""
        if not hasattr(self, "producer"):
            with open('filename.txt', 'a') as f:
                f.write('producer\n')
            if settings.DEVELOPMENT or settings.MOCK_KAFKA or not settings.KAFKA_ENABLED:
                with open('filename.txt', 'a') as f:
                    f.write('fake\n')

                self.producer = FakeKafkaProducer()
            else:
                with open('filename.txt', 'a') as f:
                    f.write('prod\n')

                if settings.KAFKA_AUTH:
                    with open('filename.txt', 'a') as f:
                        f.write('KAFKA_AUTH\n')

                    conf = {
                        "bootstrap.servers": settings.KAFKA_AUTH["bootstrap_servers"],
                        "security.protocol": settings.KAFKA_AUTH["security_protocol"],
                        "sasl.mechanism": settings.KAFKA_AUTH["sasl_mechanism"],
                        "sasl.username": settings.KAFKA_AUTH["sasl_plain_username"],
                        "sasl.password": settings.KAFKA_AUTH["sasl_plain_password"],
                    }

                    self.producer = Producer(conf)
                else:
                    with open('filename.txt', 'a') as f:
                        f.write('NOT AUTH\n')

                    conf = {"bootstrap.servers": settings.KAFKA_SERVER}

                    self.producer = Producer(conf)

        return self.producer

    def get_sync_producer(self):
        with open('filename.txt', 'a') as f:
            f.write('get_sync_producer\n')
        """Init method to return fake kafka when flag is set to false."""
        if not hasattr(self, "sync_producer"):
            with open('filename.txt', 'a') as f:
                f.write('sync_producer\n')
            if settings.DEVELOPMENT or settings.MOCK_KAFKA or not settings.KAFKA_ENABLED:
                with open('filename.txt', 'a') as f:
                    f.write('fake\n')

                self.sync_producer = FakeKafkaProducer()
            else:
                with open('filename.txt', 'a') as f:
                    f.write('prod\n')

                if settings.KAFKA_AUTH:
                    with open('filename.txt', 'a') as f:
                        f.write('KAFKA_AUTH\n')

                    conf = {
                        "bootstrap.servers": settings.KAFKA_AUTH["bootstrap_servers"],
                        "security.protocol": settings.KAFKA_AUTH["security_protocol"],
                        "sasl.mechanism": settings.KAFKA_AUTH["sasl_mechanism"],
                        "sasl.username": settings.KAFKA_AUTH["sasl_plain_username"],
                        "sasl.password": settings.KAFKA_AUTH["sasl_plain_password"],
                    }

                    self.sync_producer = Producer(conf)
                else:
                    with open('filename.txt', 'a') as f:
                        f.write('NOT AUTH\n')

                    conf = {"bootstrap.servers": settings.KAFKA_SERVER}

                    self.sync_producer = Producer(conf)

        return self.sync_producer
    def send_kafka_message(self, topic, message, headers=None):
        """Send message to kafka server."""
        if topic == "platform.rbac.sync":
            producer = self.get_sync_producer()
        else:
            producer = self.get_producer()

        json_data = json.dumps(message).encode("utf-8")
        if headers and not isinstance(headers, list):
            headers = [headers]
        producer.produce(topic, key=None, value=json_data, headers=headers)


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
