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

import logging

class FakeKafkaProducer:
    """Fake kafaka producer to enable local development without kafka server."""
    DEFAULT_CONFIG = {
        'bootstrap_servers': 'localhost',
        'client_id': None,
        'key_serializer': None,
        'value_serializer': None,
        'acks': 1,
        'compression_type': None,
        'retries': 0,
        'batch_size': 16384,
        'linger_ms': 0,
        'buffer_memory': 33554432,
        'connections_max_idle_ms': 9 * 60 * 1000,
        'max_block_ms': 60000,
        'max_request_size': 1048576,
        'metadata_max_age_ms': 300000,
        'retry_backoff_ms': 100,
        'request_timeout_ms': 30000,
        'receive_buffer_bytes': None,
        'send_buffer_bytes': None,
        'sock_chunk_bytes': 4096,  # undocumented experimental option
        'sock_chunk_buffer_count': 1000,  # undocumented experimental option
        'reconnect_backoff_ms': 50,
        'reconnect_backoff_max_ms': 1000,
        'max_in_flight_requests_per_connection': 5,
        'security_protocol': 'PLAINTEXT',
        'ssl_context': None,
        'ssl_check_hostname': True,
        'ssl_cafile': None,
        'ssl_certfile': None,
        'ssl_keyfile': None,
        'ssl_crlfile': None,
        'ssl_password': None,
        'ssl_ciphers': None,
        'api_version': None,
        'api_version_auto_timeout_ms': 2000,
        'metric_reporters': [],
        'metrics_num_samples': 2,
        'metrics_sample_window_ms': 30000,
        'sasl_mechanism': None,
        'sasl_plain_username': None,
        'sasl_plain_password': None,
        'sasl_kerberos_service_name': 'kafka',
        'sasl_kerberos_domain_name': None,
        'sasl_oauth_token_provider': None
    }

    def __init__(self, **configs):

        self.config = self.DEFAULT_CONFIG

    def send(self, topic, value=None, headers=None):
        """No operation method."""
        pass


class RBACProducer:
    """Kafka message producer to emit events to notification service."""

    def get_producer(self):
        """Init method to return fake kafka when flag is set to false."""

        logging.getLogger("management.group.view").info("Producer selection:")
        fromCache = True

        if not hasattr(self, "producer"):
            fromCache = False
            if settings.DEVELOPMENT or settings.MOCK_KAFKA or not settings.KAFKA_ENABLED:
                logging.getLogger("management.group.view").info("Producer selection FakeKafkaProducer")
                self.producer = FakeKafkaProducer()
            else:
                if settings.KAFKA_AUTH:
                    logging.getLogger("management.group.view").info("Producer selection KAFKA_AUTH true")
                    logging.getLogger("management.group.view").info("Producer selection KAFKA_AUTH %s", settings.KAFKA_AUTH['bootstrap_servers'])
                    self.producer = KafkaProducer(**settings.KAFKA_AUTH)
                else:
                    logging.getLogger("management.group.view").info("Producer selection KAFKA_AUTH false")
                    self.producer = KafkaProducer(bootstrap_servers=settings.KAFKA_SERVER)
                    logging.getLogger("management.group.view").info("Server %s", settings.KAFKA_SERVER)
        if fromCache:
            logging.getLogger("management.group.view").info("Producer from cache")
        else:
            logging.getLogger("management.group.view").info("Producer NOT from cache")
        logging.getLogger("management.group.view").info("Producer selection producer: %s", self.producer.config['bootstrap_servers'])
        logging.getLogger("management.group.view").info("Producer selection END")
        return self.producer

    def send_kafka_message(self, topic, message, headers=None):
        """Send message to kafka server."""
        logging.getLogger("management.group.view").info("send kafka message %s ", topic)
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
