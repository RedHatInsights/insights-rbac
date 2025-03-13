from copy import deepcopy
from unittest.mock import Mock, MagicMock, patch, DEFAULT
from django.test import TestCase
from kafka.errors import KafkaError
from core.kafka import RBACProducer, logger


def copy_call_args(mock):
    kafka_mock = Mock()

    def side_effect(*args, **kwargs):
        args = deepcopy(args)
        kwargs = deepcopy(kwargs)
        kafka_mock(*args, **kwargs)
        return DEFAULT

    mock.side_effect = side_effect
    return kafka_mock


class KafkaTests(TestCase):
    @patch("core.kafka.RBACProducer")
    @patch("core.kafka.logger")
    def test_kafka_producer_errors_logged(self, mock_logger, MockKafkaProducer):
        """Test that mocked Kafka error return correct messages from Kafka producer"""
        MockKafkaProducer.get_producer.side_effect = KafkaError

        with self.assertRaises(KafkaError):
            MockKafkaProducer.get_producer()
            mock_logger.error.assert_called_with("Kafka error during initialization of Kafka producer")

    @patch("core.kafka.RBACProducer")
    @patch("core.kafka.logger")
    def test_kafka_generic_producer_errors_logged(self, mock_logger, MockKafkaProducer):
        """Test that mocked generic error return correct messages from Kafka producer"""
        MockKafkaProducer.get_producer.side_effect = Exception

        with self.assertRaises(Exception):
            MockKafkaProducer.get_producer()
            mock_logger.error.assert_called_with("Non Kafka error occurred during initialization of Kafka producer")
