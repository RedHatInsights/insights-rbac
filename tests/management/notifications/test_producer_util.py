from unittest.mock import Mock, patch
from django.test import TestCase
from management.notifications.producer_util import NotificationProducer


class TypeMatcher:
    def __init__(self, expected_type):
        self.expected_type = expected_type

    def __eq__(self, other):
        return isinstance(other, self.expected_type)


producer = Mock()


@patch("management.notifications.producer_util.FakeKafkaProducer", return_value=producer)
class ProducerTest(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.account_id = "01234567"
        self.payload = "This is a test"
        self.event_type = "rh-new-role-available"
        self.topic = "platform.notifications.ingress"

    def test_message_creator(self, kafk_producer):
        """Ensure the message is created properly."""
        message = NotificationProducer().create_message(self.event_type, self.account_id, self.payload)

        self.assertEqual(message["bundle"], "console")
        self.assertEqual(message["application"], "rbac")
        self.assertEqual(message["account_id"], self.account_id)
        self.assertEqual(message["events"][0]["payload"], self.payload)

    def test_send_message(self, kafk_producer):

        NotificationProducer().send_kafka_message(self.event_type, self.account_id, self.payload)

        producer.send.assert_called_once()
        producer.send.assert_called_once_with(self.topic, headers=TypeMatcher(list), value=TypeMatcher(str))
