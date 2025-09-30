#!/bin/bash

# Script to send test relations message to Kafka
# Usage: ./send_test_relations_message.sh [topic_name]

TOPIC=${1:-"outbox.event.rbac-consumer-replication-event"}

# Create test message in the format expected by RBAC Kafka consumer
cat > /tmp/test_relations_message.json << EOL
{
  "schema": {
    "type": "struct",
    "fields": [
      {
        "type": "string",
        "optional": false,
        "field": "payload"
      }
    ],
    "optional": false,
    "name": "test.relations.message"
  },
  "payload": "{\"relations_to_add\": [{\"resource\": {\"type\": \"role\", \"id\": \"test-role-$(date +%s)\"}, \"relation\": \"member\", \"subject\": {\"type\": \"user\", \"id\": \"test-user-$(date +%s)\"}}], \"relations_to_remove\": []}"
}
EOL

echo "Sending test relations message to topic: $TOPIC"

# Send message to Kafka
docker exec -i insights_rbac-kafka-1 kafka-console-producer \
  --bootstrap-server localhost:9092 \
  --topic "$TOPIC" < /tmp/test_relations_message.json

echo "Message sent successfully!"
echo "Check consumer logs to see if it was processed."

# Clean up
rm -f /tmp/test_relations_message.json
