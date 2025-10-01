#!/bin/bash

# Script to send test relations message to Kafka
# Usage: ./send_test_relations_message.sh [topic_name]

# Detect container runtime (docker or podman)
if command -v docker &> /dev/null && docker info &> /dev/null; then
    CONTAINER_RUNTIME="docker"
elif command -v podman &> /dev/null; then
    CONTAINER_RUNTIME="podman"
else
    echo "Error: Neither Docker nor Podman is available or running"
    exit 1
fi

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
$CONTAINER_RUNTIME exec -i insights-rbac-kafka-1 kafka-console-producer \
  --bootstrap-server localhost:9092 \
  --topic "$TOPIC" < /tmp/test_relations_message.json

echo "Message sent successfully!"
echo "Check consumer logs to see if it was processed."

# Clean up
rm -f /tmp/test_relations_message.json
