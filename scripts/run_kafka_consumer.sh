#!/bin/bash

# Script to run RBAC Kafka consumer in existing rbac_server container
# Usage: ./run_kafka_consumer.sh [topic_name]

TOPIC=${1:-"outbox.event.rbac-consumer-replication-event"}

echo "Starting RBAC Kafka consumer in existing rbac_server container..."
echo "Topic: $TOPIC"
echo "Press Ctrl+C to stop the consumer"

# Run consumer in existing rbac_server container
$CONTAINER_RUNTIME exec -it \
  -e KAFKA_ENABLED=true \
  -e RBAC_KAFKA_CUSTOM_CONSUMER_BROKER=kafka:9092 \
  -e RBAC_KAFKA_CONSUMER_TOPIC="$TOPIC" \
  -e RBAC_KAFKA_CONSUMER_GROUP_ID=rbac-consumer-group \
  rbac_server python rbac/manage.py launch-rbac-kafka-consumer
