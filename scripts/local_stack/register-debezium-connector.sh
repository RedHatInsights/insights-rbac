#!/bin/sh
# One-shot: wait for Kafka Connect and register the Debezium connector.
set -eu

CONNECT_URL="${KAFKA_CONNECT_URL:-http://kafka-connect:8083}"
CONNECTOR_JSON="${CONNECTOR_JSON:-/connector/debezium-connector.json}"
CONNECTOR_NAME="${CONNECTOR_NAME:-rbac-debezium}"

echo "Waiting for Kafka Connect at ${CONNECT_URL}..."
until curl -sf "${CONNECT_URL}/connectors" >/dev/null 2>&1; do
  sleep 2
done

if curl -sf "${CONNECT_URL}/connectors/${CONNECTOR_NAME}/status" | grep -q '"state":"RUNNING"'; then
  echo "Connector ${CONNECTOR_NAME} already running"
  exit 0
fi

if curl -sf "${CONNECT_URL}/connectors" | grep -q "\"${CONNECTOR_NAME}\""; then
  echo "Deleting failed/stale connector ${CONNECTOR_NAME}..."
  curl -sf -X DELETE "${CONNECT_URL}/connectors/${CONNECTOR_NAME}" >/dev/null || true
  sleep 2
fi

echo "Creating connector ${CONNECTOR_NAME}..."
response=$(curl -s -X POST "${CONNECT_URL}/connectors" \
  -H "Content-Type: application/json" \
  -d @"${CONNECTOR_JSON}")

if echo "$response" | grep -q "\"name\":\"${CONNECTOR_NAME}\""; then
  echo "Connector ${CONNECTOR_NAME} created"
  exit 0
fi

echo "Failed to create connector:"
echo "$response"
exit 1
