#/bin/bash

DOCKER_COMMAND=podman

$DOCKER_COMMAND exec -it rbac_kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic outbox.event.one --from-beginning --timeout-ms 600
