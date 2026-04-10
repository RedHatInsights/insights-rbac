# Integration Guidelines for insights-rbac

## 1. Kafka Producer Patterns

### Topics
- `NOTIFICATIONS_TOPIC` -- Cloud notifications (role/group/cross-account changes)
- `EXTERNAL_SYNC_TOPIC` -- External service sync (e.g., Chrome sync events)
- `RBAC_KAFKA_CONSUMER_TOPIC` -- Debezium CDC outbox events (consumed internally)

### Producer usage
- Always use `core.kafka.RBACProducer`. Never instantiate `KafkaProducer` directly.
- Messages are JSON-encoded via `json.dumps().encode("utf-8")`.
- In dev/test, `FakeKafkaProducer` is used when `DEVELOPMENT`, `MOCK_KAFKA`, or `not KAFKA_ENABLED`.
- Producer retries connection up to 5 times on init failure. After init, `send()` is fire-and-forget.
- Headers must be a list of tuples: `[("rh-message-id", uuid_bytes)]`.

### Notification messages
- Use `management.notifications.notification_handlers.notify()` for per-tenant notifications.
- Use `notify_all()` for system-wide broadcasts (iterates all tenants).
- Guard all notification calls with `settings.NOTIFICATIONS_ENABLED` (custom roles/groups) or `settings.NOTIFICATIONS_RH_ENABLED` (system roles).
- Build payloads via `payload_builder()` -- always include `username`, `name`, `uuid`.
- Message structure follows `message_template.json` with `event_type`, `timestamp`, `events[0].payload`.

### Sync messages
- Use `internal.integration.sync_handlers.send_sync_message()`.
- Same `RBACProducer` singleton, different topic (`EXTERNAL_SYNC_TOPIC`).

## 2. Kafka Consumer Patterns

### Consumer architecture (`core.kafka_consumer.RBACKafkaConsumer`)
- Single-partition-per-consumer design. Multi-partition assignment triggers a warning.
- Manual offset commit (`enable_auto_commit=False`) with batch commit every N messages (`CommitConfig.commit_modulo=10`).
- `auto_offset_reset="earliest"` for at-least-once delivery guarantee.
- Consumer group ID from `settings.RBAC_KAFKA_CONSUMER_GROUP_ID`.

### Message processing pipeline
1. Parse raw bytes to JSON
2. Parse Debezium envelope (`schema` + `payload` fields required)
3. Extract `relations_to_add` / `relations_to_remove` from payload
4. Convert JSON dicts to protobuf `common_pb2.Relationship` via `json_format.ParseDict()`
5. Write/delete tuples to Kessel Relations API with fencing check
6. Save consistency token to `Tenant.relations_consistency_token`

### Error classification
- `ValidationError` and `ParseError` are NON-RETRYABLE -- consumer stops immediately.
- `grpc.StatusCode.FAILED_PRECONDITION` (stale fencing token) is FATAL -- consumer stops.
- All other errors (network, gRPC, DB) are RETRYABLE with exponential backoff.
- Max retries exceeded: consumer stops, does NOT commit offset, relies on K8s restart.

### Retry configuration
- `RetryConfig`: `operation_max_retries=10`, `backoff_factor=5`, `base_delay=0.3s`, `max_backoff=30s`.
- Jitter factor of 0.1 prevents thundering herd.
- Use `RetryHelper` class for retry logic -- never write custom retry loops.

### Health checks
- Liveness: `/tmp/kubernetes-liveness` file presence
- Readiness: `/tmp/kubernetes-readiness` file presence
- Background health check thread polls Kafka connectivity every 30s.

## 3. Debezium CDC / Outbox Pattern

### Outbox table (`management.debezium.model.Outbox`)
- Fields: `id` (UUID), `aggregatetype`, `aggregateid`, `event_type` (DB column: `type`), `payload` (JSON).
- Follows Debezium outbox event router spec.
- Records are saved then IMMEDIATELY deleted (`force_insert=True` + `delete()`). Debezium reads from WAL, not the table.

### Replicator selection
- `OutboxReplicator` -- production path: writes to outbox table, Debezium picks up from WAL.
- `RelationsApiReplicator` -- direct gRPC to Kessel (used by consumer and some internal tools).
- `LoggingReplicator` -- logs tuples (dev/debug).
- `NoopReplicator` -- does nothing (feature flag off).
- Select via `get_replicator(write_relationships)` in `internal.utils`: `"true"/"outbox"` -> Outbox, `"logging"` -> Logging, else -> Noop.

### ReplicationEvent conventions
- Always specify `event_type` from `ReplicationEventType` enum (e.g., `CREATE_CUSTOM_ROLE`, `ASSIGN_ROLE`).
- Always use `PartitionKey.byEnvironment()` -- all events globally ordered per environment.
- Include `info` dict with at minimum `org_id`. For workspace events, include `workspace_id`.
- `resource_context()` auto-generates `created_at` timestamp for latency tracking.
- Empty events (no tuples to add or remove) are logged as warnings and skipped.
- Duplicate relationships in `add` list raise `ValueError` immediately -- fix at the source.

### Aggregate types
- `"relations-replication-event"` -- relation tuple changes (roles, groups, bindings).
- `"workspace"` -- workspace lifecycle events (create/update/delete).

## 4. gRPC Client Patterns (Kessel Relations & Inventory)

### Channel creation
- `create_client_channel_relation(settings.RELATION_API_SERVER)` -- insecure in dev/Clowder, TLS in production.
- `create_client_channel_inventory(settings.INVENTORY_API_SERVER)` -- same pattern for Inventory API.
- Always use as context manager (`with create_client_channel_relation(...) as channel:`).

### Authentication
- JWT tokens fetched via `JWTManager.get_jwt_from_redis()` and passed as gRPC metadata: `[("authorization", f"Bearer {token}")]`.
- Two JWT cache implementations: `JWTCache` (standard) and `JWTCacheOptimized` (for Kafka consumer).

### Error handling
- Wrap all gRPC calls in `execute_grpc_call()` from `relations_api_replicator.py`.
- `GRPCError` wrapper extracts `code`, `reason`, `message`, `metadata` from gRPC errors.
- `FAILED_PRECONDITION` = invalid fencing token (partition reassigned) -- always fatal.

### Fencing / distributed locking
- Consumer acquires lock via `RelationsApiReplicator.acquire_lock(lock_id)` on partition assignment.
- Lock ID format: `"{consumer_group_id}/{partition_number}"`.
- All write/delete calls include `FencingCheck(lock_id, lock_token)` protobuf.
- Lock acquisition uses its own retry with exponential backoff (separate from message retry).

## 5. External HTTP Services

### BOP (Principal Proxy) -- `management.principal.proxy.PrincipalProxy`
- Singleton pattern. Connection info from env vars (`PRINCIPAL_PROXY_SERVICE_*`).
- Auth headers: `x-rh-insights-env`, `x-rh-clientid`, `x-rh-apitoken`.
- `BYPASS_BOP_VERIFICATION=True` returns DB principals with mock data (dev/ephemeral).
- Prometheus metrics: `rbac_proxy_request_processing_seconds` (histogram), `bop_request_status_total` (counter by method+status).

### IT Service -- `management.principal.it_service.ITService`
- Singleton (`__new__` pattern). Connection from `settings.IT_SERVICE_*`.
- Paginates with `first`/`max` params until empty response.
- `IT_BYPASS_IT_CALLS=True` returns mock service accounts (dev/ephemeral).
- Raises `UnexpectedStatusCodeFromITError` on non-success, re-raises `ConnectionError`/`Timeout`.
- Metrics: `it_request_all_service_accounts_processing_seconds`, `it_request_status_total`, `it_request_error`.

### UMB (Unified Message Bus) -- `management.principal.cleaner`
- STOMP protocol via `stompest` library over SSL.
- Celery-scheduled task (`principal_cleanup_via_umb`) polls queue with 15-second read timeout.
- Individual message acknowledgment (`ACK_CLIENT_INDIVIDUAL`).

## 6. Celery Task Patterns

- All tasks use `@shared_task` decorator (not `@app.task`).
- Tasks are thin wrappers calling management commands or utility functions.
- Beat schedule in `rbac/celery.py`: cross-account cleanup (daily), Redis health (30s), principal cleanup (configurable).
- Trigger async tasks from views via `.delay()` -- never `.apply_async()` in this codebase.
- Task autodiscovery via `app.autodiscover_tasks()`.

## 7. Prometheus Metrics Conventions

- Use `Counter` for event counts with labels for status/type.
- Use `Histogram` for timing with `.time()` decorator or context manager.
- Use `Gauge` for state (consumer running, start time).
- Naming: `rbac_kafka_consumer_*`, `rbac_proxy_*`, `it_request_*`, `relations_replication_event_total`.
- Cap label cardinality (e.g., `min(attempt + 1, 10)` for retry attempts).

## 8. Read-Your-Writes Support

- After processing `create_workspace` events, send PostgreSQL `NOTIFY` on `READ_YOUR_WRITES_CHANNEL`.
- NOTIFY payload is the `resource_id` (workspace UUID).
- NOTIFY is best-effort -- failure is logged but does not fail message processing.
- Controlled by `READ_YOUR_WRITES_WORKSPACE_ENABLED` and `READ_YOUR_WRITES_TIMEOUT_SECONDS`.

## 9. Testing Integration Code

- `OutboxReplicator` accepts an `OutboxLog` protocol for dependency injection.
- Use `InMemoryLog` in tests instead of `OutboxWAL` to avoid DB writes.
- Use `FakeKafkaProducer` (auto-selected in dev) or mock `RBACProducer.get_producer()`.
- `RelationTuple` is the domain type for tuples -- use `as_message()` to convert to protobuf, `to_dict()` for JSON.
- Use `RelationTuple.validate_message()` to assert protobuf round-trip correctness.
