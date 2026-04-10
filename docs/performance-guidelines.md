# insights-rbac Performance Guidelines

## 1. Redis Access Cache

**Cache architecture**: This repo uses a custom Redis caching layer (`management/cache.py`) with `BlockingConnectionPool`. There are five cache types: `AccessCache` (per-principal per-app access policy), `TenantCache`, `PrincipalCache`, `JWKSCache`, and `JWTCache`.

- **Always invalidate cache when modifying Role, Access, ResourceDefinition, Group, or Group membership.** Django signals handle this automatically for models with `ACCESS_CACHE_CONNECT_SIGNALS=True`. If you bypass signals (e.g., `bulk_update`, raw SQL), you must manually call `AccessCache(tenant.org_id).delete_policy(principal.uuid)` or `delete_all_policies_for_tenant()`.
- **Skip cache purging for the public tenant.** Use `skip_purging_cache_for_public_tenant(tenant)` before any cache invalidation. The public tenant holds system/seeded objects shared across orgs; it has no per-user cache entries.
- **Use `JWTCacheOptimized` instead of `JWTCache` in high-throughput paths** (e.g., Kafka consumers). It skips the `redis_health_check()` call on every read, which does a `PING` round-trip.
- **Batch cache deletions.** Use `scan_iter` with `count=BATCH_DELETE_SIZE` (1000) and pipeline deletes, as done in `delete_all_policies_for_tenant()`. Never use `KEYS *` in production.
- **Cache key format convention**: `rbac::<type>::<scope>=<value>`. Examples: `rbac::policy::tenant=X::user=Y`, `rbac::principal::org_id::username`.
- **Cache lifetimes**: access policy = `ACCESS_CACHE_LIFETIME` (600s default), principals = `PRINCIPAL_CACHE_LIFETIME` (3600s default), JWKS = `IT_TOKEN_JKWS_CACHE_LIFETIME` (28800s default).

## 2. Database Query Optimization

- **Always use `prefetch_related` for traversals through ManyToMany or reverse FK relations.** The codebase follows this pattern consistently:
  - Roles: `prefetch_related("access", "ext_relation", "access__permission")`
  - Groups: annotate with `principalCount` and `policyCount` using `Count(..., distinct=True)`
  - RoleBindings: `select_related("role").prefetch_related("role__children", "group_entries__group")`
- **Use field-driven eager loading in V2 querysets.** See `RoleV2QuerySet.with_fields()` -- only `select_related("tenant")` when `org_id` is requested, only `prefetch_related("permissions")` when `permissions` is requested. Follow this pattern for new V2 querysets.
- **Use `.values()` and `.iterator()` for large data processing.** See `workspace/service.py` which queries `ResourceDefinition.objects.filter(...).values(...)` and groups with `.iterator()` to avoid loading full model instances into memory.
- **Use `bulk_create` / `bulk_update` for batch operations.** The repo uses this in tenant bootstrapping, role binding creation, and principal updates. Always prefer these over loops of `.save()`.
- **Filter by tenant explicitly.** All models inherit `TenantAwareModel` with a FK to `Tenant`. Use `filter_queryset_by_tenant(queryset, request.tenant)` or `.filter(tenant=tenant)`. The public tenant pattern is: `.filter(tenant__in=[request.tenant, public_tenant])`.

## 3. Transaction Isolation and Concurrency

- **V2 write operations use SERIALIZABLE isolation with automatic retry.** This is the core concurrency pattern:
  - **Views**: Use `AtomicOperationsMixin` (in `v2_mixins.py`). Override `perform_atomic_create/update/destroy` hooks, never override `create/update/destroy` directly. The mixin wraps operations in `pgtransaction.atomic(isolation_level=SERIALIZABLE, retry=3)`.
  - **Services**: Use `@atomic` decorator or `atomic_block()` context manager from `management/atomic_transactions.py`. These use `pgtransaction.SERIALIZABLE`.
  - **Workspace views**: Use `@pgtransaction.atomic(isolation_level=pgtransaction.SERIALIZABLE, retry=3)` directly.
- **Handle `OperationalError` with `SerializationFailure` and `DeadlockDetected`.** Return 409 for serialization failures, 500 for deadlocks. See `_handle_concurrency_error` in `v2_mixins.py`.
- **Use `select_for_update()` when modifying rows that may be concurrently accessed.** The codebase uses `select_for_update(of=["self"])` to lock specific tables. Always pair with `transaction.atomic()`.
- **Disable serializable isolation in tests.** Set `ATOMIC_RETRY_DISABLED=True` in test settings. The `is_atomic_disabled()` check falls back to plain `transaction.atomic()`.

## 4. Outbox Pattern and Dual Write

- **All relation replication goes through the Outbox table** (`management/debezium/model.py`). The `OutboxReplicator` writes to the Outbox, then immediately deletes the row. Debezium captures the change from the WAL (write-ahead log). This is the Debezium outbox pattern.
- **Outbox writes must happen inside the same transaction as the data change.** This ensures atomicity. The outbox row is saved via `force_insert=True` then deleted immediately.
- **Use `transaction.on_commit()` for Prometheus counter increments** related to replication events. This avoids counting events for rolled-back transactions.
- **Never produce duplicate tuples in a replication event.** The `OutboxReplicator._check_for_duplicate_relationships()` raises `ValueError` if duplicates are found. Fix the tuple generation logic rather than deduplicating.
- **Partition key**: All events currently use `PartitionKey.byEnvironment()` which serializes all events globally.

## 5. Celery Task Patterns

- **Celery beat schedule** (in `rbac/celery.py`):
  - Redis health check: every 30 seconds (`run_redis_cache_health`).
  - Cross-account cleanup: daily at midnight.
  - Principal cleanup: every 60s via UMB, or weekly (7th/14th/21st/28th) via BOP.
- **All Celery tasks are `@shared_task`** and defined in `management/tasks.py`. They delegate to management commands or service functions.
- **Heavy migration/cleanup tasks must be Celery tasks**, not inline request processing. Examples: `migrate_data_in_worker`, `cleanup_tenant_orphan_bindings_in_worker`.
- **Use `call_command()` inside Celery tasks** to reuse management command logic.

## 6. Prometheus Metrics

- **Naming convention**: `rbac_<component>_<metric>_<unit>` or `<domain>_<metric>_<unit>`.
- **Always use labels for dimensionality**: status (success/failure), message_type, result.
- **Define metrics at module level**, not inside functions. Import from `prometheus_client`.
- **Use `Histogram` for latencies**, `Counter` for event counts, `Gauge` for state (e.g., consumer running).
- **Custom histogram buckets**: Generate based on configuration values when appropriate (see `_generate_ryw_histogram_buckets`).
- **Celery worker exposes metrics** via `prometheus_client.start_http_server` on `metricsPort` at worker startup.

## 7. Multi-Tenant Query Safety

- **Every data model extends `TenantAwareModel`** which has a FK to `api.models.Tenant`. Queries must always scope to the request tenant.
- **Public tenant pattern**: System/seeded roles and default groups live in the public tenant (`tenant_name="public"`). When listing roles, always include public tenant: `.filter(tenant__in=[request.tenant, public_tenant])`.
- **`Tenant._get_public_tenant()`** caches the public tenant instance in a class variable. Use it for repeated access.
- **Never leak data across tenants.** All querysets must filter by tenant. The `FilterQuerySet.public_tenant_only()` method returns only system objects from the public tenant.

## 8. Middleware Performance

- **`should_load_user_permissions` optimization** (`middleware.py`): Skip permission loading for org admins (they have full access). For the `/access/` endpoint, only load permissions when both `username` and `application` query params are present.
- **Avoid redundant BOP/proxy calls.** The `get_principal` function checks the `PrincipalCache` before querying the database, and caches on miss. The `BYPASS_BOP_VERIFICATION` setting skips external user verification entirely.

## 9. Read-Your-Writes Consistency

- The workspace service implements read-your-writes using PostgreSQL `LISTEN`/`NOTIFY` (`workspace/service.py`). After a write commits, a `transaction.on_commit` callback waits for a notification on `READ_YOUR_WRITES_CHANNEL`.
- **Timeout is configurable** via `READ_YOUR_WRITES_TIMEOUT_SECONDS` (default 10s).
- **Metrics track both success and timeout** via `ryw_wait_total` and `ryw_wait_duration_seconds`.

## 10. Anti-Patterns to Avoid

- **Never call `redis_health_check()` on every cache read in hot paths.** It does a `PING` round-trip. Use `JWTCacheOptimized` pattern instead.
- **Never use `KEYS *` or unbounded `scan_iter`** without `count` parameter.
- **Never override `create/update/destroy` on V2 ViewSets** that use `AtomicOperationsMixin`. Override the `perform_atomic_*` hooks instead.
- **Never write to Outbox outside a transaction.** The outbox pattern requires the data change and outbox write to be in the same transaction for atomicity.
- **Never skip tenant filtering.** This is the most critical security and performance constraint in the codebase.
