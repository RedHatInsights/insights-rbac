# Database Guidelines for insights-rbac

## 1. Multi-Tenancy Architecture

This repo uses a **single-schema, FK-based multi-tenancy** model (NOT django-tenants schema isolation). All tenant-scoped models inherit from `TenantAwareModel`, which adds a `tenant = ForeignKey(Tenant, on_delete=CASCADE)`.

**Rules:**
- Every new domain model MUST inherit from `api.models.TenantAwareModel` unless it is explicitly tenant-independent (like `ExtTenant`, `Outbox`).
- Every query on tenant-scoped data MUST filter by `tenant`. Use `filter_queryset_by_tenant(queryset, tenant)` from `management.utils` or filter explicitly.
- The `public` tenant (name `"public"`) holds system/seeded data shared across all orgs. Retrieve it via `Tenant._get_public_tenant()` or `Tenant.objects.get(tenant_name="public")`.
- Queries that need both tenant-specific and system data must filter by `tenant__in=[request.tenant, public_tenant]` or use `Q(tenant=tenant) | Q(tenant__tenant_name="public")`.

## 2. Model Field Conventions

### UUID Fields
- **V1 models** (Role, Group, Principal, Policy): use `uuid = UUIDField(default=uuid4, editable=False, unique=True)` as a separate field (NOT the primary key). The auto-increment `id` remains the PK.
- **V2 models** (RoleV2, RoleBinding, Workspace): use `uuid7` from `uuid_utils.compat`. Workspace uses `id = UUIDField(primary_key=True, default=uuid.uuid7)`.
- **New models** SHOULD use `uuid7` for time-sortable UUIDs, following the V2 convention.

### Timestamp Fields
- `created = DateTimeField(default=timezone.now)` -- never use `auto_now_add`.
- `modified = AutoDateTimeField(default=timezone.now)` -- this is a custom field in `management.rbac_fields` that sets `timezone.now()` on every `pre_save`. Do NOT use `auto_now`.

### Naming
- Boolean flags: `system`, `platform_default`, `admin_default` (no `is_` prefix).
- Type discriminators: use `TextChoices` enum with `db_index=True` (see `Principal.Types`, `Workspace.Types`, `RoleV2.Types`).

## 3. Model Constraints and Indexes

### UniqueConstraints (preferred over `unique_together`)
All uniqueness rules use `models.UniqueConstraint` with descriptive `name`:
```python
# Pattern: "unique <thing> per <scope>"
UniqueConstraint(fields=["name", "tenant"], name="unique role name per tenant")
UniqueConstraint(fields=["username", "tenant"], name="unique principal username per tenant")
```
- Conditional constraints use `condition=Q(...)`. Example: Workspace enforces uniqueness of root/default types per tenant.
- Case-insensitive uniqueness uses `Upper()` function in constraints.

### CheckConstraints
Used for data integrity beyond nullability:
```python
CheckConstraint(condition=~Q(source=""), name="role binding principal has source")
```

### Indexes
- Add composite indexes for common query patterns, especially those involving `tenant` as a prefix:
```python
models.Index(fields=["tenant", "created"])
```
- Use `db_index=True` on fields used for filtering: `type`, `service_account_id`, `user_id`, `org_id`.

## 4. Model Save Overrides and Validation

Several models override `save()` for domain logic:
- `Principal.save()`: lowercases `username`.
- `Role.save()`: populates `display_name` from `name` if empty.
- `Permission.save()`: splits `permission` string into `application`, `resource_type`, `verb`.
- `Workspace.save()`: calls `self.full_clean()` before saving (enforces `clean()` validation).
- `RoleV2.save()`: calls `self.full_clean()` before saving.

**Rule:** When a model has business validation, call `full_clean()` in `save()`. New V2 models follow this pattern.

## 5. Proxy Models for Type Discrimination

`RoleV2` uses proxy models (`CustomRoleV2`, `SeededRoleV2`, `PlatformRoleV2`) with:
- `TypedRoleV2Manager` that auto-filters by `type`.
- `TypeValidatedRoleV2Mixin` that validates/enforces the type on `__init__` and `save`.

**Rule:** When querying specific role types, use the proxy model's manager (e.g., `CustomRoleV2.objects`) rather than filtering `RoleV2.objects.filter(type=...)` manually.

## 6. QuerySet and Manager Patterns

### Custom QuerySets
- `FilterQuerySet` (api/models.py): provides `public_tenant_only()` for system data.
- `RoleBindingQuerySet`: domain methods like `for_tenant()`, `for_subject()`, `orphaned()`, `with_resource_names()`.
- `RoleV2QuerySet`: `assignable()`, `for_tenant()`, `with_fields()`, `named()`.
- `WorkspaceQuerySet`/`WorkspaceManager`: `root()`, `default()`, `built_in()`, `standard()`, `descendant_ids_with_parents()`.

**Rule:** Add query logic to custom QuerySets, not to views or serializers. Attach via `.as_manager()` or a custom Manager that delegates to the QuerySet.

### Eager Loading
- Use `select_related` for FK traversals and `prefetch_related` for M2M/reverse FK.
- `RoleBindingQuerySet.for_tenant()` demonstrates annotating cross-relation fields for cursor pagination compatibility.
- `RoleV2QuerySet.with_fields()` conditionally applies eager loading based on requested response fields.

## 7. Transaction and Locking Patterns

### SERIALIZABLE Transactions (V2 services)
V2 service methods use `pgtransaction.atomic(isolation_level=SERIALIZABLE)` via the `@atomic` decorator or `atomic_block()` context manager from `management.atomic_transactions`.

**Rules:**
- V2 service methods that modify data MUST use the `@atomic` decorator from `management.atomic_transactions`.
- The `ATOMIC_RETRY_DISABLED` setting disables serializable retries in tests; never set it in production.
- V1 views use plain `transaction.atomic()`.

### Locking
- `select_for_update()` is used before mutating roles, bindings, and tenant mappings.
- `select_for_update(of=["self"])` is used when only the target row should be locked.
- `FOR SHARE` (raw SQL) is used in `v2_activation.py` for read-path concurrency -- Django ORM has no FOR SHARE support.
- `pg_try_advisory_xact_lock` is used for singleton job exclusion (principal cleanup).

## 8. Raw SQL Usage

Raw SQL is acceptable ONLY for PostgreSQL-specific features not available in the ORM:
- **Recursive CTEs** for workspace hierarchy (ancestors, descendants, depth).
- **Advisory locks** (`pg_try_advisory_xact_lock`).
- **`FOR SHARE`** row-level locking.
- **`LISTEN`/`NOTIFY`** for read-your-writes consistency.

**Rules:**
- Always use parameterized queries (`%s` placeholders). Never interpolate values into SQL strings.
- Prefer `Workspace.objects.filter(id__in=RawSQL(sql, params))` over raw cursor when the result feeds back into ORM queries.
- Use `connection.cursor()` only when you need scalar results (e.g., `MAX(depth)`).

## 9. Outbox Pattern (CDC via Debezium)

The `Outbox` model (`management.debezium.model`) implements the Debezium Outbox Event Router pattern:

**How it works:**
1. `OutboxReplicator.replicate()` creates an `Outbox` row with `aggregatetype`, `aggregateid`, `event_type`, and JSON `payload`.
2. The row is immediately saved then deleted (`force_insert=True` then `delete()`). Debezium captures the INSERT from the WAL.
3. This MUST happen inside the same transaction as the domain mutation to guarantee atomicity.

**Rules:**
- Never read from the Outbox table; rows are ephemeral (insert + delete in the same call).
- The `event_type` field uses `db_column="type"` mapping.
- `ReplicationEvent` carries `add` and `remove` lists of `RelationTuple`. Empty events are logged as warnings and skipped.
- Use `transaction.on_commit()` for metrics counters, not for the outbox write itself.

## 10. Signal Handlers for Cache Invalidation

Models connect `post_save`, `pre_delete`, and `m2m_changed` signals to invalidate `AccessCache` (Redis) and send Kafka sync messages. These are conditionally connected based on `settings.ACCESS_CACHE_CONNECT_SIGNALS` and `settings.KAFKA_ENABLED`.

**Rule:** If adding a new model that affects access policy resolution, add signal handlers following the existing pattern in the model file, not in views.

## 11. Migration Safety

With 82 migrations and a production PostgreSQL database:
- Avoid `RunSQL` for schema changes; prefer Django migration operations.
- Data migrations (`RunPython`) must be idempotent and handle missing data gracefully.
- Add indexes via `AddIndex` operations (not inline on fields), as shown in migration `0078`.
- Never add non-nullable columns without a default in a single migration; use a two-step approach (add nullable, backfill, alter to non-nullable).
- Constraint names must be stable and descriptive (Django auto-generates names otherwise).

## 12. Cross-Account Requests

`CrossAccountRequest` uses `request_id` as `primary_key=True` (UUIDv4), unlike other models. It is NOT tenant-aware (no FK to Tenant). It references roles via an M2M through table `RequestsRoles`.

## 13. V1 vs V2 Model Coexistence

The codebase maintains parallel V1 and V2 models:
- V1: `Role`, `Group`, `Policy`, `Access`, `ResourceDefinition`, `BindingMapping`
- V2: `RoleV2` (with proxy subtypes), `RoleBinding`, `RoleBindingGroup`, `RoleBindingPrincipal`, `Workspace`, `TenantMapping`

`RoleV2.v1_source` FK links V2 seeded roles to their V1 system role origins. `BindingMapping` bridges V1 roles to V2 role bindings during migration.

**Rule:** New feature work should target V2 models. V1 models are maintained for backward compatibility but should not gain new features.
