# AI Agent Guidance for insights-rbac

This file provides cross-cutting guidance for any AI agent (Claude Code, Cursor, CodeRabbit, etc.) working in this repository. Domain-specific rules live in the guideline files indexed below -- this file links to them and covers conventions that span multiple domains.

insights-rbac is a Django REST Framework microservice providing Role-Based Access Control for console.redhat.com. Python 3.12, PostgreSQL 16, Redis, Celery.

## Domain Guidelines Index

| File | Scope |
|------|-------|
| [`docs/security-guidelines.md`](docs/security-guidelines.md) | Authentication layers (identity header, PSK, JWT, internal), authorization patterns (v1/v2), tenant isolation, input validation, secrets |
| [`docs/performance-guidelines.md`](docs/performance-guidelines.md) | Redis caching hierarchy, query optimization (eager loading, N+1 prevention, annotations), transaction management (SERIALIZABLE isolation), pagination strategies, Celery tasks |
| [`docs/error-handling-guidelines.md`](docs/error-handling-guidelines.md) | Global exception handler, v1 vs v2 error formats (RFC 7807), custom exception classes, where to raise what (service vs serializer vs view), logging conventions |
| [`docs/api-contracts-guidelines.md`](docs/api-contracts-guidelines.md) | Dual API versions (v1/v2), URL routing, ViewSet patterns, pagination, serializer conventions (input/output split), field selection, OpenAPI/TypeSpec |
| [`docs/database-guidelines.md`](docs/database-guidelines.md) | Multi-tenancy (TenantAwareModel), UUID conventions (v7 for new models), model patterns, constraints/indexes, workspace hierarchy (recursive SQL), Debezium outbox, migrations |
| [`docs/testing-guidelines.md`](docs/testing-guidelines.md) | Test runner (dotted paths), base classes (IdentityRequest), v2 test setup (feature flag, URL reload, Kessel mocks), relation replication testing, mocking patterns, coverage |
| [`docs/integration-guidelines.md`](docs/integration-guidelines.md) | Kessel Relations/Inventory (gRPC), Kafka producer/consumer, Debezium CDC, BOP, IT Service, UMB, notifications, feature flags, Prometheus metrics |

## Context Index

| File | Purpose |
|------|---------|
| `CLAUDE.md` | Claude Code-specific commands and behavioral preferences |
| `CONTRIBUTING.md` | Contribution workflow, code style, PR format |
| `docs/source/specs/v2/openapi.yaml` | V2 API specification (generated) |
| `docs/source/specs/typespec/main.tsp` | TypeSpec source -- the contract for v2 API changes |
| `Makefile` | Build, test, migration, and Docker commands |
| `tox.ini` | Test environments, linting config, env vars for tests |
| `.pre-commit-config.yaml` | Pre-commit hooks: flake8, black, trailing whitespace, django-upgrade, openapi-spec-validator |

## Key Conventions

### Code Patterns

- **Multi-tenancy**: All business models inherit `TenantAwareModel` (ForeignKey to Tenant). Always filter queries by `request.tenant`. Never return cross-tenant data. See `docs/database-guidelines.md` and `docs/security-guidelines.md` for full rules.
- **Service layer**: Business logic goes in `service.py` files, not views or serializers. Services raise domain exceptions (plain Python, not DRF). Serializers catch domain exceptions and convert to `serializers.ValidationError`.
- **V2 base class**: All v2 views must extend `BaseV2ViewSet` from `rbac/management/base_viewsets.py`. Write operations must also use `AtomicOperationsMixin` -- override `perform_atomic_create`/`perform_atomic_update`/`perform_atomic_destroy`, never override `create`/`update`/`destroy` directly.
- **Error format**: V2 APIs use RFC 7807 Problem JSON via `ProblemJSONRenderer`. Build error responses with `v2response_error_from_errors()`. V1 uses flat `errors` arrays.
- **Two-layer access control (v2)**: Every v2 endpoint needs both a `*AccessPermission` class (endpoint-level 403) and a `*AccessFilterBackend` (queryset-level filtering). Detail views return 404 for inaccessible objects to prevent existence leakage.
- **Feature flag gating**: V2 routes only register when `V2_APIS_ENABLED=True`. Never register v2 routes unconditionally. V2 writes additionally require `V2WriteRequiresWorkspacesEnabled`.

### Testing

- **Test runner**: Django requires dotted module paths, not file paths. `pipenv run tox -e py312-fast` for fast iteration (no coverage). `pipenv run tox -e py312` for full coverage.
- **Base classes**: Use `IdentityRequest` from `tests/identity_request.py` (provides tenant, identity headers, request context). Use `TransactionalIdentityRequest` for tests involving `pgtransaction.atomic(retry=...)` or `select_for_update`.
- **V2 test setup**: Apply `@override_settings(V2_APIS_ENABLED=True)`, reload URLs with `reload(urls)` + `clear_url_caches()` in setUp, bootstrap tenant with `bootstrap_tenant_for_v2_test()`, mock Kessel permission checks.
- **Parallel execution**: Tests run with `--parallel` and `--failfast`. Clean up created objects in `tearDown` since tests share the database.
- **Mocking**: Always mock Kafka (`MOCK_KAFKA=True` is set in tox.ini), Kessel Inventory, and outbox replicator. Never mock Django ORM queries, serializer validation, or URL routing.

### Code Style and Formatting

- **Black**: line length 119, target py312. Run `pipenv run black -t py312 -l 119 rbac tests`.
- **Flake8**: max line length 120, ignores D106/W503/C901, excludes migrations.
- **Pre-commit hooks**: flake8, black (check mode), trailing-whitespace, end-of-file-fixer, debug-statements, django-upgrade (target 5.2), openapi-spec-validator.
- **Import order**: PyCharm style (`flake8-import-order`), application imports are `rbac` and `api`.

### Commit Messages

Conventional commits format: `type(scope): short description in lowercase`. Types: `fix`, `feat`, `test`, `refactor`, `style`, `docs`, `chore`. Scopes are optional (e.g., `roles`, `permissions`, `deps`). Do NOT include `Co-Authored-By` lines.

### What NOT to Do

- Do not modify v1 API behavior -- it is stable and widely consumed.
- Do not add v2 routes without checking the `V2_APIS_ENABLED` flag.
- Do not put business logic in serializers or views -- use the service layer.
- Do not skip pre-commit hooks or bypass formatting.
- Do not raise DRF exceptions from services -- raise domain exceptions instead.
- Do not override `create`/`update`/`destroy` on v2 viewsets using `AtomicOperationsMixin` -- override `perform_atomic_*` methods.
- Do not expose integer primary keys in APIs -- use UUIDs.
- Do not perform outbox writes or external calls outside a transaction boundary.
- Do not return 403 for inaccessible v2 detail resources -- return 404 to prevent existence leakage.

### Database Migrations

- Generate: `make make-migrations`
- Apply: `make run-migrations`
- Reset: `make reinitdb` (drops and recreates)
- Migrations are excluded from linting and coverage.
- Always test migrations against real PostgreSQL -- SQLite is not used.
- New models should use UUID v7 as primary key (`uuid_utils.compat.uuid7`).

### Local Development

```bash
# Docker full stack (port 9080 + postgres + redis + celery)
make docker-up

# Local python (port 8000, needs Docker DB on port 15432)
make start-db
make run-migrations
make serve
```
