# insights-rbac Testing Guidelines

## Test Runner and Configuration

- Tests use **Django's built-in test runner** (`manage.py test`), not pytest. Do not add pytest-style fixtures or `conftest.py` files.
- Run tests via tox: `tox -e py312` (with coverage) or `tox -e py312-fast` (without coverage). Pass specific test paths: `tox -e py312-fast -- tests/management/role/test_v2_view.py`.
- Tests run in **parallel** (`--parallel 4` with `--failfast`). Ensure tests are isolated and do not depend on execution order.
- Linting: `tox -e lint` runs flake8 and `black --check -t py312 -l 119`. Format with `black -t py312 -l 119 rbac tests`.

## Test File Organization

- All tests live under `tests/`, mirroring the `rbac/` source structure: `tests/management/role/`, `tests/api/cross_access/`, `tests/internal/`, etc.
- Name test files `test_<subject>.py` (e.g., `test_view.py`, `test_model.py`, `test_service.py`, `test_serializer.py`).
- V2 API tests use the prefix `test_v2_` (e.g., `test_v2_view.py`, `test_v2_service.py`, `test_v2_model.py`).
- Every test directory must contain an `__init__.py` file.

## Base Classes: IdentityRequest

- **Most test classes inherit from `IdentityRequest`** (from `tests.identity_request`), not plain `TestCase`. This is the standard base for any test needing a tenant, user identity, or request context.
- `IdentityRequest` extends `TestCase` and provides: `self.tenant`, `self.headers`, `self.customer_data`, `self.user_data`, `self.request_context`, and helper methods `_create_request_context()`, `_create_customer_data()`, `_create_user_data()`.
- Use `TransactionalIdentityRequest` (wraps `TransactionTestCase`) only when you need real DB transactions (e.g., testing deadlock retry, concurrent access, or signals that require committed data).
- For tests that do not need identity/tenant context (pure unit tests), use plain `django.test.TestCase`.

## Multi-Tenancy in Tests

- `IdentityRequest.setUpClass()` creates `self.tenant` with a random `org_id` via Faker. The tenant is saved to DB and torn down in `tearDownClass`.
- System roles and permissions belong to the **public tenant**: `Tenant.objects.get(tenant_name="public")`. Always use the public tenant for system-level objects.
- Custom roles, groups, principals, and policies belong to a specific tenant. Always pass `tenant=self.tenant` when creating these.
- To test cross-tenant isolation, create a second tenant in `setUp()` with a distinct `org_id`.

## V2 API Test Setup

- V2 endpoint tests require `@override_settings(V2_APIS_ENABLED=True, V2_EDIT_API_ENABLED=True)` on the class.
- V2 tests must call `bootstrap_tenant_for_v2_test(self.tenant)` in `setUp()` to initialize V2 workspaces and tenant mapping.
- V2 tests must reload URL configuration: `reload(urls)` then `clear_url_caches()` in `setUp()`.
- Use `reverse("v2_management:roles-detail", kwargs={"uuid": str(uuid)})` for V2 URLs and `reverse("v1_management:role-list")` for V1 URLs.

## API Endpoint Testing Pattern

```python
from rest_framework.test import APIClient
from rest_framework import status

def setUp(self):
    super().setUp()
    self.client = APIClient()

def test_example(self):
    url = reverse("v1_management:role-list")
    response = self.client.get(url, **self.headers)  # self.headers from IdentityRequest
    self.assertEqual(response.status_code, status.HTTP_200_OK)
    data = response.json()
```

- Always pass `**self.headers` (or `**self.test_headers` for alternate tenants) to authenticate requests.
- Use `self.client.get/post/put/patch/delete(url, data, format="json", **self.headers)`.
- Test both success and error paths (401, 403, 404, 400).

## Relation Replication and Dual Write Testing

- Use `InMemoryTuples` and `InMemoryRelationReplicator` (from `migration_tool.in_memory_tuples`) to capture relation tuples without hitting Kessel.
- Use `NoopReplicator` when you do not care about replication side effects.
- Mock `OutboxReplicator` methods when testing code paths that use the production replicator: `@patch("management.relation_replicator.outbox_replicator.OutboxReplicator._save_replication_event")` or `@patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")`.
- For dual-write tests, extend `DualWriteTestCase` (from `tests.management.role.test_dual_write`). Use its `given_*` methods (e.g., `given_v1_role`, `given_group`, `given_roles_assigned_to_group`) to set up state and `expect_*` / consistency assertion helpers to verify.
- Use `RbacFixture` for creating test entities (tenants, roles, groups, principals) with proper V2 bootstrapping.

## Consistency Assertions

- After dual-write operations, call `assert_v1_v2_tuples_fully_consistent(self, self.tuples)` (from `tests.util`) to verify V1 DB state matches V2 tuples.
- This runs both `assert_v1_v2_locally_consistent` (DB-only checks) and `assert_v2_tuples_consistent` (tuple checks against `InMemoryTuples`).

## Mocking Patterns

- Use `unittest.mock.patch` as decorator or context manager. Prefer `@patch("full.module.path.ClassName.method")`.
- For Kafka: `@patch("core.kafka.RBACProducer.send_kafka_message")`. Use `copy_call_args(mock)` from `tests.core.test_kafka` when you need to capture mutable arguments before they change.
- For Kessel access checks: patch `management.permissions.role_v2_access.get_kessel_principal_id` and `WorkspaceInventoryAccessChecker.check_resource_access`.
- Use `self.enterContext(patch(...))` for patches that should last the entire test method (available in Django 4.2+ TestCase).
- Use `@override_settings(KEY=VALUE)` on classes or methods to toggle feature flags (e.g., `V2_APIS_ENABLED`, `REPLICATION_TO_RELATION_ENABLED`, `ATOMIC_RETRY_DISABLED`).

## Cache Isolation

- `BaseIdentityRequest.tearDown()` clears `PRINCIPAL_CACHE` (Redis or in-memory). If your test manipulates principals or caches, ensure tearDown clears them: `PRINCIPAL_CACHE.delete_all_principals_for_tenant(self.tenant.org_id)`.
- For `TenantCache`, explicitly delete cached tenants: `TenantCache().delete_tenant(org_id)`.
- Clear `GlobalPolicyIdService.clear_shared()` in V2 tests to avoid cross-test contamination (already done by `bootstrap_tenant_for_v2_test`).

## Test Data Creation

- Use `Faker` (available as `self.fake` on `IdentityRequest`) for generating random test data. Usernames include a UUID suffix for cache isolation.
- Create request contexts for different user types: `self._create_request_context(customer_data, user_data, is_org_admin=True/False, is_internal=True/False, service_account_data=...)`.
- Permissions follow the format `"app:resource:verb"` (e.g., `"inventory:hosts:read"`).

## Settings Commonly Overridden in Tests

| Setting | Purpose |
|---------|---------|
| `V2_APIS_ENABLED=True` | Enable V2 API endpoints |
| `V2_EDIT_API_ENABLED=True` | Enable V2 write operations |
| `REPLICATION_TO_RELATION_ENABLED=True` | Enable dual-write (set by default on IdentityRequest) |
| `ATOMIC_RETRY_DISABLED=True` | Disable retry logic in tests |
| `ROOT_SCOPE_PERMISSIONS` | Override permission scope config |
| `TENANT_SCOPE_PERMISSIONS` | Override permission scope config |
| `V2_MIGRATION_APP_EXCLUDE_LIST` | Exclude apps from V2 migration |
| `PRINCIPAL_USER_DOMAIN="redhat"` | Set principal domain (set by default on IdentityRequest) |

## Test Naming and Documentation

- Test methods: `test_<action>_<condition>_<expected_result>` (e.g., `test_retrieve_role_not_found`, `test_create_group_success`).
- Every test class and test method should have a docstring describing what is being tested.

## What NOT to Do

- Do not use pytest fixtures, parametrize, or conftest.py -- this project uses Django's unittest-based test framework.
- Do not make real HTTP calls to external services (Kessel, IT service, Kafka). Always mock external dependencies.
- Do not use `TransactionTestCase` unless you genuinely need transaction semantics; it is significantly slower because it flushes the database between tests instead of using rollback.
- Do not hardcode org_id or account_id values that might collide with other parallel tests. Use Faker-generated values from `IdentityRequest`.
- Do not skip `super().setUp()` / `super().tearDown()` calls -- the base class manages tenant lifecycle and cache cleanup.
