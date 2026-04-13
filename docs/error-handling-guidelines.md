# Error Handling Guidelines for insights-rbac

## 1. API Version-Aware Exception Handling

This repo uses a version-dispatching exception handler registered as `EXCEPTION_HANDLER` in DRF settings. The router is `exception_version_handler` in `rbac/api/common/exception_handler.py`.

- **V1 endpoints** (`/api/v1/`): errors are returned as `{"errors": [{"detail": "...", "source": "...", "status": "400"}]}`.
- **V2 endpoints** (`/api/v2/`): errors use **RFC 7807 Problem Details** format via `v2response_error_from_errors()`: `{"status": 400, "title": "The request payload contains invalid syntax.", "detail": "...", "errors": [{"message": "...", "field": "..."}]}`. V2 responses must set `content_type="application/problem+json"`.

**Rule**: In V1/V2 views, avoid returning raw DRF error dicts. Let the exception handler format responses, or use `v2response_error_from_errors()` for manual V2 error responses.

## 2. Custom Exception Hierarchy

Domain exceptions live in dedicated files per module. Use these instead of generic Python exceptions:

### Shared (`management/exceptions.py`)
- `RequiredFieldError(field_name)` -- missing required field (400)
- `InvalidFieldError(field, message)` -- field validation failure (400)
- `NotFoundError(resource_type, resource_id)` -- resource not found (404)

### Role domain (`management/role/v2_exceptions.py`)
- `RoleV2Error` -- base class for role errors
- `RoleAlreadyExistsError(name)` -- duplicate role name (handled as IntegrityError/400)
- `PermissionsNotFoundError(missing_permissions)` -- invalid permissions (400)
- `RoleDatabaseError(message)` -- unexpected DB error (500)
- `InvalidRolePermissionsError(message)` -- malformed permission data (400)
- `RolesNotFoundError(uuids)` -- roles not found (converted to 404)
- `CustomRoleRequiredError(message)` -- operation requires custom role (500)

### Subject domain (`management/subject/exceptions.py`)
- `SubjectError` -- base class
- `UnsupportedSubjectTypeError(subject_type)` -- invalid subject type

### Permission domain (`management/permission/exceptions.py`)
- `PermissionError` -- base class
- `InvalidPermissionDataError(message)` -- malformed permission data

### Authorization (`management/authorization/`)
- `InvalidTokenError` -- bad JWT (401)
- `MissingAuthorizationError` -- no Bearer token (401)
- `UnableMeetPrerequisitesError` -- token validation infra failure (500)

### Infrastructure
- `DualWriteException` (`management/relation_replicator/relation_replicator.py`) -- replication failure (500)
- `V1WriteBlockedError` (`management/tenant_mapping/v2_activation.py`) -- V1 write on V2-activated tenant
- `TenantNotBootstrappedError` (`management/tenant_service/v2.py`) -- tenant not bootstrapped
- `SentryDiagnosticError` (`internal/errors.py`) -- deliberately raised to create a Sentry event

**Rule**: Create domain-specific exceptions under the relevant module's `exceptions.py` or a dedicated file. Follow the pattern: base error class per domain, specific subclasses with structured init params. Always store context attributes (field names, IDs) on the exception instance.

## 3. Exception Handler Registration

Domain exceptions that should produce HTTP error responses should be registered in `rbac/api/common/exception_handler.py`. V2-specific exceptions (like `RolesNotFoundError`, `NotFoundError`, `InvalidFieldError`, `RequiredFieldError`) are handled in `custom_exception_handler_v2`. Authorization exceptions (`InvalidTokenError`, `MissingAuthorizationError`, `UnableMeetPrerequisitesError`) and `IntegrityError` are handled in both V1 and V2 handlers. Unregistered custom exceptions will return no response (None), causing Django to return a 500 with no structured body.

**Rule**: When adding a new domain exception, add handling in the appropriate exception handler(s) based on which API versions need to handle it.

## 4. Validation Errors in Views

Two patterns exist; use the correct one for the API version:

- **V1 views**: Use `raise_validation_error(source, message)` from `management/utils.py`, which raises `rest_framework.exceptions.ValidationError` with `{source: [message]}` format.
- **V2 views**: Use `serializer.is_valid(raise_exception=True)` and let the exception handler format it, OR raise domain exceptions that are caught in the exception handler.

**Rule**: In V1 views, use `raise_validation_error()`. In V2 views, prefer `is_valid(raise_exception=True)` or domain exceptions. Avoid bare `raise Exception(...)` in V1/V2 public API views; use domain exceptions instead.

## 5. Transaction and Concurrency Error Handling

### AtomicOperationsMixin (`management/v2_mixins.py`)
V2 write views use `AtomicOperationsMixin` which wraps operations in `SERIALIZABLE` isolation with automatic retry (default 3 attempts via `pgtransaction.atomic`).

**Rules**:
- Do not override `create()`, `update()`, or `destroy()` on V2 ViewSets that use `AtomicOperationsMixin`. Override `perform_atomic_create()`, `perform_atomic_update()`, or `perform_atomic_destroy()` instead. Violating this raises `TypeError` at class definition time.
- `SerializationFailure` returns 409 Conflict with `"Too many concurrent updates. Please retry."`.
- `DeadlockDetected` returns 500 with `"Internal server error. Please try again later."`.
- Other `OperationalError` is re-raised (will become a 500).

### DualWriteException handling
Catch `DualWriteException` in V1 views and return via the view's `dual_write_exception_response()` method (on `RoleViewSet`), which logs the traceback and returns 500 with source and detail.

### IntegrityError
- In middleware: caught by `@catch_integrity_error` decorator, returns `{"code": 400, "message": "..."}`.
- In exception handler: caught and returned as 400 with the view's basename as source.

**Rule**: Wrap multi-step DB + replication operations in `transaction.atomic()`. Catch `IntegrityError` for race conditions (e.g., concurrent tenant creation).

## 6. Logging Conventions

### Logger initialization
```python
logger = logging.getLogger(__name__)
```
Always use `__name__` (module path). The settings configure loggers for `api`, `internal`, `rbac`, `management`, `migration_tool`, and `feature_flags` namespaces.

### Log levels
- `logger.error(...)` -- operational failures (auth failures, Kafka errors, failed metrics server)
- `logger.warning(...)` -- recoverable issues (retries, empty partitions, health check degradation)
- `logger.info(...)` -- request logging (structured dict with method, path, status, org_id, username, user_id, is_admin, is_system, is_internal, request_id)
- `logger.debug(...)` -- diagnostic detail (identity header contents, gRPC error extraction)
- `logger.exception(...)` -- used for concurrency errors (SerializationFailure, DeadlockDetected) to include stack traces

### Structured request logging
The middleware `IdentityHeaderMiddleware.log_request()` logs a dict to `logger.info()` with standardized fields. Follow this pattern for new request-level logging.

**Rule**: Use `logger.error()` for failures requiring operator attention. Use `logger.exception()` only when the stack trace adds diagnostic value (concurrency errors, unexpected exceptions). Never log sensitive data (tokens, passwords). Include `org_id` in error context when available.

## 7. Sentry / Glitchtip Integration

Sentry SDK connects to Glitchtip via `GLITCHTIP_DSN` env var (see `rbac/rbac/settings.py`). Django and Redis integrations are enabled.

- Use `sentry_sdk.capture_exception(e)` for critical infrastructure failures (e.g., metrics server startup in `celery.py`).
- Use `SentryDiagnosticError` (raised at `/internal/sentry/`) as a deliberate test event -- do not use this pattern for real errors.
- Unhandled exceptions are automatically captured by the Django integration.

**Rule**: Only call `sentry_sdk.capture_exception()` explicitly for infrastructure-level failures that might otherwise be swallowed (background tasks, startup errors). Do not capture handled/expected business errors.

## 8. ECS Logging

The `ECSCustomFormatter` (`rbac/rbac/ECSCustom/__init__.py`) extends `ecs_logging.StdlibFormatter` to extract HTTP request/response metadata from `WSGIRequest` objects attached to log records. It is activated by setting `DJANGO_LOG_HANDLERS=ecs`.

**Rule**: Do not attach non-standard fields to ECS log records. The formatter strips `message`, `status_code`, and `server_time` to comply with ECS field reference standards.

## 9. Middleware Error Responses

Middleware (`rbac/middleware.py`) returns raw `HttpResponse` with JSON payloads -- NOT DRF `Response` objects, since middleware runs outside the DRF request lifecycle.

Format: `{"code": <int>, "message": "<string>"}` with matching HTTP status code.

- Missing org_id: 400
- Missing service account client_id: 400
- Invalid/missing identity: 401 via `HttpResponseUnauthorizedRequest` (no body)
- IntegrityError during request processing: 400 via `@catch_integrity_error`
- Read-only mode: 405 via `ReadOnlyApiMiddleware` with `{"error": "..."}`

**Rule**: In middleware, return `HttpResponse(json.dumps(payload), content_type="application/json", status=...)`. Never use DRF Response in middleware.

## 10. PROBLEM_TITLES Map

V2 error responses use standardized titles from `PROBLEM_TITLES` in `management/utils.py`:

| Status | Title |
|--------|-------|
| 400 | The request payload contains invalid syntax. |
| 401 | Authentication credentials were not provided or are invalid. |
| 403 | You do not have permission to perform this action. |
| 404 | Not found. |
| 409 | Conflict. |
| 500 | Unexpected error occurred. |

**Rule**: When adding new status codes to V2 responses, add a corresponding entry to `PROBLEM_TITLES`.

## 11. gRPC Error Handling

The `GRPCError` wrapper class (`management/relation_replicator/relations_api_replicator.py`) extracts structured error details from gRPC `RpcError` including status code, reason, and metadata from `ErrorInfo` protobuf. Failed extraction is logged at debug level and silently degraded.

**Rule**: When working with Kessel Relations API errors, wrap `grpc.RpcError` in `GRPCError` for structured access. Failures in the replication layer should be wrapped in `DualWriteException`.
