# insights-rbac API Contracts Guidelines

## 1. API Versioning

- The application serves two API versions at `api/rbac/v1/` and `api/rbac/v2/`, controlled by the `API_PATH_PREFIX` env var (default `api/`).
- v2 APIs are gated behind `settings.V2_APIS_ENABLED`. Never register v2 routes outside the `if settings.V2_APIS_ENABLED` block in `rbac/rbac/urls.py`.
- The global exception handler (`api/common/exception_handler.py`) dispatches to `custom_exception_handler` (v1) or `custom_exception_handler_v2` (v2) based on path. Both versions MUST be kept in sync when adding new exception types.
- v1 write endpoints are blocked when workspaces are enabled (`V1WriteBlockedWhenWorkspacesEnabled`). v2 write endpoints require workspaces enabled (`V2WriteRequiresWorkspacesEnabled`). Always apply the correct guard.

## 2. Response Envelope Formats

### v1 List Responses
```json
{"meta": {"count": N, "limit": N, "offset": N}, "links": {"first": "...", "next": "...", "previous": "...", "last": "..."}, "data": [...]}
```
Uses `StandardResultsSetPagination` (LimitOffsetPagination). Default limit=10, max=1000.

### v2 List Responses (offset-based: Workspaces)
Same envelope as v1. Uses `V2ResultsSetPagination`. Supports `limit=-1` to return all results.

### v2 List Responses (cursor-based: RoleBindings, Roles)
```json
{"meta": {"limit": N}, "links": {"next": "...", "previous": "..."}, "data": [...]}
```
Uses `V2CursorPagination`. No `count`, `offset`, `first`, or `last` keys. Supports `limit=-1`. Default limit=10, max=1000.

### v1 Error Responses
```json
{"errors": [{"detail": "...", "source": "...", "status": "400"}]}
```

### v2 Error Responses (Problem Details)
```json
{"status": 400, "title": "The request payload contains invalid syntax.", "detail": "...", "errors": [...]}
```
Content-Type: `application/problem+json`. Titles come from `PROBLEM_TITLES` dict in `management/utils.py`. Use `v2response_error_from_errors()` to build these.

## 3. ViewSet Patterns

### v1 ViewSets
- Inherit from DRF mixins + `viewsets.GenericViewSet` or `viewsets.ModelViewSet` directly.
- Use `StandardResultsSetPagination`.
- Registered in `management/urls.py` via `DefaultRouter`.

### v2 ViewSets
- MUST inherit from `BaseV2ViewSet` (`management/base_viewsets.py`), which composes individual DRF mixins and adds `ProblemJSONRenderer` and `V2ResultsSetPagination`.
- `BaseV2ViewSet.get_queryset()` automatically filters by `request.tenant` and orders by `name, -modified`. Override with care.
- For write operations (create/update/destroy), use `AtomicOperationsMixin` from `management/v2_mixins.py`. This wraps mutations in `SERIALIZABLE` isolation transactions with retry=3.
- When using `AtomicOperationsMixin`, NEVER override `create()`, `update()`, or `destroy()` directly. Override `perform_atomic_create()`, `perform_atomic_update()`, `perform_atomic_destroy()` instead. The mixin enforces this at class definition time via `__init_subclass__`.
- v2 routes are registered in `management/v2_urls.py` via `V2Router`, which extends `DefaultRouter` with `:batchCreate` and `:batchDelete` custom routes.

## 4. URL Routing Conventions

- v1: resource names are plural, lowercase (`groups`, `roles`, `permissions`, `auditlogs`). Some endpoints are plain views (`principals/`, `access/`).
- v2: resource names are plural, kebab-case (`workspaces`, `role-bindings`, `roles`).
- v2 batch operations use colon-prefixed action names: `/role-bindings:batchCreate/`, `/roles:batchDelete/`.
- v2 sub-resource endpoints use path segments: `/role-bindings/by-subject/`.
- Workspace has a custom action: `/{id}/move/`.
- All URLs end with trailing slashes.

## 5. Serializer Patterns

### Input vs Output Serializers
- v2 endpoints use SEPARATE input and output serializers. Input serializers validate query parameters or request bodies. Output serializers format responses. Name them `*InputSerializer` / `*OutputSerializer` or `*RequestSerializer` / `*ResponseSerializer`.
- v1 often uses a single serializer for both directions, sometimes with `RoleDynamicSerializer` patterns.

### Tenant Injection
- v1 serializers that create objects use `SerializerCreateOverrideMixin` to auto-inject `tenant=self.context["request"].tenant` into `ModelClass.objects.create()`.
- v2 serializers delegate creation to a service layer, passing tenant explicitly: `self.service.create(..., tenant=tenant)`.

### Field Selection (v2 only, AIP-161 pattern)
- The `fields` query parameter controls response fields using `FieldSelection` from `management/utils.py`.
- Syntax: `field1,field2` for root fields; `object(field1,field2)` for nested fields.
- Each endpoint defines its own `FieldSelection` subclass with `VALID_ROOT_FIELDS` and `VALID_NESTED_FIELDS` class variables.
- Read operations: silently filter invalid fields. Write operations: raise `ValidationError` for invalid fields (strict mode).
- Serializers dynamically pop unrequested fields in `__init__` or `to_representation`.

### NUL Byte Sanitization
- All v2 input serializers MUST override `to_internal_value()` to strip `\x00` (NUL) bytes from string values before validation.

## 6. Filtering and Query Parameters

- v1 uses `CommonFilters(django_filters.FilterSet)` with `name_filter()` supporting `name_match=partial|exact`.
- v2 validates query parameters via dedicated input serializers (not django-filters). Call `input_serializer.is_valid(raise_exception=True)` before using `validated_data`.
- v2 ordering uses `order_by` query parameter with dot notation (`group.name`, `role.modified`, `-role.created`). Field mappings are defined in `V2CursorPagination` (`GROUP_FIELD_MAPPING`, `USER_FIELD_MAPPING`, `ROLE_BINDING_FIELD_MAPPING`). Invalid fields raise `ValidationError`.
- `validate_and_get_key()` in `management/utils.py` validates query params against allowed values with a default fallback.
- `validate_uuid()` validates UUID format; use it for all UUID path/query params.

## 7. Concurrency and Transaction Handling

- v2 write operations use `pgtransaction.atomic(isolation_level=SERIALIZABLE, retry=3)`.
- `SerializationFailure` returns 409 (or 503 for workspaces). `DeadlockDetected` returns 500. Always handle `OperationalError` and inspect `__cause__`.
- Workspace views use `Retry-After: 1` header on 503 responses.
- The `is_atomic_disabled()` setting allows skipping transactions in tests.

## 8. Service Layer (v2)

- v2 endpoints follow a View -> Serializer -> Service -> Model pattern.
- Services live in `management/<resource>/service.py` (e.g., `WorkspaceService`, `RoleBindingService`, `RoleV2Service`).
- Service methods are responsible for business logic, model operations, and relation replication. Serializers handle validation and delegate to services.
- Domain exceptions (`RequiredFieldError`, `InvalidFieldError`, `NotFoundError`, `RolesNotFoundError`) are raised by services and caught by the global exception handler or serializer-level try/except.

## 9. OpenAPI / TypeSpec Specification

- The TypeSpec spec lives at `docs/source/specs/typespec/main.tsp`. It generates OpenAPI 3 output in `tsp-output/@typespec/openapi3/`.
- v2 OpenAPI is served at `api/rbac/v2/openapi.json` via `api/openapi/view.py`.
- When adding or modifying v2 endpoints, update `main.tsp` to match. Key conventions:
  - All models use `@example` decorators. All operations use `@opExample`.
  - Error responses use `Problems.ProblemDetails<Status>` models.
  - Pagination models: `CursorPaginationMeta`/`CursorPaginationLinks` for cursor-based; `OffsetPaginationMeta`/`OffsetPaginationLinks` for offset-based.
  - `FieldMask`, `Limit`, `Cursor`, `Offset`, `OrderBy` are custom scalars -- reuse them.
  - Compile with `tsp compile .` from the typespec directory after changes.

## 10. Permission Classes

- Every ViewSet MUST declare `permission_classes`. v1 uses `RoleAccessPermission`, `GroupAccessPermission`, etc.
- v2 uses Kessel-based permissions (e.g., `RoleV2KesselAccessPermission`, `RoleBindingKesselAccessPermission`, `WorkspaceAccessPermission`).
- Write-guard permissions (`V1WriteBlockedWhenWorkspacesEnabled` / `V2WriteRequiresWorkspacesEnabled`) must be included for any mutating endpoint.

## 11. Key Conventions Checklist

- v2 list serializers: Use separate input serializer for query param validation
- v2 response format: `{meta, links, data}` envelope -- never return bare lists
- v2 errors: Always `application/problem+json` with `{status, title, detail}` structure
- Pagination links: Rewritten to partial URLs (path + query only, no host) via `link_rewrite()`
- UUIDs: Use `UUIDStringField` (hex with hyphens) for API-facing UUID fields
- v2 lookup field: Roles use `lookup_field = "uuid"`, not `pk`
- Batch operations: Max 100 items (`@maxItems(100)` / `max_length=100`)
- HTTP methods: Roles v2 explicitly restricts to `["get", "post", "put", "head", "options"]` -- no PATCH or DELETE on individual roles
- Tenant scoping: ALL queries must filter by tenant. `BaseV2ViewSet` does this automatically; v1 views use `get_*_queryset()` helpers from `management/querysets.py`
