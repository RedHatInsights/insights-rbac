# Security Guidelines for insights-rbac

## Authentication Architecture

### 1. x-rh-identity Header Authentication (Public API)
- The `IdentityHeaderMiddleware` in `rbac/rbac/middleware.py` decodes a base64-encoded JSON `x-rh-identity` header to populate `request.user` (an `api.models.User` instance, NOT Django's auth user).
- Never trust user-supplied fields from the identity header without validation. The middleware already validates `org_id` presence and service account `client_id` non-emptiness. Follow the same pattern for any new fields.
- Cross-account requests require `user.internal == True` AND email ending with `@redhat.com`. Never weaken this check.
- When adding new public endpoints, add them to `is_no_auth()` in middleware.py ONLY if they truly require no authentication (health checks, OpenAPI specs).

### 2. PSK Authentication (Service-to-Service)
- S2S requests use headers `x-rh-rbac-psk`, `x-rh-rbac-account`, `x-rh-rbac-org-id`, `x-rh-rbac-client-id` (defined in `api/common/__init__.py`).
- PSK validation in `management/utils.py:validate_psk()` checks against `SERVICE_PSKS` env var (JSON). It supports primary and alt-secret for key rotation. Never log PSK values.
- PSK-authenticated users get `user.system = True` and `user.admin = True`. Any new S2S endpoint must check `user.system` to distinguish from regular admin users.

### 3. JWT/Bearer Token Authentication (S2S via SSO)
- `ITSSOTokenValidator` in `management/authorization/token_validator.py` validates JWT tokens against Red Hat SSO JWKS.
- Token validation checks: issuer match, scope claims, expiration. The `IT_BYPASS_TOKEN_VALIDATION` setting returns mocked data -- never enable in production.
- After token validation, `build_system_user_from_token()` checks the user_id against `SYSTEM_USERS` env var (JSON allowlist). Only allowlisted service accounts can authenticate this way.
- The `allow_any_org` flag in SYSTEM_USERS allows a system user to act on behalf of any org. Verify `org_id` consistency between token and headers when this is false.

### 4. Internal API Authentication
- Paths under `/_private/` use `InternalIdentityHeaderMiddleware` in `internal/middleware.py`.
- `/_private/_s2s/` paths authenticate via PSK or bearer token.
- Other `/_private/` paths require identity type `Associate` or `X509` (validated in `internal/utils.py:build_internal_user()`). Never add other identity types without security review.
- A2S paths (`/_private/_a2s/`) are an exception: they use public `IdentityHeaderMiddleware` auth and pass through without a user if unauthenticated.

## Authorization Patterns

### 5. Permission Classes
- V1 API views use resource-specific permission classes (`GroupAccessPermission`, `RoleAccessPermission`, etc.) that check `request.user.access` dict populated by middleware.
- The access dict structure is `{resource_type: {read: [...], write: [...]}}`. A `*` in the list means unrestricted access.
- `user.admin` (org admin) bypasses all V1 permission checks. This is intentional. Do not add additional admin checks.
- The `ALLOW_ANY` env var disables all permission checks. It must never be set in production.

### 6. V2 Permission Model (Workspaces)
- V2 uses Kessel Inventory API for fine-grained authorization via `WorkspaceInventoryAccessChecker`.
- V2 permission classes: `WorkspaceAccessPermission`, `RoleBindingSystemUserAccessPermission`, `RoleBindingKesselAccessPermission`.
- Feature flags control V1/V2 branching. The `WorkspaceAccessPermission` is the ONLY place where V1/V2 branching should occur for workspace access.
- System user access uses `check_system_user_access()` from `management/permissions/system_user_utils.py`. Use this single entry point; do not duplicate the decision tree.

### 7. V1/V2 Write Gating
- `V1WriteBlockedWhenWorkspacesEnabled` blocks V1 writes when workspaces are enabled for an org.
- `V2WriteRequiresWorkspacesEnabled` blocks V2 writes when workspaces are NOT enabled.
- Both check feature flags AND database activation state. Always use `is_v2_edit_enabled_for_request()` for consistency.
- `assert_v1_write_allowed()` provides the authoritative row-level-locked check inside transactions. Permission classes are a fast first line of defense.

## Tenant Isolation

### 8. Tenant Scoping
- Every data query MUST be scoped to `request.tenant`. The `BaseV2ViewSet.get_queryset()` automatically filters by tenant.
- V1 views use `filter_queryset_by_tenant()` or explicit `.filter(tenant=tenant)`.
- Never allow a request to access data from a different tenant's org_id. The `request.tenant` is set by middleware based on the authenticated user's org_id.
- System users with `allow_any_org=True` can specify org_id via headers. Their tenant is resolved from the header org_id.

## Input Validation

### 9. Query Parameter Sanitization
- Use `clean_query_param()` from `management/utils.py` for string query params. It rejects NUL characters (`\x00`) and treats whitespace-only as None.
- Use `validate_uuid()` or `is_valid_uuid()` for UUID parameters.
- Use `validate_and_get_key()` for enum-style query parameters with defined valid values.
- The `UUIDStringField` serializer field enforces hyphenated UUID format only (no hex-only UUIDs).

### 10. Request Body Validation
- Internal API endpoints validate request bodies against JSON schemas in `internal/schemas.py` using `jsonschema.validate()`.
- Role binding permission checks sanitize resource_id/resource_type with `.replace("\x00", "")` and validate against `ALLOWED_RESOURCE_TYPES` allowlist.
- Always fail closed on malformed input in permission checks (return `False`).

### 11. Username Handling
- Usernames are case-insensitive; `User.username` setter lowercases automatically.
- Principal lookups use `username__iexact`. Follow this pattern for consistency.
- Group names "Custom Default Access" and "Default Access" are reserved. Use `validate_group_name()`.

## Secrets and Configuration

### 12. Secret Management
- All secrets come from environment variables: `DJANGO_SECRET_KEY`, `SERVICE_PSKS`, `SYSTEM_USERS`, `REDIS_PASSWORD`, `CW_AWS_SECRET_ACCESS_KEY`, `RELATIONS_API_CLIENT_SECRET`, `INVENTORY_API_CLIENT_SECRET`.
- Never log secrets. The `User.__repr__` masks `bearer_token` with `***`. Follow this pattern.
- Never hardcode secrets. The default `SECRET_KEY` in settings.py is for development only.
- gRPC channels use TLS (`grpc.ssl_channel_credentials()`) in production. Insecure channels are only for development/Clowder environments.

## CSRF and CORS

### 13. CSRF is Disabled
- `DisableCSRF` middleware sets `_dont_enforce_csrf_checks = True` on all requests. This is by design for API-only service behind 3scale gateway. Do not add browser-based session auth.

### 14. CORS Configuration
- `CORS_ORIGIN_ALLOW_ALL = True` is set. The service relies on the gateway (3scale) for origin enforcement.
- Custom headers `x-rh-identity` and `HTTP_X_RH_IDENTITY` are in `CORS_ALLOW_HEADERS`.

## Destructive Operations

### 15. Time-Gated Destructive APIs
- Internal destructive APIs are gated by `INTERNAL_DESTRUCTIVE_API_OK_UNTIL` (datetime). The `destructive_ok("api")` check in `core/utils.py` compares against current time.
- Destructive seeding uses `DESTRUCTIVE_SEEDING_OK_UNTIL`. Both default to epoch (1970) which means disabled.
- Never remove these time gates. They are the safety net for dangerous operations.

## Development vs Production

### 16. Development-Only Features
- `DevelopmentIdentityHeaderMiddleware` injects a fake identity header. It is only loaded when `DEVELOPMENT=True`.
- `IT_BYPASS_TOKEN_VALIDATION` returns mocked user data. Never enable in production.
- `BYPASS_BOP_VERIFICATION` skips principal verification. Never enable in production.
- Never add `DEVELOPMENT` or `ALLOW_ANY` checks that weaken security without documenting them as dev-only.

## Read-Only Mode

### 17. API Read-Only Controls
- `ReadOnlyApiMiddleware` blocks write methods when `READ_ONLY_API_MODE` is set (excludes internal API).
- V2-specific read-only mode is controlled by feature flag `is_v2_api_read_only_mode_enabled()`.
- Internal API (`api_namespace == "internal"`) is always exempt from read-only mode.
