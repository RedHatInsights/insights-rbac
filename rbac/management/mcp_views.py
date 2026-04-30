#
# Copyright 2025 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

"""MCP endpoint for RBAC using Anthropic MCP Python SDK for tool registration and schema generation."""

import asyncio
import concurrent.futures
import inspect
import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache, wraps
from typing import Any, Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from management.access.view import AccessView
from management.audit_log.view import AuditLogViewSet
from management.group.view import GroupViewSet
from management.models import Access, AuditLog, Group
from management.permission.view import PermissionViewSet
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from management.principal.view import PrincipalView
from management.role.v2_view import RoleV2ViewSet
from management.role.view import RoleViewSet
from management.role_binding.view import RoleBindingViewSet
from management.tenant_mapping.v2_activation import is_v2_write_activated
from management.workspace.view import WorkspaceViewSet
from mcp.server.fastmcp import FastMCP
from prometheus_client import Counter, Histogram
from redis import exceptions as redis_exceptions

from api.common import RH_IDENTITY_HEADER
from api.cross_access.view import CrossAccountRequestViewSet
from api.status.view import status as status_view_fn

# Cache view functions — .as_view() returns a new callable each time,
# but the result is stateless and reusable.
_principal_view = PrincipalView.as_view()
_status_view = status_view_fn
_access_view = AccessView.as_view()
_permission_list_view = PermissionViewSet.as_view({"get": "list"})
_permission_options_view = PermissionViewSet.as_view({"get": "options"})
_auditlog_list_view = AuditLogViewSet.as_view({"get": "list"})
_role_access_view = RoleViewSet.as_view({"get": "access"})
_role_v1_list_view = RoleViewSet.as_view({"get": "list"})
_role_v1_detail_view = RoleViewSet.as_view({"get": "retrieve"})
_role_v2_list_view = RoleV2ViewSet.as_view({"get": "list"})
_role_v2_detail_view = RoleV2ViewSet.as_view({"get": "retrieve"})
_group_list_view = GroupViewSet.as_view({"get": "list"})
_group_detail_view = GroupViewSet.as_view({"get": "retrieve"})
_group_principals_view = GroupViewSet.as_view({"get": "principals"})
_group_roles_view = GroupViewSet.as_view({"get": "roles"})
_cross_account_list_view = CrossAccountRequestViewSet.as_view({"get": "list"})
_cross_account_detail_view = CrossAccountRequestViewSet.as_view({"get": "retrieve"})
_workspace_list_view = WorkspaceViewSet.as_view({"get": "list"})
_workspace_detail_view = WorkspaceViewSet.as_view({"get": "retrieve"})
_role_binding_list_view = RoleBindingViewSet.as_view({"get": "list"})
_role_binding_by_subject_view = RoleBindingViewSet.as_view({"get": "by_subject"})

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-03-26"

# --- Prometheus metrics ---

mcp_tool_call_total = Counter(
    "rbac_mcp_tool_call_total",
    "Total MCP tool calls (excludes hello)",
    ["tool", "status"],
)
mcp_tool_call_duration_seconds = Histogram(
    "rbac_mcp_tool_call_duration_seconds",
    "Duration of MCP tool calls in seconds (excludes hello)",
    ["tool"],
)

# Factory for building internal Django requests to delegate to views.
_request_factory = RequestFactory()

# Headers forwarded from the original request to internal view requests,
# beyond the identity header (which is always forwarded).
_FORWARDED_HEADERS = ("HTTP_X_REQUEST_ID", "HTTP_X_RH_INSIGHTS_REQUEST_ID")

# --- Tool description overrides (Redis-backed, no restart needed) ---

_REDIS_DESC_PREFIX = "mcp:desc:"


def _get_redis():
    """Get a Redis connection using the shared connection pool from management.cache."""
    from management.cache import _connection_pool

    from redis import Redis

    return Redis(connection_pool=_connection_pool, ssl=settings.REDIS_SSL)


def _get_description_override(tool_name: str) -> str | None:
    try:
        value = _get_redis().get(f"{_REDIS_DESC_PREFIX}{tool_name}")
        return value.decode() if value else None
    except redis_exceptions.RedisError:
        logger.debug("mcp: redis unavailable for description override, tool=%s", tool_name)
        return None


def _set_description_override(tool_name: str, description: str) -> None:
    _get_redis().set(f"{_REDIS_DESC_PREFIX}{tool_name}", description)


def _delete_description_override(tool_name: str) -> None:
    _get_redis().delete(f"{_REDIS_DESC_PREFIX}{tool_name}")


def _get_all_description_overrides() -> dict[str, str]:
    try:
        r = _get_redis()
        keys = r.keys(f"{_REDIS_DESC_PREFIX}*")
        if not keys:
            return {}
        values = r.mget(keys)
        prefix_len = len(_REDIS_DESC_PREFIX)
        return {k.decode()[prefix_len:]: v.decode() for k, v in zip(keys, values) if v is not None}
    except redis_exceptions.RedisError:
        logger.debug("mcp: redis unavailable for description overrides")
        return {}


# --- MCP Server setup using the Anthropic MCP Python SDK ---

mcp = FastMCP("RBAC")


# --- Tool configuration ---
#
# @register_tool registers each tool with both FastMCP (for schema generation)
# and _TOOL_CONFIG (for sync execution). This eliminates the need for separate
# stub functions and a manual config dict.


class ApiVersion:
    """API version classification for MCP tools."""

    UNIFIED = "unified"
    COMMON = "common"
    V1 = "v1"
    V2 = "v2"
    UNVERSIONED = "unversioned"


@dataclass(frozen=True)
class ToolConfig:
    """Configuration for an MCP tool."""

    fn: Callable[..., str]
    requires_auth: bool = False
    passes_request: bool = False
    api_version: str = ApiVersion.COMMON


_TOOL_CONFIG: dict[str, ToolConfig] = {}


def register_tool(
    *,
    description: str,
    requires_auth: bool = False,
    api_version: str = ApiVersion.COMMON,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register a tool with both FastMCP and _TOOL_CONFIG.

    If the function's first parameter is named ``request``, a schema-only
    wrapper (without the ``request`` param) is registered with FastMCP so
    the generated JSON schema matches what MCP clients send. The real
    implementation receives the Django request at call time via
    ``_handle_tools_call``.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = fn.__name__
        sig = inspect.signature(fn)
        first_param = next(iter(sig.parameters), None)
        passes_request = first_param == "request"

        _TOOL_CONFIG[tool_name] = ToolConfig(
            fn=fn,
            requires_auth=requires_auth,
            passes_request=passes_request,
            api_version=api_version,
        )

        if passes_request:
            # Build a wrapper whose signature omits `request` so FastMCP
            # generates a schema without it.
            remaining = [p for name, p in sig.parameters.items() if name != "request"]
            wrapper_sig = sig.replace(parameters=remaining)

            @wraps(fn)
            def _schema_stub(**kwargs: Any) -> str:
                raise RuntimeError(f"{tool_name} should not be called via FastMCP dispatch")

            _schema_stub.__signature__ = wrapper_sig  # type: ignore[attr-defined]
            mcp.tool(name=tool_name, description=description)(_schema_stub)
        else:
            mcp.tool(name=tool_name, description=description)(fn)

        return fn

    return decorator


def _clone_request(source: HttpRequest, path: str, **kwargs: Any) -> HttpRequest:
    """Clone a Django request for internal view delegation.

    Copies authentication context (user, tenant, identity header) and
    selected tracing headers from the source request so that the target
    view applies the same permission checks and is observable in traces.
    """
    view_request = _request_factory.get(path, **kwargs)
    view_request.user = source.user
    view_request.tenant = getattr(source, "tenant", None)
    view_request.req_id = getattr(source, "req_id", None)

    identity = source.META.get(RH_IDENTITY_HEADER)
    if identity:
        view_request.META[RH_IDENTITY_HEADER] = identity

    for header in _FORWARDED_HEADERS:
        value = source.META.get(header)
        if value:
            view_request.META[header] = value

    return view_request


# --- Tool implementations ---


@register_tool(
    description=(
        "Say hello to the RBAC service. Returns your message echoed back along with "
        "the current server date in UTC. No authentication required. "
        "Use this to verify MCP connectivity."
    ),
    api_version=ApiVersion.UNVERSIONED,
)
def hello(message: str = "Hello, World!") -> str:
    """Respond to a greeting — no authentication required."""
    now: str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return json.dumps({"response": f"RBAC received your message: '{message}'", "date": now})


@register_tool(
    description=(
        "List principals (users) for the authenticated organization. "
        "Supports pagination (limit/offset), sorting (asc/desc), and filtering by status "
        "(enabled/disabled/all). Set 'usernames' (comma-separated) to look up specific users. "
        "Set 'match_criteria' to 'exact' (default) or 'partial' for username matching. "
        "Set username_only='true' to return only usernames. "
        "TROUBLESHOOTING: To confirm a user exists and check their org admin status, call "
        "list_principals(usernames='<user>', match_criteria='exact'). "
        "Returns: {meta: {count}, links, data: [{username, email, first_name, last_name, is_org_admin, ...}]}. "
        "Calls: GET /api/v1/principals/"
    ),
    requires_auth=True,
)
def list_principals(
    request: HttpRequest,
    *,
    limit: int = 10,
    offset: int = 0,
    sort_order: str = "asc",
    status: str = "enabled",
    username_only: str = "false",
    usernames: str = "",
    match_criteria: str = "",
) -> str:
    """List principals by delegating to PrincipalView."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
        "sort_order": sort_order,
        "status": status,
        "username_only": username_only,
    }
    if usernames:
        query_params["usernames"] = usernames
    if match_criteria:
        query_params["match_criteria"] = match_criteria

    path = reverse("v1_management:principals")
    return _call_view(request, _principal_view, path, query_params)


def _call_view(
    request: HttpRequest,
    view: Callable[..., Any],
    path: str,
    query_params: dict[str, str],
    **view_kwargs: str,
) -> str:
    """Call a Django view with cloned request and return the response body.

    For detail views, pass the lookup kwarg as a keyword argument,
    e.g. ``_call_view(request, view, path, {}, pk=value)``.

    DRF responses are rendered via their configured renderer so the
    output matches exactly what the API would return.
    """
    view_request = _clone_request(request, path, data=query_params)
    response = view(view_request, **view_kwargs)
    if hasattr(response, "render"):
        response = response.render()
    return response.content.decode()


# ┌──────────────────────────────────┬───────────┬────────────────────────────────────────────┐
# │ MCP Tool                         │ Version   │ API Endpoint                               │
# ├──────────────────────────────────┼───────────┼────────────────────────────────────────────┤
# │ hello                            │ unver.    │ (none — in-process greeting)               │
# │ get_status                       │ unver.    │ GET /api/v1/status/                        │
# │ list_principals                  │ common    │ GET /api/v1/principals/                    │
# │ list_permissions                 │ common    │ GET /api/v1/permissions/                   │
# │ list_permission_options          │ common    │ GET /api/v1/permissions/options/            │
# │ list_audit_logs                  │ common    │ GET /api/v1/auditlogs/                     │
# │ list_groups                      │ common    │ GET /api/v1/groups/                        │
# │ get_group                        │ common    │ GET /api/v1/groups/{uuid}/                 │
# │ list_group_principals            │ common    │ GET /api/v1/groups/{uuid}/principals/      │
# │ list_cross_account_requests      │ common    │ GET /api/v1/cross-account-requests/        │
# │ get_cross_account_request        │ common    │ GET /api/v1/cross-account-requests/{id}/   │
# │ list_workspaces                  │ common    │ GET /api/v2/workspaces/                    │
# │ get_workspace                    │ common    │ GET /api/v2/workspaces/{uuid}/             │
# │ search_roles                     │ unified   │ V1: GET /api/v1/roles/                     │
# │                                  │           │ V2: GET /api/v2/roles/                     │
# │ get_role                         │ unified   │ V1: GET /api/v1/roles/{uuid}/ + /access/   │
# │                                  │           │ V2: GET /api/v2/roles/{uuid}/              │
# │ check_user_permission            │ unified   │ V1: GET /api/v1/access/                    │
# │                                  │           │ V2: role-bindings → roles                  │
# │ list_access                      │ v1        │ GET /api/v1/access/                        │
# │ list_group_roles                 │ v1        │ GET /api/v1/groups/{uuid}/roles/           │
# │ list_role_access                 │ v1        │ GET /api/v1/roles/{uuid}/access/           │
# │ list_role_bindings               │ v2        │ GET /api/v2/role-bindings/                 │
# │ list_role_bindings_by_subject    │ v2        │ GET /api/v2/role-bindings/by-subject/      │
# └──────────────────────────────────┴───────────┴────────────────────────────────────────────┘


@register_tool(
    description=(
        "Get RBAC server status including API version, commit hash, server address, "
        "platform info, Python version and loaded modules. No authentication required. "
        "Calls: GET /api/v1/status/"
    ),
    api_version=ApiVersion.UNVERSIONED,
)
def get_status(request: HttpRequest) -> str:
    """Return server status by delegating to the status view."""
    path = reverse("v1_api:server-status")
    return _call_view(request, _status_view, path, {})


@register_tool(
    description=(
        "List permissions available in RBAC. Each permission has the format 'application:resource_type:verb'. "
        "Filter by application, resource_type, or verb. Supports pagination and ordering by 'permission' or "
        "'-permission'. "
        "Returns: {meta: {count}, links, data: [{application, resource_type, verb, permission}]}. "
        "Calls: GET /api/v1/permissions/"
    ),
    requires_auth=True,
)
def list_permissions(
    request: HttpRequest,
    *,
    application: str = "",
    resource_type: str = "",
    verb: str = "",
    limit: int = 10,
    offset: int = 0,
    order_by: str = "",
) -> str:
    """List permissions by delegating to PermissionViewSet."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
    }
    if application:
        query_params["application"] = application
    if resource_type:
        query_params["resource_type"] = resource_type
    if verb:
        query_params["verb"] = verb
    if order_by:
        query_params["order_by"] = order_by

    path = reverse("v1_management:permission-list")
    return _call_view(request, _permission_list_view, path, query_params)


@register_tool(
    description=(
        "List audit log entries recording RBAC changes for the authenticated organization. "
        "Each entry records who changed what (principal, resource_type, action). "
        "Filter by principal_username (who made the change), resource_type "
        "(group/role/role_v2/user/permission/workspace/role_binding), action (add/edit/delete/create/remove), "
        "group_name (filter by group), or role_name (filter by role). "
        "IMPORTANT: Always set group_name and/or role_name to narrow results (avoids scanning 100+ entries). "
        "Example: list_audit_logs(resource_type='group', action='add', group_name='Contractors', "
        "role_name='Vulnerability administrator') "
        "Set include_authorization=true to see the role/permission that authorized the action. "
        "Order by: 'created', 'principal_username', 'resource_type', 'action' (prefix with '-' to reverse). "
        "NOTE: Authorization shows actor's CURRENT role/permission — may differ from time of change. "
        "RESPONSE FORMAT: When summarizing audit log entries, include the action, resource type, who performed it "
        "(principal_username), the date and time (formatted as '14 April at 9:32 AM', not numeric like "
        "'2025-04-14T09:32:15'), and the description field. When include_authorization=true, also state the "
        "role name (authorized_by.role), "
        "group name (authorized_by.via_group), and specific permission (authorized_by.permission) that "
        "authorized the action."
    ),
    requires_auth=True,
)
def list_audit_logs(
    request: HttpRequest,
    *,
    limit: int = 10,
    offset: int = 0,
    order_by: str = "-created",
    principal_username: str = "",
    resource_type: str = "",
    action: str = "",
    group_name: str = "",
    role_name: str = "",
    include_authorization: bool = False,
) -> str:
    """List audit logs with optional authorization context."""
    valid_order_fields = {"created", "principal_username", "resource_type", "action"}
    order_field = order_by.lstrip("-")
    if order_field not in valid_order_fields:
        return json.dumps(
            {"error": f"Invalid order_by field '{order_by}'. Valid fields: {', '.join(sorted(valid_order_fields))}"}
        )

    tenant = getattr(request, "tenant", None)
    if not tenant:
        return json.dumps({"error": "No tenant context available"})

    queryset = AuditLog.objects.filter(tenant=tenant).order_by(order_by)

    if principal_username:
        queryset = queryset.filter(principal_username__icontains=principal_username)
    if resource_type:
        queryset = queryset.filter(resource_type=resource_type)
    if action:
        queryset = queryset.filter(action=action)
    if group_name:
        queryset = queryset.filter(description__icontains=group_name)
    if role_name:
        queryset = queryset.filter(description__icontains=role_name)

    total_count = queryset.count()
    entries = list(queryset[offset : offset + limit])  # noqa: E203

    if not entries:
        return json.dumps({"meta": {"count": total_count}, "data": []})

    if not include_authorization:
        # Return basic audit log data
        data = [
            {
                "principal_username": e.principal_username,
                "action": e.action,
                "resource_type": e.resource_type,
                "description": e.description,
                "created": e.created.isoformat() if e.created else None,
            }
            for e in entries
        ]
        return json.dumps({"meta": {"count": total_count}, "data": data}, default=str)

    # Enrich with authorization context
    auth_cache: dict[str, dict[str, dict[str, Any] | None]] = {}
    org_admin_cache: dict[str, bool] = {}
    org_admin_auth: dict[str, Any] = {
        "role": "Org Admin",
        "via_group": None,
        "permission": "(bypasses all RBAC checks)",
    }
    results = []

    for entry in entries:
        actor = entry.principal_username
        entry_action = entry.action
        entry_resource = entry.resource_type
        required_perms = _get_required_permissions(entry_resource, entry_action)
        cache_key = f"{entry_resource}:{entry_action}"

        if actor not in auth_cache:
            auth_cache[actor] = {}

        if actor not in org_admin_cache:
            org_admin_cache[actor] = _is_org_admin(actor, tenant.org_id)

        auth_info: dict[str, Any] | None
        if org_admin_cache[actor]:
            auth_info = org_admin_auth
        elif cache_key not in auth_cache[actor]:
            auth_cache[actor][cache_key] = _find_authorizing_role(actor, tenant, required_perms)
            auth_info = auth_cache[actor][cache_key]
        else:
            auth_info = auth_cache[actor][cache_key]

        result: dict[str, Any] = {
            "principal_username": actor,
            "action": entry_action,
            "resource_type": entry_resource,
            "description": entry.description,
            "created": entry.created.isoformat() if entry.created else None,
            "authorized_by": auth_info,
        }

        if not auth_info:
            result["note"] = f"User '{actor}' not found or no longer has permissions. Required: {required_perms}"

        results.append(result)

    return json.dumps({"meta": {"count": total_count}, "data": results}, default=str)


# Permission requirements by resource_type and action
_REQUIRED_PERMISSIONS: dict[str, dict[str, list[str]]] = {
    "group": {
        "create": ["rbac:group:write"],
        "delete": ["rbac:group:write"],
        "edit": ["rbac:group:write"],
        "add": ["rbac:group:write", "rbac:principal:write"],
        "remove": ["rbac:group:write", "rbac:principal:write"],
    },
    "role": {
        "create": ["rbac:role:write"],
        "delete": ["rbac:role:write"],
        "edit": ["rbac:role:write"],
    },
    "role_v2": {
        "create": ["rbac:role:write"],
        "delete": ["rbac:role:write"],
        "edit": ["rbac:role:write"],
    },
    "workspace": {
        "create": ["rbac:workspace:write"],
        "delete": ["rbac:workspace:write"],
        "edit": ["rbac:workspace:write"],
    },
    "role_binding": {
        "create": ["rbac:role_binding:write"],
        "delete": ["rbac:role_binding:write"],
    },
    "user": {
        "add": ["rbac:principal:write"],
        "remove": ["rbac:principal:write"],
    },
    "permission": {
        "create": ["rbac:role:write"],
        "edit": ["rbac:role:write"],
        "delete": ["rbac:role:write"],
    },
}


def _get_required_permissions(resource_type: str, action: str) -> list[str]:
    """Get the permissions required for a given resource_type and action."""
    resource_perms = _REQUIRED_PERMISSIONS.get(resource_type, {})
    return resource_perms.get(action, [f"rbac:{resource_type}:write"])


def _is_org_admin(username: str, org_id: str) -> bool:
    """Check if a user is an org admin by querying BOP."""
    try:
        proxy = PrincipalProxy()
        resp = proxy.request_filtered_principals([username], org_id=org_id, limit=1)
        if resp.get("status_code") == 200:
            data = resp.get("data", [])
            if data and len(data) > 0:
                return data[0].get("is_org_admin", False)
    except Exception:
        logger.debug("mcp: failed to check org admin status for user=%s", username)
    return False


def _find_authorizing_role(username: str, tenant: Any, required_perms: list[str]) -> dict[str, Any] | None:
    """Find the role and permission that authorized an action."""
    principal = Principal.objects.filter(username=username, tenant=tenant).first()
    if not principal:
        return None

    # Single query: get all permissions the user has with their role/group context
    access_entries = (
        Access.objects.filter(
            role__policies__group__principals=principal,
            role__policies__group__tenant=tenant,
        )
        .select_related("permission", "role")
        .values(
            "permission__permission",
            "role__name",
            "role__display_name",
            "role__policies__group__name",
        )
    )

    # Build required permission set for fast lookup
    required_set = set(required_perms)

    for entry in access_entries:
        granted_perm = entry["permission__permission"]
        # Check exact match first (fast path)
        if granted_perm in required_set:
            return {
                "role": entry["role__display_name"] or entry["role__name"],
                "via_group": entry["role__policies__group__name"],
                "permission": granted_perm,
            }
        # Check wildcard match
        for required in required_perms:
            if _permission_matches(granted_perm, required):
                return {
                    "role": entry["role__display_name"] or entry["role__name"],
                    "via_group": entry["role__policies__group__name"],
                    "permission": granted_perm,
                }

    return None


@register_tool(
    description=(
        "List access permissions for a principal (V1 API only). By default shows access for the "
        "currently authenticated user. Set 'username' to query another user's access (requires "
        "org admin or rbac:principal:read permission). Each entry is a permission string "
        "with optional resource definitions that further constrain it. "
        "IMPORTANT: This is a V1-only endpoint. For V2 organizations, this returns only legacy "
        "V1 access and does NOT include V2 role binding permissions. For V2 orgs, use "
        "check_user_permission (which auto-detects V1/V2) or list_role_bindings with "
        "granted_subject_type='principal' and granted_subject_principal_user_id='<username>'. "
        "Order by: 'application', 'resource_type', 'verb' (prefix with '-' to reverse). "
        "Returns: {meta: {count}, links, data: [{permission, resourceDefinitions: [...]}]}. "
        "Calls: GET /api/v1/access/"
    ),
    requires_auth=True,
    api_version=ApiVersion.V1,
)
def list_access(
    request: HttpRequest,
    *,
    application: str,
    username: str = "",
    limit: int = 10,
    offset: int = 0,
    order_by: str = "",
    status: str = "enabled",
) -> str:
    """List principal access by delegating to AccessView."""
    query_params: dict[str, str] = {
        "application": application,
        "limit": str(limit),
        "offset": str(offset),
        "status": status,
    }
    if username:
        query_params["username"] = username
    if order_by:
        query_params["order_by"] = order_by

    path = reverse("v1_management:access")
    return _call_view(request, _access_view, path, query_params)


@register_tool(
    description=(
        "Get distinct values for a permission field. Use this to discover what applications, "
        "resource_types, or verbs exist. The 'field' parameter is required and must be one of: "
        "'application', 'resource_type', 'verb'. Optionally filter by application, resource_type, "
        "or verb (comma-separated for multiple). "
        "Returns: {meta: {count}, links, data: ['value1', 'value2', ...]}. "
        "Calls: GET /api/v1/permissions/options/"
    ),
    requires_auth=True,
)
def list_permission_options(
    request: HttpRequest,
    *,
    field: str,
    application: str = "",
    resource_type: str = "",
    verb: str = "",
    limit: int = 10,
    offset: int = 0,
) -> str:
    """List distinct permission field values by delegating to PermissionViewSet.options."""
    query_params: dict[str, str] = {
        "field": field,
        "limit": str(limit),
        "offset": str(offset),
    }
    if application:
        query_params["application"] = application
    if resource_type:
        query_params["resource_type"] = resource_type
    if verb:
        query_params["verb"] = verb

    path = reverse("v1_management:permission-options")
    return _call_view(request, _permission_options_view, path, query_params)


@register_tool(
    description=(
        "List roles assigned to a specific group. Provide either group_uuid OR group_name "
        "(if both are provided, group_uuid takes precedence). "
        "Use group_name for convenience (case-insensitive lookup). "
        "Example: list_group_roles(group_name='<group-name>') to see roles assigned to that group. "
        "Filter results by role_name, role_description, role_display_name, or role_system. "
        "Set exclude='true' to list roles NOT in the group. "
        "Order by: 'name', 'display_name', 'modified', 'policyCount' (prefix with '-' to reverse). "
        "Returns: {meta: {count}, links, data: [{uuid, name, description, system, ...}]}."
    ),
    requires_auth=True,
    api_version=ApiVersion.V1,
)
def list_group_roles(
    request: HttpRequest,
    *,
    group_uuid: str = "",
    group_name: str = "",
    limit: int = 10,
    offset: int = 0,
    order_by: str = "",
    role_name: str = "",
    role_description: str = "",
    role_display_name: str = "",
    role_system: str = "",
    exclude: str = "false",
) -> str:
    """List roles for a group by delegating to GroupViewSet.roles."""
    tenant = getattr(request, "tenant", None)
    if not tenant:
        return json.dumps({"error": "No tenant context available"})

    resolved_uuid = group_uuid
    if not resolved_uuid and group_name:
        group = Group.objects.filter(name__iexact=group_name, tenant=tenant).only("uuid").first()
        if not group:
            return json.dumps({"error": f"Group '{group_name}' not found"})
        resolved_uuid = str(group.uuid)

    if not resolved_uuid:
        return json.dumps({"error": "Either group_uuid or group_name is required"})

    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
    }
    if order_by:
        query_params["order_by"] = order_by
    if role_name:
        query_params["role_name"] = role_name
    if role_description:
        query_params["role_description"] = role_description
    if role_display_name:
        query_params["role_display_name"] = role_display_name
    if role_system:
        query_params["role_system"] = role_system
    if exclude != "false":
        query_params["exclude"] = exclude

    path = reverse("v1_management:group-roles", kwargs={"uuid": resolved_uuid})
    return _call_view(request, _group_roles_view, path, query_params, uuid=resolved_uuid)


@register_tool(
    description=(
        "List access permissions granted by a specific role (V1 API). Each access entry is a "
        "permission string with optional resource definitions. "
        "Returns: {meta: {count}, links, data: [{permission, resourceDefinitions: [...]}]}. "
        "Calls: GET /api/v1/roles/{uuid}/access/"
    ),
    requires_auth=True,
    api_version=ApiVersion.V1,
)
def list_role_access(
    request: HttpRequest,
    *,
    role_uuid: str,
    limit: int = 10,
    offset: int = 0,
) -> str:
    """List access for a role by delegating to RoleViewSet.access."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
    }
    path = reverse("v1_management:role-access", kwargs={"uuid": role_uuid})
    return _call_view(request, _role_access_view, path, query_params, uuid=role_uuid)


@register_tool(
    description=(
        "Search and filter roles by name, permission, application, or other criteria. "
        "Automatically detects whether the organization uses V1 or V2 and routes accordingly. "
        "Best tool for answering 'which role grants permission X?' or 'find role named Y'. "
        "TROUBLESHOOTING: To find a role by name, call search_roles(name='<role_name>'). "
        "To find which roles grant a specific permission, call "
        "search_roles(permission='<app>:<resource>:<verb>'). Accepts comma-separated permissions. "
        "To see all roles for an application, call search_roles(application='<app>'). "
        "V2 orgs support name with '*' wildcards (e.g., name='Cost*') and resource_type filter. "
        "V1 orgs additionally support display_name, system flag filters. "
        "Returns: {meta: {count}, links, data: [{uuid, name, description, ...}], org_version: 'v1'|'v2'}."
    ),
    requires_auth=True,
    api_version=ApiVersion.UNIFIED,
)
def search_roles(
    request: HttpRequest,
    *,
    limit: int = 10,
    offset: int = 0,
    name: str = "",
    display_name: str = "",
    permission: str = "",
    application: str = "",
    system: str = "",
    resource_type: str = "",
    order_by: str = "",
) -> str:
    """Search roles, auto-detecting V1/V2 and delegating to the appropriate view."""
    tenant = getattr(request, "tenant", None)
    if tenant and is_v2_write_activated(tenant):
        return _search_roles_v2(request, limit, offset, name, resource_type, permission, order_by)
    return _search_roles_v1(request, limit, offset, name, display_name, permission, application, system, order_by)


def _search_roles_v1(
    request: HttpRequest,
    limit: int,
    offset: int,
    name: str,
    display_name: str,
    permission: str,
    application: str,
    system: str,
    order_by: str,
) -> str:
    """Search roles using V1 API."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
    }
    if name:
        query_params["name"] = name
    if display_name:
        query_params["display_name"] = display_name
    if permission:
        query_params["permission"] = permission
    if application:
        query_params["application"] = application
    if system:
        query_params["system"] = system
    if order_by:
        query_params["order_by"] = order_by

    path = reverse("v1_management:role-list")
    raw = _call_view(request, _role_v1_list_view, path, query_params)
    result = json.loads(raw)
    result["org_version"] = "v1"
    return json.dumps(result)


def _search_roles_v2(
    request: HttpRequest,
    limit: int,
    offset: int,
    name: str,
    resource_type: str,
    permission: str,
    order_by: str,
) -> str:
    """Search roles using V2 API."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
    }
    if name:
        query_params["name"] = name
    if resource_type:
        query_params["resource_type"] = resource_type
    if permission:
        query_params["permission"] = permission
    if order_by:
        query_params["order_by"] = order_by

    path = reverse("v2_management:roles-list")
    raw = _call_view(request, _role_v2_list_view, path, query_params)
    result = json.loads(raw)
    result["org_version"] = "v2"
    return json.dumps(result)


@register_tool(
    description=(
        "Get details of a specific role by UUID, including its permissions. "
        "Automatically detects whether the organization uses V1 or V2 and routes accordingly. "
        "Returns: {uuid, name, description, permissions: [...], org_version: 'v1'|'v2'}."
    ),
    requires_auth=True,
    api_version=ApiVersion.UNIFIED,
)
def get_role(
    request: HttpRequest,
    *,
    role_uuid: str,
) -> str:
    """Get a single role, auto-detecting V1/V2 and delegating to the appropriate view."""
    tenant = getattr(request, "tenant", None)
    if tenant and is_v2_write_activated(tenant):
        return _get_role_v2(request, role_uuid)
    return _get_role_v1(request, role_uuid)


def _get_role_v1(request: HttpRequest, role_uuid: str) -> str:
    """Get role details using V1 API (retrieve + access)."""
    detail_path = reverse("v1_management:role-detail", kwargs={"uuid": role_uuid})
    detail_raw = _call_view(request, _role_v1_detail_view, detail_path, {}, uuid=role_uuid)
    result = json.loads(detail_raw)

    access_path = reverse("v1_management:role-access", kwargs={"uuid": role_uuid})
    access_raw = _call_view(request, _role_access_view, access_path, {"limit": "1000"}, uuid=role_uuid)
    access_data = json.loads(access_raw)

    result["permissions"] = access_data.get("data", [])
    result["org_version"] = "v1"
    return json.dumps(result)


def _get_role_v2(request: HttpRequest, role_uuid: str) -> str:
    """Get role details using V2 API."""
    path = reverse("v2_management:roles-detail", kwargs={"uuid": role_uuid})
    raw = _call_view(request, _role_v2_detail_view, path, {}, uuid=role_uuid)
    result = json.loads(raw)
    result["org_version"] = "v2"
    return json.dumps(result)


@register_tool(
    description=(
        "List groups for the authenticated organization. Groups are collections of principals "
        "that can be assigned roles via policies. Filter by name (partial match), username "
        "(groups a specific user belongs to), or role_names (groups that have a specific role assigned). "
        "TROUBLESHOOTING: To find which groups a user belongs to, call list_groups(username='<user>'). "
        "To find groups with a specific role, call list_groups(role_names='<role_name>'). "
        "Order by: 'name', '-name', 'modified', '-modified', 'principalCount', '-principalCount', "
        "'policyCount', '-policyCount'. "
        "Returns: {meta: {count}, links, data: [{uuid, name, description, principalCount, ...}]}. "
        "Calls: GET /api/v1/groups/"
    ),
    requires_auth=True,
)
def list_groups(
    request: HttpRequest,
    *,
    limit: int = 10,
    offset: int = 0,
    name: str = "",
    username: str = "",
    role_names: str = "",
    order_by: str = "",
) -> str:
    """List groups by delegating to GroupViewSet."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
    }
    if name:
        query_params["name"] = name
    if username:
        query_params["username"] = username
    if role_names:
        query_params["role_names"] = role_names
    if order_by:
        query_params["order_by"] = order_by

    path = reverse("v1_management:group-list")
    return _call_view(request, _group_list_view, path, query_params)


@register_tool(
    description=(
        "Get details of a specific group by UUID, including its name, description, "
        "principal count, policy count, and role count. "
        "Returns: {uuid, name, description, principalCount, policyCount, roleCount, ...}. "
        "Calls: GET /api/v1/groups/{uuid}/"
    ),
    requires_auth=True,
)
def get_group(
    request: HttpRequest,
    *,
    group_uuid: str,
) -> str:
    """Get a single group by delegating to GroupViewSet."""
    path = reverse("v1_management:group-detail", kwargs={"uuid": group_uuid})
    return _call_view(request, _group_detail_view, path, {}, uuid=group_uuid)


@register_tool(
    description=(
        "List principals (users) that are members of a specific group. "
        "Optionally filter by principal_type. "
        "Returns: {meta: {count}, links, data: [{username, email, first_name, last_name, ...}]}. "
        "Calls: GET /api/v1/groups/{uuid}/principals/"
    ),
    requires_auth=True,
)
def list_group_principals(
    request: HttpRequest,
    *,
    group_uuid: str,
    limit: int = 10,
    offset: int = 0,
    principal_type: str = "",
) -> str:
    """List principals in a group by delegating to GroupViewSet.principals."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
    }
    if principal_type:
        query_params["principal_type"] = principal_type

    path = reverse("v1_management:group-principals", kwargs={"uuid": group_uuid})
    return _call_view(request, _group_principals_view, path, query_params, uuid=group_uuid)


@register_tool(
    description=(
        "List cross-account access requests. These allow users from one org (e.g. Red Hat TAMs) "
        "to request temporary access to another org's resources. "
        "Set query_by='target_org' (default) to see requests INTO your org, or "
        "query_by='user_id' to see requests you made to other orgs. "
        "Filter by status (pending/approved/denied/expired/cancelled), org_id, or approved_only. "
        "TROUBLESHOOTING: To see who from Red Hat currently has access to your org, call "
        "list_cross_account_requests(query_by='target_org', status='approved'). "
        "Order by: 'request_id', 'start_date', 'end_date', 'created', 'modified', "
        "'status' (prefix with '-' to reverse). "
        "Returns: {meta: {count}, links, data: [{request_id, target_account, status, start_date, end_date, ...}]}. "
        "Calls: GET /api/v1/cross-account-requests/"
    ),
    requires_auth=True,
)
def list_cross_account_requests(
    request: HttpRequest,
    *,
    limit: int = 10,
    offset: int = 0,
    query_by: str = "",
    status: str = "",
    org_id: str = "",
    approved_only: str = "",
    order_by: str = "",
) -> str:
    """List cross-account requests by delegating to CrossAccountRequestViewSet."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
    }
    if query_by:
        query_params["query_by"] = query_by
    if status:
        query_params["status"] = status
    if org_id:
        query_params["org_id"] = org_id
    if approved_only:
        query_params["approved_only"] = approved_only
    if order_by:
        query_params["order_by"] = order_by

    path = reverse("v1_api:cross-list")
    return _call_view(request, _cross_account_list_view, path, query_params)


@register_tool(
    description=(
        "Get details of a specific cross-account access request by its ID, including "
        "status, start/end dates, target account, and the requested roles. "
        "Returns: {request_id, target_account, status, start_date, end_date, created, roles, ...}. "
        "Calls: GET /api/v1/cross-account-requests/{request_id}/"
    ),
    requires_auth=True,
)
def get_cross_account_request(
    request: HttpRequest,
    *,
    request_id: str,
) -> str:
    """Get a single cross-account request by delegating to CrossAccountRequestViewSet."""
    path = reverse("v1_api:cross-detail", kwargs={"pk": request_id})
    return _call_view(request, _cross_account_detail_view, path, {}, pk=request_id)


@register_tool(
    description=(
        "List workspaces for the authenticated organization (V2 API). Workspaces are hierarchical "
        "containers used to scope role bindings to specific resource boundaries. "
        "Order by: 'name', 'created', 'modified', 'type' (prefix with '-' to reverse). "
        "Returns: {meta: {count}, links, data: [{uuid, name, description, type, parent_id, created, ...}]}. "
        "Calls: GET /api/v2/workspaces/"
    ),
    requires_auth=True,
)
def list_workspaces(
    request: HttpRequest,
    *,
    limit: int = 10,
    offset: int = 0,
    order_by: str = "",
) -> str:
    """List workspaces by delegating to WorkspaceViewSet."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
    }
    if order_by:
        query_params["order_by"] = order_by

    path = reverse("v2_management:workspace-list")
    return _call_view(request, _workspace_list_view, path, query_params)


@register_tool(
    description=(
        "Get details of a specific workspace by UUID (V2 API). Returns the workspace's name, "
        "type, parent, and optionally its full ancestry chain (set include_ancestry=true). "
        "Returns: {uuid, name, description, type, parent_id, created, modified, ...}. "
        "Calls: GET /api/v2/workspaces/{uuid}/"
    ),
    requires_auth=True,
)
def get_workspace(
    request: HttpRequest,
    *,
    workspace_uuid: str,
    include_ancestry: bool = False,
) -> str:
    """Get a single workspace by delegating to WorkspaceViewSet."""
    query_params: dict[str, str] = {}
    if include_ancestry:
        query_params["include_ancestry"] = "true"

    path = reverse("v2_management:workspace-detail", kwargs={"pk": workspace_uuid})
    return _call_view(request, _workspace_detail_view, path, query_params, pk=workspace_uuid)


@register_tool(
    description=(
        "List role bindings for the authenticated organization (V2 API). A role binding assigns "
        "a role to a subject (user/group) within a resource scope (e.g. workspace). "
        "Filter by role_id, resource_type, resource_id, subject_type, or subject_id. "
        "ACCESS RESOLUTION: To find what permissions a user has (or which are missing) in V2, "
        "(1) call list_role_bindings(granted_subject_type='principal', "
        "granted_subject_principal_user_id='<username>') to find all effective bindings "
        "including those inherited through group membership "
        "(this is the V2 equivalent of list_access(username=X) for V1), "
        "(2) for each binding extract the role UUID, "
        "(3) call get_role(role_uuid=...) or list_role_access(role_uuid=...) to inspect "
        "the role's permissions, (4) compare against the required permissions to identify "
        "what is granted and what is missing. "
        "TIP: For a quick yes/no check, use check_user_permission instead — it auto-detects "
        "V1/V2 and does the full resolution automatically. "
        "Returns: {meta: {count}, links, data: [{uuid, role, resource, subject, ...}]}. "
        "Calls: GET /api/v2/role-bindings/"
    ),
    requires_auth=True,
    api_version=ApiVersion.V2,
)
def list_role_bindings(
    request: HttpRequest,
    *,
    limit: int = 10,
    offset: int = 0,
    role_id: str = "",
    resource_type: str = "",
    resource_id: str = "",
    subject_type: str = "",
    subject_id: str = "",
    granted_subject_type: str = "",
    granted_subject_id: str = "",
    granted_subject_principal_user_id: str = "",
) -> str:
    """List role bindings by delegating to RoleBindingViewSet."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
    }
    if role_id:
        query_params["role_id"] = role_id
    if resource_type:
        query_params["resource_type"] = resource_type
    if resource_id:
        query_params["resource_id"] = resource_id
    if subject_type:
        query_params["subject_type"] = subject_type
    if subject_id:
        query_params["subject_id"] = subject_id
    if granted_subject_type:
        query_params["granted_subject_type"] = granted_subject_type
    if granted_subject_id:
        query_params["granted_subject_id"] = granted_subject_id
    if granted_subject_principal_user_id:
        query_params["granted_subject.principal.user_id"] = granted_subject_principal_user_id

    path = reverse("v2_management:role-bindings-list")
    return _call_view(request, _role_binding_list_view, path, query_params)


@register_tool(
    description=(
        "List role bindings grouped by subject (V2 API). Shows which roles each subject "
        "(user/group) has within a specific resource. Requires resource_id and resource_type. "
        "Optionally filter by subject_type and subject_id. "
        "Returns: {meta: {count}, links, data: [{subject, roles: [...], ...}]}. "
        "Calls: GET /api/v2/role-bindings/by-subject/"
    ),
    requires_auth=True,
    api_version=ApiVersion.V2,
)
def list_role_bindings_by_subject(
    request: HttpRequest,
    *,
    resource_id: str,
    resource_type: str,
    subject_type: str = "",
    subject_id: str = "",
    limit: int = 10,
    offset: int = 0,
) -> str:
    """List role bindings by subject by delegating to RoleBindingViewSet.by_subject."""
    query_params: dict[str, str] = {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "limit": str(limit),
        "offset": str(offset),
    }
    if subject_type:
        query_params["subject_type"] = subject_type
    if subject_id:
        query_params["subject_id"] = subject_id

    path = reverse("v2_management:role-bindings-by-subject")
    return _call_view(request, _role_binding_by_subject_view, path, query_params)


def _permission_matches(granted_permission: str, requested_permission: str) -> bool:
    """Check if a granted permission matches a requested permission, supporting wildcards.

    Supports exact match and wildcard patterns in the granted permission:
    - "app:resource:verb" matches "app:resource:verb" (exact)
    - "app:*:*" matches "app:resource:verb" (wildcard resource and verb)
    - "app:resource:*" matches "app:resource:verb" (wildcard verb)
    """
    granted_parts = granted_permission.split(":")
    requested_parts = requested_permission.split(":")
    if len(granted_parts) != 3 or len(requested_parts) != 3:
        return False
    return all(g == "*" or g == r for g, r in zip(granted_parts, requested_parts))


@register_tool(
    description=(
        "Check whether a specific user has a specific permission. Returns true/false "
        "with the matched permission details. Automatically detects whether the organization "
        "is V1 or V2 and uses the appropriate access resolution method: "
        "V1 uses the access endpoint; V2 resolves role bindings and inspects role permissions. "
        "The permission format is 'application:resource_type:verb' (e.g., "
        "'cost-management:cost_model:write'). Supports wildcard matching. "
        "Requires org admin or rbac:principal:read permission to check another user. "
        "ACCESS RESOLUTION: This is the fastest way to answer 'Can user X do Y?' — "
        "it works for both V1 and V2 organizations automatically. "
        "Returns: {allowed: bool, username, permission, matched_permission, ...} "
        "or {allowed: false, hint: str}. "
        "V1 calls: GET /api/v1/access/?username=X&application=Y (internally). "
        "V2 resolves: role bindings → roles → permissions (internally)."
    ),
    requires_auth=True,
    api_version=ApiVersion.UNIFIED,
)
def check_user_permission(
    request: HttpRequest,
    *,
    username: str,
    permission: str,
) -> str:
    """Check if a user has a specific permission by delegating to AccessView (V1) or role bindings (V2)."""
    parts = permission.split(":")
    if len(parts) != 3:
        return json.dumps(
            {
                "error": "Permission must be in format 'application:resource_type:verb'. "
                "Example: 'cost-management:cost_model:write'"
            }
        )

    tenant = getattr(request, "tenant", None)
    if not tenant or not is_v2_write_activated(tenant):
        return _check_user_permission_v1(request, username, permission)

    from management.principal.model import Principal

    principal = Principal.objects.filter(username=username, tenant=tenant).first()
    if not principal:
        return json.dumps(
            {
                "allowed": False,
                "username": username,
                "permission": permission,
                "org_version": "v2",
                "hint": f"User '{username}' not found in this organization.",
            }
        )

    bindings_path = reverse("v2_management:role-bindings-list")
    raw = _call_view(
        request,
        _role_binding_list_view,
        bindings_path,
        {
            "granted_subject_type": "user",
            "granted_subject_id": str(principal.uuid),
            "limit": "1000",
        },
    )
    bindings_data = json.loads(raw)
    bindings = bindings_data.get("data", [])

    if not bindings:
        return json.dumps(
            {
                "allowed": False,
                "username": username,
                "permission": permission,
                "org_version": "v2",
                "total_bindings_checked": 0,
                "hint": f"User '{username}' has no role bindings in this V2 organization. "
                f"Use list_role_bindings(granted_subject_type='user', "
                f"granted_subject_id='{principal.uuid}') to see all role bindings.",
            }
        )

    role_uuids = {b["role"]["id"] for b in bindings if b.get("role", {}).get("id")}

    for role_uuid in role_uuids:
        role_path = reverse("v2_management:roles-detail", kwargs={"uuid": role_uuid})
        role_raw = _call_view(request, _role_v2_detail_view, role_path, {}, uuid=role_uuid)
        role_data = json.loads(role_raw)

        for perm in role_data.get("permissions", []):
            perm_str = f"{perm['application']}:{perm['resource_type']}:{perm['operation']}"
            if _permission_matches(perm_str, permission):
                return json.dumps(
                    {
                        "allowed": True,
                        "username": username,
                        "permission": permission,
                        "matched_permission": perm_str,
                        "role_name": role_data.get("name"),
                        "role_uuid": str(role_uuid),
                        "org_version": "v2",
                    }
                )

    return json.dumps(
        {
            "allowed": False,
            "username": username,
            "permission": permission,
            "org_version": "v2",
            "total_roles_checked": len(role_uuids),
            "hint": f"User '{username}' does not have permission '{permission}' in this V2 organization. "
            f"Use list_role_bindings(granted_subject_type='user', "
            f"granted_subject_id='{principal.uuid}') to see all role bindings, "
            f"or search_roles(name='*') to browse available roles.",
        }
    )


def _check_user_permission_v1(request: HttpRequest, username: str, permission: str) -> str:
    """Check user permission using V1 access endpoint."""
    application = permission.split(":")[0]
    query_params: dict[str, str] = {
        "application": application,
        "username": username,
        "limit": "1000",
    }
    path = reverse("v1_management:access")

    try:
        raw = _call_view(request, _access_view, path, query_params)
    except Exception as e:
        return json.dumps(
            {
                "error": f"Failed to check permissions: {e}",
                "hint": "Requires org admin or rbac:principal:read permission to check another user.",
            }
        )

    data = json.loads(raw)

    if "detail" in data:
        return json.dumps(
            {
                "allowed": False,
                "error": data["detail"],
                "hint": "Requires org admin or rbac:principal:read permission to check another user.",
            }
        )

    access_list = data.get("data", [])

    for entry in access_list:
        entry_permission = entry.get("permission", "")
        if _permission_matches(entry_permission, permission):
            return json.dumps(
                {
                    "allowed": True,
                    "username": username,
                    "permission": permission,
                    "matched_permission": entry_permission,
                    "resource_definitions": entry.get("resourceDefinitions", []),
                }
            )

    application = permission.split(":")[0]
    return json.dumps(
        {
            "allowed": False,
            "username": username,
            "permission": permission,
            "total_permissions_checked": len(access_list),
            "hint": f"User '{username}' does not have permission '{permission}'. "
            f"Use list_access(username='{username}', application='{application}') to see all "
            f"permissions, or list_groups(username='{username}') to trace the group/role chain.",
        }
    )


# --- JSON-RPC parsing ---


class JsonRpcError(Exception):
    """JSON-RPC validation error raised during request parsing."""

    def __init__(self, request_id: Any | None, code: int, message: str) -> None:
        """Initialize with JSON-RPC error fields."""
        self.request_id = request_id
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass
class JsonRpcRequest:
    """Parsed JSON-RPC 2.0 request."""

    request_id: Any | None
    method: str
    params: dict[str, Any]


def _parse_jsonrpc(body: bytes) -> JsonRpcRequest:
    """Parse and validate a JSON-RPC 2.0 request body.

    Returns a JsonRpcRequest on success. Raises JsonRpcError on validation failure.
    Notifications (no id) return a JsonRpcRequest with request_id=None.
    """
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise JsonRpcError(None, -32700, "Parse error")

    if isinstance(payload, list):
        raise JsonRpcError(None, -32600, "Invalid Request: batch requests are not supported")

    if not isinstance(payload, dict):
        raise JsonRpcError(None, -32600, "Invalid Request: expected a JSON object")

    req_id = payload.get("id")

    if payload.get("jsonrpc") != "2.0":
        raise JsonRpcError(req_id, -32600, "Invalid Request: jsonrpc must be '2.0'")

    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise JsonRpcError(req_id, -32600, "Invalid Request: method must be a non-empty string")

    raw_params = payload.get("params") or {}
    if req_id is not None and not isinstance(raw_params, dict):
        raise JsonRpcError(req_id, -32600, "Invalid Request: params must be an object")

    return JsonRpcRequest(
        request_id=req_id,
        method=method,
        params=raw_params if isinstance(raw_params, dict) else {},
    )


# --- Django View implementing MCP StreamableHTTP transport ---


@method_decorator(csrf_exempt, name="dispatch")
class MCPView(View):
    """WSGI-compatible MCP endpoint implementing StreamableHTTP transport.

    Handles the MCP JSON-RPC protocol over HTTP POST, using the Anthropic MCP
    Python SDK (mcp) for tool registration and schema generation.

    Authentication is handled by Django's IdentityHeaderMiddleware, the same
    way as the regular /api/v1/principals/ endpoint.
    """

    http_method_names = ["post", "get", "delete"]

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle MCP JSON-RPC requests via HTTP POST."""
        org_id = getattr(getattr(request, "user", None), "org_id", None)
        req_id = getattr(request, "req_id", "unknown")

        try:
            rpc_req = _parse_jsonrpc(request.body)
        except JsonRpcError as exc:
            logger.warning(
                "mcp: parse error, org_id=%s, req_id=%s, code=%s, msg='%s'",
                org_id,
                req_id,
                exc.code,
                exc.message,
            )
            return _error_response(exc.request_id, exc.code, exc.message)

        logger.info("mcp: method=%s, org_id=%s, req_id=%s", rpc_req.method, org_id, req_id)

        if rpc_req.request_id is None:
            return HttpResponse(status=202, content_type="application/json")

        if rpc_req.method == "initialize":
            return _handle_initialize(request, rpc_req.request_id, rpc_req.params)
        if rpc_req.method == "tools/list":
            return _handle_tools_list(request, rpc_req.request_id, rpc_req.params)
        if rpc_req.method == "tools/call":
            return _handle_tools_call(request, rpc_req.request_id, rpc_req.params)

        logger.warning("mcp: unknown method=%s, org_id=%s, req_id=%s", rpc_req.method, org_id, req_id)
        return _error_response(rpc_req.request_id, -32601, f"Method not found: {rpc_req.method}")

    def get(self, request: HttpRequest) -> HttpResponse:
        """SSE streaming is not supported in WSGI mode."""
        return HttpResponse("SSE streaming not supported in WSGI mode", status=405, content_type="text/plain")

    def delete(self, request: HttpRequest) -> HttpResponse:
        """Handle MCP session termination."""
        return HttpResponse(status=200, content_type="application/json")


# --- JSON-RPC method handlers ---


def _handle_initialize(request: HttpRequest, request_id: Any, params: dict[str, Any]) -> JsonResponse:
    """Handle MCP initialize request."""
    client_info = params.get("clientInfo", {})
    logger.info("mcp: initialize, client=%s/%s", client_info.get("name", "unknown"), client_info.get("version", "?"))
    result = {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {"listChanged": False},
        },
        "serverInfo": {
            "name": mcp.name,
            "version": "1.0.0",
        },
    }
    response = _success_response(request_id, result)
    response["Mcp-Session-Id"] = str(uuid.uuid4())
    return response


@lru_cache(maxsize=1)
def _get_tools() -> list[Any]:
    """Resolve and cache tool metadata from FastMCP on first call.

    Tools are static (listChanged: False). Lazy initialization avoids
    import-time side effects. Runs in WSGI context where no event loop
    is active; ASGI would require a different approach.
    """
    return asyncio.run(mcp.list_tools())


def _is_v2_available() -> bool:
    """Check whether V2 API routes are mounted."""
    return getattr(settings, "V2_APIS_ENABLED", False)


def _handle_tools_list(request: HttpRequest, request_id: Any, params: dict[str, Any]) -> JsonResponse:
    """Handle MCP tools/list request using FastMCP's registered tools."""
    v2_available = _is_v2_available()
    overrides = _get_all_description_overrides()
    tools_data = [
        {
            "name": tool.name,
            "description": overrides.get(tool.name, tool.description or ""),
            "inputSchema": tool.inputSchema,
        }
        for tool in _get_tools()
        if v2_available or _TOOL_CONFIG.get(tool.name, ToolConfig(fn=lambda: "")).api_version != ApiVersion.V2
    ]
    return _success_response(request_id, {"tools": tools_data})


def _normalize_tool_result(result: Any) -> str:
    """Normalize tool return values into a string suitable for MCP text content."""
    if isinstance(result, str):
        return result
    return json.dumps(result, default=str)


class ToolTimeoutError(Exception):
    """Raised when a tool exceeds its execution timeout.

    Distinct from the built-in TimeoutError so that _handle_tools_call can
    distinguish infrastructure timeouts from TimeoutError raised by the
    tool itself (e.g. from ``requests`` or other libraries).
    """


_MCP_TOOL_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=settings.MCP_TOOL_MAX_WORKERS,
    thread_name_prefix="mcp-tool",
)


def _execute_with_timeout(fn: Callable[..., Any], timeout: int, *args: Any, **kwargs: Any) -> Any:
    """Execute a tool function with a timeout.

    Uses the module-level ThreadPoolExecutor so threads are reused across
    calls instead of creating a new executor per request.

    Raises ToolTimeoutError if the function does not complete within the
    given timeout (seconds).
    """
    future = _MCP_TOOL_EXECUTOR.submit(fn, *args, **kwargs)
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        raise ToolTimeoutError(f"Tool execution exceeded {timeout}s timeout")


def _handle_tools_call(request: HttpRequest, request_id: Any, params: dict[str, Any]) -> JsonResponse:
    """Handle MCP tools/call request.

    Calls tool functions directly in the sync WSGI context (not through
    FastMCP's async call_tool) to avoid Django's SynchronousOnlyOperation
    error when tools access the ORM.

    Tools that need auth context receive the Django request as the first
    argument, so no thread-local state is needed.

    Tool execution is wrapped in a configurable timeout (MCP_TOOL_TIMEOUT_SECONDS,
    default 30s) using a ThreadPoolExecutor. On timeout, a JSON-RPC internal
    error (-32603) is returned and a Prometheus metric with status="timeout"
    is recorded.
    """
    tool_name: str = params.get("name", "")
    if "arguments" not in params:
        return _error_response(request_id, -32602, "Missing required field: arguments")
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        return _error_response(request_id, -32602, "Invalid params: arguments must be an object")

    config = _TOOL_CONFIG.get(tool_name)
    if config is None:
        logger.warning("mcp: tools/call unknown tool='%s'", tool_name)
        return _error_response(request_id, -32602, f"Unknown tool: {tool_name}")

    if config.api_version == ApiVersion.V2 and not _is_v2_available():
        logger.warning("mcp: tools/call tool='%s' rejected, V2 APIs not enabled", tool_name)
        return _error_response(
            request_id,
            -32602,
            f"Tool '{tool_name}' requires V2 APIs, which are not enabled in this deployment.",
        )

    org_id = getattr(getattr(request, "user", None), "org_id", None)
    logger.info(
        "mcp: tools/call tool='%s', org_id=%s, args=%s",
        tool_name,
        org_id,
        list(arguments.keys()),
    )

    if config.requires_auth:
        if not org_id:
            logger.warning("mcp: tools/call tool='%s' rejected, no auth", tool_name)
            _record_metric(tool_name, "auth_error")
            return _error_response(request_id, -32000, "Authentication required")

    track = tool_name != "hello"
    start = time.monotonic() if track else 0
    timeout = getattr(settings, "MCP_TOOL_TIMEOUT_SECONDS", 30)

    try:
        if timeout > 0:
            if config.passes_request:
                result = _execute_with_timeout(config.fn, timeout, request, **arguments)
            else:
                result = _execute_with_timeout(config.fn, timeout, **arguments)
        else:
            if config.passes_request:
                result = config.fn(request, **arguments)
            else:
                result = config.fn(**arguments)

        if track:
            duration = time.monotonic() - start
            _record_metric(tool_name, "success", duration)
            logger.info("mcp: tools/call tool='%s' completed in %.3fs", tool_name, duration)

        content = [{"type": "text", "text": _normalize_tool_result(result)}]
        return _success_response(request_id, {"content": content, "isError": False})
    except ToolTimeoutError:
        duration = time.monotonic() - start if track else timeout
        if track:
            _record_metric(tool_name, "timeout", duration)
        logger.error("mcp: tools/call tool='%s' timed out after %ds", tool_name, timeout)
        return _error_response(request_id, -32603, f"Tool execution timed out after {timeout}s")
    except TypeError as exc:
        if track:
            _record_metric(tool_name, "invalid_params", time.monotonic() - start)
        return _error_response(request_id, -32602, f"Invalid params for tool '{tool_name}': {exc}")
    except Exception:
        if track:
            _record_metric(tool_name, "error", time.monotonic() - start)
        logger.exception("mcp: tools/call tool='%s' failed", tool_name)
        return _error_response(request_id, -32603, "Internal error executing tool")


def _record_metric(tool_name: str, status: str, duration: float | None = None) -> None:
    """Record prometheus metrics for a tool call."""
    mcp_tool_call_total.labels(tool=tool_name, status=status).inc()
    if duration is not None:
        mcp_tool_call_duration_seconds.labels(tool=tool_name).observe(duration)


# --- JSON-RPC response helpers ---


def _success_response(request_id: Any, result: dict[str, Any]) -> JsonResponse:
    """Create a JSON-RPC success response."""
    return JsonResponse({"jsonrpc": "2.0", "result": result, "id": request_id})


def _error_response(request_id: Any, code: int, message: str) -> JsonResponse:
    """Create a JSON-RPC error response."""
    return JsonResponse({"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": request_id})
