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
import inspect
import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache, wraps
from typing import Any, Callable

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from management.principal.view import PrincipalView
from mcp.server.fastmcp import FastMCP
from prometheus_client import Counter, Histogram

from api.common import RH_IDENTITY_HEADER

# Cache the view function — PrincipalView.as_view() returns a new callable each time,
# but the result is stateless and reusable.
_principal_view = PrincipalView.as_view()

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

# --- MCP Server setup using the Anthropic MCP Python SDK ---

mcp = FastMCP("RBAC")


# --- Tool configuration ---
#
# @register_tool registers each tool with both FastMCP (for schema generation)
# and _TOOL_CONFIG (for sync execution). This eliminates the need for separate
# stub functions and a manual config dict.


@dataclass(frozen=True)
class ToolConfig:
    """Configuration for an MCP tool."""

    fn: Callable[..., str]
    requires_auth: bool = False
    passes_request: bool = False


_TOOL_CONFIG: dict[str, ToolConfig] = {}


def register_tool(
    *,
    description: str,
    requires_auth: bool = False,
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
    description="Say hello or send a greeting to RBAC. Responds with your message and the current server date.",
)
def hello(message: str = "Hello, World!") -> str:
    """Respond to a greeting — no authentication required."""
    now: str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return json.dumps({"response": f"RBAC received your message: '{message}'", "date": now})


@register_tool(
    description="List principals (users) for the authenticated organization",
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
) -> str:
    """List principals by delegating to PrincipalView."""
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
        "sort_order": sort_order,
        "status": status,
        "username_only": username_only,
    }

    path = reverse("v1_management:principals")
    view_request = _clone_request(request, path, data=query_params)
    response = _principal_view(view_request)

    if hasattr(response, "data"):
        return json.dumps(response.data, default=str)
    return response.content.decode()


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


def _handle_tools_list(request: HttpRequest, request_id: Any, params: dict[str, Any]) -> JsonResponse:
    """Handle MCP tools/list request using FastMCP's registered tools."""
    tools_data = [
        {
            "name": tool.name,
            "description": tool.description or "",
            "inputSchema": tool.inputSchema,
        }
        for tool in _get_tools()
    ]
    return _success_response(request_id, {"tools": tools_data})


def _normalize_tool_result(result: Any) -> str:
    """Normalize tool return values into a string suitable for MCP text content."""
    if isinstance(result, str):
        return result
    return json.dumps(result, default=str)


def _handle_tools_call(request: HttpRequest, request_id: Any, params: dict[str, Any]) -> JsonResponse:
    """Handle MCP tools/call request.

    Calls tool functions directly in the sync WSGI context (not through
    FastMCP's async call_tool) to avoid Django's SynchronousOnlyOperation
    error when tools access the ORM.

    Tools that need auth context receive the Django request as the first
    argument, so no thread-local state is needed.
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

    try:
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
