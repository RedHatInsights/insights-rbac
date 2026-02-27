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
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import RequestFactory
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from management.principal.view import PrincipalView
from mcp.server.fastmcp import FastMCP

from api.common import RH_IDENTITY_HEADER

# Cache the view function — PrincipalView.as_view() returns a new callable each time,
# but the result is stateless and reusable.
_principal_view = PrincipalView.as_view()

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2025-03-26"

# Factory for building internal Django requests to delegate to views.
_request_factory = RequestFactory()

# --- MCP Server setup using the Anthropic MCP Python SDK ---

mcp = FastMCP("RBAC")


@mcp.tool(description="Say hello or send a greeting to RBAC. Responds with your message and the current server date.")
def hello(message: str = "Hello, World!") -> str:
    """Respond to a greeting — no authentication required."""
    now: str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return json.dumps({"response": f"RBAC received your message: '{message}'", "date": now})


@mcp.tool(description="List principals (users) for the authenticated organization")
def list_principals(
    limit: int = 10,
    offset: int = 0,
    sort_order: str = "asc",
    status: str = "enabled",
    username_only: str = "false",
) -> str:
    """Schema-only wrapper for FastMCP tool registration.

    Execution is handled by _list_principals_impl with an explicit request
    parameter, so this function is never called directly.
    """
    raise RuntimeError("list_principals should not be called via FastMCP dispatch")


def _list_principals_impl(
    request: HttpRequest,
    *,
    limit: int = 10,
    offset: int = 0,
    sort_order: str = "asc",
    status: str = "enabled",
    username_only: str = "false",
) -> str:
    """List principals by delegating to PrincipalView.

    Uses the same Django view class, authentication, and permission checks
    as the /api/v1/principals/ REST API endpoint.
    """
    query_params: dict[str, str] = {
        "limit": str(limit),
        "offset": str(offset),
        "sort_order": sort_order,
        "status": status,
        "username_only": username_only,
    }
    return _call_principal_view(request, query_params)


def _call_principal_view(mcp_request: HttpRequest, query_params: dict[str, str]) -> str:
    """Build a GET request and delegate to PrincipalView.

    Creates an internal Django request with the same authentication context
    as the original MCP request, then passes it to PrincipalView.as_view()
    so that all permission checks, pagination, and proxy calls are handled
    identically to a normal /api/v1/principals/ GET request.
    """
    path = reverse("v1_management:principals")
    view_request = _request_factory.get(path, data=query_params)

    # Copy authentication context set by IdentityHeaderMiddleware
    view_request.user = mcp_request.user
    view_request.tenant = getattr(mcp_request, "tenant", None)
    view_request.req_id = getattr(mcp_request, "req_id", None)

    # Copy identity header for downstream services
    identity = mcp_request.META.get(RH_IDENTITY_HEADER)
    if identity:
        view_request.META[RH_IDENTITY_HEADER] = identity

    # Delegate to PrincipalView — same code path as a regular API request
    response = _principal_view(view_request)

    if hasattr(response, "data"):
        return json.dumps(response.data, default=str)
    return response.content.decode()


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
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            return _error_response(None, -32700, "Parse error")

        if body.get("jsonrpc") != "2.0":
            return _error_response(body.get("id"), -32600, "Invalid Request: jsonrpc must be '2.0'")

        method: str = body.get("method", "")
        raw_params: Any = body.get("params") or {}
        request_id: str | int | None = body.get("id")

        # JSON-RPC notifications (no id) return 202 Accepted
        if request_id is None:
            return HttpResponse(status=202, content_type="application/json")

        if not isinstance(raw_params, dict):
            return _error_response(request_id, -32600, "Invalid Request: params must be an object")
        params: dict[str, Any] = raw_params

        handler = _HANDLERS.get(method)
        if handler is None:
            return _error_response(request_id, -32601, f"Method not found: {method}")

        return handler(request, request_id, params)

    def get(self, request: HttpRequest) -> HttpResponse:
        """SSE streaming is not supported in WSGI mode."""
        return HttpResponse("SSE streaming not supported in WSGI mode", status=405, content_type="text/plain")

    def delete(self, request: HttpRequest) -> HttpResponse:
        """Handle MCP session termination."""
        return HttpResponse(status=200, content_type="application/json")


# --- JSON-RPC method handlers ---


def _handle_initialize(request: HttpRequest, request_id: Any, params: dict[str, Any]) -> JsonResponse:
    """Handle MCP initialize request."""
    logger.info("MCP initialize request received")
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


# Resolve tool metadata once at import time — tools are static (listChanged: False).
try:
    _CACHED_TOOLS: list[Any] = asyncio.run(mcp.list_tools())
except RuntimeError:
    # Fallback for environments where an event loop is already running (e.g. ASGI, Jupyter)
    _CACHED_TOOLS = []
    logger.warning("Could not resolve MCP tool metadata at import time — tools/list will be empty")


def _handle_tools_list(request: HttpRequest, request_id: Any, params: dict[str, Any]) -> JsonResponse:
    """Handle MCP tools/list request using FastMCP's registered tools."""
    logger.info("MCP tools/list request received")
    tools_data = [
        {
            "name": tool.name,
            "description": tool.description or "",
            "inputSchema": tool.inputSchema,
        }
        for tool in _CACHED_TOOLS
    ]
    return _success_response(request_id, {"tools": tools_data})


def _handle_tools_call(request: HttpRequest, request_id: Any, params: dict[str, Any]) -> JsonResponse:
    """Handle MCP tools/call request.

    Calls tool functions directly in the sync WSGI context (not through
    FastMCP's async call_tool) to avoid Django's SynchronousOnlyOperation
    error when tools access the ORM.

    Tools that need auth context receive the Django request explicitly via
    a closure, so no thread-local state is needed.
    """
    tool_name: str = params.get("name", "")
    if "arguments" not in params:
        return _error_response(request_id, -32602, "Missing required field: arguments")
    arguments: dict[str, Any] = params.get("arguments", {})

    config = _TOOL_CONFIG.get(tool_name)
    if config is None:
        return _error_response(request_id, -32602, f"Unknown tool: {tool_name}")

    logger.info("MCP tools/call: tool='%s', argument_keys=%s", tool_name, list(arguments.keys()))

    if config["requires_auth"]:
        user = getattr(request, "user", None)
        if not user or not getattr(user, "org_id", None):
            return _error_response(request_id, -32000, "Authentication required")

    # Build tool callable with request closure for tools that need auth context
    tool_fn = config["fn"](request)

    try:
        result = tool_fn(**arguments)
        content = [{"type": "text", "text": result}]
        return _success_response(request_id, {"content": content, "isError": False})
    except TypeError as exc:
        return _error_response(request_id, -32602, f"Invalid params for tool '{tool_name}': {exc}")
    except Exception:
        logger.exception("Error executing MCP tool '%s'", tool_name)
        return _error_response(request_id, -32603, "Internal error executing tool")


# --- Tool configuration ---
#
# Single registry for tool execution and auth requirements.
# FastMCP is used only for schema generation (tools/list).
# Each tool's "fn" is a factory that receives the request and returns
# a callable(**arguments) -> str, allowing authenticated tools to
# access the request without thread-local state.

_TOOL_CONFIG: dict[str, dict[str, Any]] = {
    "hello": {
        "requires_auth": False,
        "fn": lambda request: lambda **kwargs: hello(**kwargs),
    },
    "list_principals": {
        "requires_auth": True,
        "fn": lambda request: lambda **kwargs: _list_principals_impl(request, **kwargs),
    },
}

_HANDLERS: dict[str, Any] = {
    "initialize": _handle_initialize,
    "tools/list": _handle_tools_list,
    "tools/call": _handle_tools_call,
}


# --- JSON-RPC response helpers ---


def _success_response(request_id: Any, result: dict[str, Any]) -> JsonResponse:
    """Create a JSON-RPC success response."""
    return JsonResponse({"jsonrpc": "2.0", "result": result, "id": request_id})


def _error_response(request_id: Any, code: int, message: str) -> JsonResponse:
    """Create a JSON-RPC error response."""
    return JsonResponse({"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": request_id})
