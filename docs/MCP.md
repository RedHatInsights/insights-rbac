# RBAC MCP Endpoint

This document describes the Model Context Protocol (MCP) endpoint for the RBAC service, which enables AI agents to discover and invoke RBAC operations via the standard MCP JSON-RPC 2.0 protocol.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Endpoint](#endpoint)
- [Authentication](#authentication)
- [Protocol](#protocol)
  - [Initialize](#initialize)
  - [List Tools](#list-tools)
  - [Call Tool](#call-tool)
  - [Notifications](#notifications)
  - [Session Termination](#session-termination)
- [Available Tools](#available-tools)
  - [hello](#hello)
  - [list_principals](#list_principals)
- [Adding New Tools](#adding-new-tools)
- [Local Development](#local-development)
- [Error Handling](#error-handling)
- [Key Files Reference](#key-files-reference)

---

## Overview

The MCP endpoint exposes RBAC operations as tools that any MCP-compatible client can discover and invoke. It implements the [MCP StreamableHTTP transport](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http) over a single HTTP POST endpoint.

| Property | Value |
|----------|-------|
| **Path** | `/_private/_a2s/mcp/` |
| **Transport** | StreamableHTTP (JSON-RPC 2.0 over HTTP POST) |
| **Auth** | `x-rh-identity` header (same as public API) |
| **Runtime** | Synchronous WSGI (Django) |

---

## Architecture

```
MCP Client (AI Agent)
    │
    │  JSON-RPC 2.0 over HTTP POST
    ▼
┌──────────────────────────────────────────────┐
│  IdentityHeaderMiddleware                    │
│  (A2S paths use public auth, not PSK/JWT)    │
└──────────────────────┬───────────────────────┘
                       ▼
┌──────────────────────────────────────────────┐
│  MCPView.post()                              │
│  ├─ _parse_jsonrpc()  → JsonRpcRequest       │
│  ├─ initialize        → protocol handshake   │
│  ├─ tools/list        → _get_tools() (async) │
│  └─ tools/call        → _TOOL_CONFIG lookup  │
│       ├─ hello()                  (no auth)   │
│       └─ list_principals(request) (auth)      │
│            └─ _clone_request() → PrincipalView│
└──────────────────────────────────────────────┘
```

**Key design decisions:**

- **Synchronous execution** — Tools run in the WSGI request thread to avoid Django's `SynchronousOnlyOperation` when accessing the ORM. FastMCP is used only for JSON schema generation (`tools/list`), not for dispatching tool calls.
- **A2S routing** — The endpoint lives under `/_private/_a2s/` (agent-to-service), which uses the same `x-rh-identity` auth as public APIs instead of the internal PSK/JWT auth normally applied to `/_private/` paths.
- **`@register_tool` decorator** — Registers each tool with both FastMCP (for schema) and `_TOOL_CONFIG` (for sync execution) in one declaration.

---

## Endpoint

```
POST /_private/_a2s/mcp/
```

All MCP protocol messages are sent as HTTP POST requests to this single endpoint. The JSON-RPC `method` field determines the operation.

| HTTP Method | Behavior |
|-------------|----------|
| `POST` | Handle MCP JSON-RPC requests |
| `GET` | Returns 405 (SSE streaming not supported in WSGI) |
| `DELETE` | Returns 200 (session termination acknowledgement) |

---

## Authentication

The MCP endpoint uses the same `x-rh-identity` header as the public RBAC API. See [AUTHENTICATION.md](AUTHENTICATION.md) for full details.

**Key points:**

- Tools marked `requires_auth=True` (e.g. `list_principals`) require a valid identity header with an `org_id`.
- Tools without auth requirements (e.g. `hello`) work without any identity header.
- Unauthenticated requests to auth-required tools receive a JSON-RPC error (`-32000 Authentication required`), not an HTTP 401.

---

## Protocol

The endpoint implements the MCP JSON-RPC 2.0 protocol. All requests must include:

```json
{
  "jsonrpc": "2.0",
  "method": "<method-name>",
  "id": <request-id>,
  "params": {}
}
```

### Initialize

Start a new MCP session. Returns protocol version and server capabilities.

**Request:**
```bash
curl -X POST http://localhost:8000/_private/_a2s/mcp/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "initialize",
    "id": 1,
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": {"name": "my-agent", "version": "1.0"}
    }
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "protocolVersion": "2025-03-26",
    "capabilities": {
      "tools": {"listChanged": false}
    },
    "serverInfo": {
      "name": "RBAC",
      "version": "1.0.0"
    }
  },
  "id": 1
}
```

The response includes an `Mcp-Session-Id` header for session tracking.

### List Tools

Discover available tools and their JSON Schema input definitions.

**Request:**
```bash
curl -X POST http://localhost:8000/_private/_a2s/mcp/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "tools": [
      {
        "name": "hello",
        "description": "Say hello or send a greeting to RBAC...",
        "inputSchema": {
          "type": "object",
          "properties": {
            "message": {"type": "string", "default": "Hello, World!"}
          }
        }
      },
      {
        "name": "list_principals",
        "description": "List principals (users) for the authenticated organization",
        "inputSchema": {
          "type": "object",
          "properties": {
            "limit": {"type": "integer", "default": 10},
            "offset": {"type": "integer", "default": 0},
            "sort_order": {"type": "string", "default": "asc"},
            "status": {"type": "string", "default": "enabled"},
            "username_only": {"type": "string", "default": "false"}
          }
        }
      }
    ]
  },
  "id": 2
}
```

### Call Tool

Invoke a tool by name with arguments.

**Request (unauthenticated tool):**
```bash
curl -X POST http://localhost:8000/_private/_a2s/mcp/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "id": 3,
    "params": {
      "name": "hello",
      "arguments": {"message": "Hi from my agent!"}
    }
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"response\": \"RBAC received your message: 'Hi from my agent!'\", \"date\": \"2025-01-15 10:30:00 UTC\"}"
      }
    ],
    "isError": false
  },
  "id": 3
}
```

**Request (authenticated tool):**
```bash
curl -X POST http://localhost:8000/_private/_a2s/mcp/ \
  -H "Content-Type: application/json" \
  -H "x-rh-identity: <base64-encoded-identity>" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "id": 4,
    "params": {
      "name": "list_principals",
      "arguments": {"limit": 5, "sort_order": "desc"}
    }
  }'
```

### Notifications

JSON-RPC requests without an `id` field are treated as notifications. The server acknowledges with HTTP 202 (no response body).

```bash
curl -X POST http://localhost:8000/_private/_a2s/mcp/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}'
# Returns HTTP 202
```

### Session Termination

```bash
curl -X DELETE http://localhost:8000/_private/_a2s/mcp/
# Returns HTTP 200
```

---

## Available Tools

### hello

A simple greeting tool for smoke-testing connectivity. No authentication required.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `message` | string | `"Hello, World!"` | Message to send |

**Example:**
```json
{"name": "hello", "arguments": {"message": "Testing!"}}
```

**Returns:** JSON with `response` (echoed message) and `date` (server UTC timestamp).

### list_principals

Lists principals (users) for the authenticated organization. Requires a valid `x-rh-identity` header.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | `10` | Max results to return |
| `offset` | integer | `0` | Pagination offset |
| `sort_order` | string | `"asc"` | Sort order (`asc` or `desc`) |
| `status` | string | `"enabled"` | Filter by status |
| `username_only` | string | `"false"` | Return only usernames |

**Example:**
```json
{"name": "list_principals", "arguments": {"limit": 5}}
```

**Returns:** JSON array of principal objects from the RBAC database, matching the `/api/rbac/v1/principals/` response format.

---

## Adding New Tools

Use the `@register_tool` decorator to add new tools. It handles both FastMCP schema registration and sync execution configuration automatically.

### Basic tool (no auth)

```python
@register_tool(description="Describe what the tool does")
def my_tool(param1: str, param2: int = 10) -> str:
    """Implement the tool logic."""
    result = do_something(param1, param2)
    return json.dumps(result)
```

### Authenticated tool (receives Django request)

```python
@register_tool(description="Tool that needs user context", requires_auth=True)
def my_auth_tool(request: HttpRequest, *, limit: int = 10) -> str:
    """Tool that delegates to an existing Django view."""
    path = reverse("v1_management:some-view")
    view_request = _clone_request(request, path, data={"limit": str(limit)})
    response = _some_view(view_request)
    return json.dumps(response.data, default=str)
```

### How it works

1. The decorator inspects the function signature. If the first parameter is `request`, it creates a schema-only wrapper (without `request`) for FastMCP, so the JSON schema only includes user-facing parameters.
2. `requires_auth=True` means the tool will reject calls without a valid identity header.
3. `_clone_request()` copies auth context (user, tenant, identity header) and tracing headers (`X-Request-ID`, `X-RH-Insights-Request-ID`) from the MCP request to the internal view request.
4. Tool functions must return a `str`. Use `json.dumps()` for structured output.

---

## Local Development

### Start the server

```bash
# With development mode (auto identity injection)
DEVELOPMENT=True make serve

# Or with manual identity header
make serve
```

### Full session example

```bash
# 1. Initialize
curl -s -X POST http://localhost:8000/_private/_a2s/mcp/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2025-03-26","capabilities":{}}}' | python3 -m json.tool

# 2. List available tools
curl -s -X POST http://localhost:8000/_private/_a2s/mcp/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2,"params":{}}' | python3 -m json.tool

# 3. Call hello (no auth needed)
curl -s -X POST http://localhost:8000/_private/_a2s/mcp/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"hello","arguments":{"message":"Hi!"}}}' | python3 -m json.tool

# 4. Call list_principals (needs auth — use dev mode or provide x-rh-identity)
curl -s -X POST http://localhost:8000/_private/_a2s/mcp/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":4,"params":{"name":"list_principals","arguments":{"limit":3}}}' | python3 -m json.tool

# 5. End session
curl -X DELETE http://localhost:8000/_private/_a2s/mcp/
```

### Run tests

```bash
# MCP tests only
tox -e py312 -- tests.management.test_mcp_views

# Full test suite
tox -r
```

---

## Error Handling

All errors follow the JSON-RPC 2.0 error response format:

```json
{
  "jsonrpc": "2.0",
  "error": {"code": -32602, "message": "Unknown tool: foo"},
  "id": 3
}
```

### Error codes

| Code | Meaning | Example |
|------|---------|---------|
| `-32700` | Parse error | Malformed JSON body |
| `-32600` | Invalid Request | Missing `jsonrpc: "2.0"`, batch requests, non-string method |
| `-32601` | Method not found | Unknown JSON-RPC method (not `initialize`/`tools/list`/`tools/call`) |
| `-32602` | Invalid params | Unknown tool name, missing `arguments`, invalid argument types |
| `-32603` | Internal error | Unhandled exception in tool execution |
| `-32000` | Authentication required | Auth-required tool called without valid identity |

---

## Key Files Reference

| File | Description |
|------|-------------|
| `rbac/management/mcp_views.py` | MCP endpoint implementation (`MCPView`, tools, JSON-RPC handling) |
| `rbac/management/mcp_urls.py` | URL routing for MCP endpoint |
| `rbac/rbac/a2s.py` | `is_a2s_path()` helper shared by both middleware classes |
| `rbac/rbac/middleware.py` | A2S bypass in `IdentityHeaderMiddleware` |
| `rbac/internal/middleware.py` | A2S bypass in `InternalIdentityHeaderMiddleware` |
| `rbac/rbac/settings.py` | `A2S_PATH_PREFIX`, `CORS_EXPOSE_HEADERS` settings |
| `rbac/rbac/urls.py` | Top-level URL routing for `/_private/_a2s/` |
| `tests/management/test_mcp_views.py` | Comprehensive test suite (30+ tests) |
