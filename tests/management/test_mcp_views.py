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
"""Test the MCP views via _private/_a2s/ path."""

import json
import time
from importlib import reload
from unittest.mock import patch

from django.test import override_settings
from django.urls import clear_url_caches
from django.utils import timezone
from management.mcp_views import (
    ApiVersion,
    ToolConfig,
    ToolTimeoutError,
    _TOOL_CONFIG,
    _execute_with_timeout,
    _permission_matches,
)
from management.models import Access, AuditLog, Group, Permission, Policy, Principal, Role
from management.role.v2_model import RoleV2
from management.role_binding.model import RoleBinding, RoleBindingGroup, RoleBindingPrincipal
from management.tenant_mapping.model import TenantMapping
from rest_framework import status
from rest_framework.test import APIClient
from tests.identity_request import IdentityRequest

from api.models import Tenant
from rbac import urls


class MCPToolTestMixin:
    """Shared helpers for calling MCP tools in tests."""

    def _call_tool(self, tool_name, arguments=None, use_auth=True):
        """Helper to call an MCP tool and return the parsed response."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 100,
            "params": {"name": tool_name, "arguments": arguments or {}},
        }
        kwargs = {"data": json.dumps(body), "content_type": "application/json"}
        if use_auth:
            kwargs.update(self.headers)
        return self.client.post(self.url, **kwargs)

    def _get_tool_output(self, response):
        """Extract tool output from MCP response."""
        data = response.json()
        return json.loads(data["result"]["content"][0]["text"])


class MCPViewTests(MCPToolTestMixin, IdentityRequest):
    """Test the MCP endpoint at /_private/_a2s/mcp/ (agent-to-service with public auth)."""

    def setUp(self):
        """Set up the MCP view tests."""
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()
        self.principal = Principal.objects.create(username="test_user", tenant=self.tenant)

    def tearDown(self):
        """Tear down MCP view tests."""
        AuditLog.objects.all().delete()
        Policy.objects.all().delete()
        Role.objects.all().delete()
        Group.objects.all().delete()
        Principal.objects.all().delete()
        super().tearDown()

    # --- Protocol tests ---

    def test_initialize_returns_server_info(self):
        """Positive: MCP initialize returns server capabilities."""
        body = {"jsonrpc": "2.0", "method": "initialize", "id": 1, "params": {}}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["jsonrpc"], "2.0")
        self.assertEqual(data["id"], 1)
        result = data["result"]
        self.assertEqual(result["protocolVersion"], "2025-03-26")
        self.assertIn("tools", result["capabilities"])
        self.assertEqual(result["serverInfo"]["name"], "RBAC")
        self.assertIn("Mcp-Session-Id", response)

    def test_notification_returns_202(self):
        """Positive: JSON-RPC notification (no id) returns 202."""
        body = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, 202)

    def test_tools_list_returns_list_principals_tool(self):
        """Positive: tools/list returns the list_principals tool with schema."""
        body = {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        tools = data["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("list_principals", tool_names)

        tool = next(t for t in tools if t["name"] == "list_principals")
        self.assertIn("inputSchema", tool)
        schema = tool["inputSchema"]
        self.assertIn("limit", schema["properties"])
        self.assertIn("offset", schema["properties"])
        self.assertIn("sort_order", schema["properties"])

    def test_unknown_method_returns_error(self):
        """Negative: Unknown method returns -32601 error."""
        body = {"jsonrpc": "2.0", "method": "unknown/method", "id": 3, "params": {}}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32601)
        self.assertIn("Method not found", data["error"]["message"])

    def test_invalid_json_returns_parse_error(self):
        """Negative: Invalid JSON returns -32700 parse error."""
        response = self.client.post(self.url, data="not json", content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32700)

    def test_invalid_jsonrpc_version_returns_error(self):
        """Negative: Wrong jsonrpc version returns -32600 error."""
        body = {"jsonrpc": "1.0", "method": "initialize", "id": 4, "params": {}}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32600)

    def test_missing_method_returns_error(self):
        """Negative: Missing method field returns -32600 error."""
        body = {"jsonrpc": "2.0", "id": 40, "params": {}}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32600)
        self.assertIn("method", data["error"]["message"])

    def test_notification_without_method_returns_error(self):
        """Negative: Notification (no id) without method returns -32600 error."""
        body = {"jsonrpc": "2.0"}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32600)

    def test_get_returns_405(self):
        """Negative: GET request returns 405 (SSE not supported in WSGI)."""
        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 405)

    def test_delete_returns_200(self):
        """Positive: DELETE for session termination returns 200."""
        response = self.client.delete(self.url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_tools_list_returns_hello_tool(self):
        """Positive: tools/list includes the hello tool with message param."""
        body = {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tools = response.json()["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("hello", tool_names)

        hello_tool = next(t for t in tools if t["name"] == "hello")
        self.assertIn("message", hello_tool["inputSchema"]["properties"])

    # --- Tool execution tests ---

    def test_tools_call_hello_with_default(self):
        """Positive: hello tool returns date and default message."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 20,
            "params": {"name": "hello", "arguments": {}},
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        result = data["result"]
        self.assertFalse(result["isError"])
        tool_output = json.loads(result["content"][0]["text"])
        self.assertEqual(tool_output["response"], "RBAC received your message: 'Hello, World!'")
        self.assertIn("date", tool_output)

    def test_tools_call_hello_with_custom_message(self):
        """Positive: hello tool echoes back custom message."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 21,
            "params": {"name": "hello", "arguments": {"message": "Hi from LLM!"}},
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = json.loads(response.json()["result"]["content"][0]["text"])
        self.assertEqual(tool_output["response"], "RBAC received your message: 'Hi from LLM!'")
        self.assertRegex(tool_output["date"], r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": [{"username": "test_user", "email": "test@example.com"}],
            "userCount": 1,
        },
    )
    def test_tools_call_list_principals_success(self, mock_request):
        """Positive: tools/call list_principals returns principal data via PrincipalView."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 5,
            "params": {
                "name": "list_principals",
                "arguments": {"limit": 10, "offset": 0},
            },
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["id"], 5)
        result = data["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(len(result["content"]), 1)
        self.assertEqual(result["content"][0]["type"], "text")

        tool_output = json.loads(result["content"][0]["text"])
        self.assertEqual(tool_output["meta"]["count"], 1)
        self.assertIn("links", tool_output)
        self.assertEqual(len(tool_output["data"]), 1)
        self.assertEqual(tool_output["data"][0]["username"], "test_user")

    @patch("management.mcp_views._principal_view")
    def test_tools_call_list_principals_non_drf_response(self, mock_principal_view):
        """Positive: tools/call handles plain HttpResponse (non-DRF) via content.decode() fallback."""
        from django.http import HttpResponse as DjangoHttpResponse

        payload = {"data": [{"username": "plain_user"}], "meta": {"count": 1}}
        mock_principal_view.return_value = DjangoHttpResponse(
            json.dumps(payload), content_type="application/json", status=200
        )

        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 50,
            "params": {"name": "list_principals", "arguments": {}},
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["id"], 50)
        result = data["result"]
        self.assertFalse(result["isError"])
        tool_output = json.loads(result["content"][0]["text"])
        self.assertEqual(tool_output["data"][0]["username"], "plain_user")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": {"userCount": "2", "users": [{"username": "user1"}, {"username": "user2"}]},
        },
    )
    def test_tools_call_list_principals_dict_response(self, mock_request):
        """Positive: tools/call handles dict-style proxy response."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 6,
            "params": {
                "name": "list_principals",
                "arguments": {"limit": 5, "offset": 0, "sort_order": "desc"},
            },
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        tool_output = json.loads(data["result"]["content"][0]["text"])
        self.assertEqual(tool_output["meta"]["count"], "2")
        self.assertEqual(len(tool_output["data"]), 2)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": [{"username": "test_user"}],
            "userCount": 1,
        },
    )
    def test_tools_call_passes_options_to_proxy(self, mock_request):
        """Positive: tools/call passes correct options to PrincipalProxy via PrincipalView."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 7,
            "params": {
                "name": "list_principals",
                "arguments": {
                    "limit": 20,
                    "offset": 5,
                    "sort_order": "desc",
                    "status": "disabled",
                    "username_only": "true",
                },
            },
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_request.assert_called_once_with(
            org_id=self.customer_data["org_id"],
            limit=20,
            offset=5,
            options={
                "limit": 20,
                "offset": 5,
                "sort_order": "desc",
                "status": "disabled",
                "username_only": "true",
                "principal_type": "user",
                "admin_only": "false",
            },
        )

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 500,
            "errors": [{"detail": "Unexpected error.", "status": "500", "source": "principals"}],
        },
    )
    def test_tools_call_list_principals_proxy_error(self, mock_request):
        """Negative: tools/call handles proxy error gracefully via PrincipalView."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 8,
            "params": {
                "name": "list_principals",
                "arguments": {},
            },
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertNotIn("error", data)
        self.assertFalse(data["result"]["isError"])
        tool_output = json.loads(data["result"]["content"][0]["text"])
        self.assertIn("errors", tool_output)

    def test_tools_call_unknown_tool_returns_error(self):
        """Negative: Calling an unknown tool returns error."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 9,
            "params": {
                "name": "nonexistent_tool",
                "arguments": {},
            },
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32602)
        self.assertEqual(data["error"]["message"], "Unknown tool: nonexistent_tool")

    @patch.dict(
        "management.mcp_views._TOOL_CONFIG",
        {"hello": ToolConfig(fn=lambda **kw: (_ for _ in ()).throw(Exception("boom")))},
    )
    def test_tools_call_internal_error_returns_32603(self):
        """Negative: tool raising an exception returns JSON-RPC -32603."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 30,
            "params": {"name": "hello", "arguments": {}},
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32603)

    def test_non_dict_params_returns_invalid_request(self):
        """Negative: params as a list instead of object returns -32600."""
        body = {"jsonrpc": "2.0", "method": "tools/call", "id": 32, "params": [1, 2, 3]}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32600)
        self.assertIn("params must be an object", data["error"]["message"])

    def test_tools_call_missing_name_returns_unknown_tool(self):
        """Negative: tools/call without name returns unknown tool error."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 34,
            "params": {"arguments": {}},
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32602)
        self.assertIn("Unknown tool", data["error"]["message"])

    def test_tools_call_non_dict_arguments_returns_32602(self):
        """Negative: tools/call with non-dict arguments returns -32602."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 35,
            "params": {"name": "hello", "arguments": "not a dict"},
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32602)
        self.assertIn("arguments must be an object", data["error"]["message"])

    def test_tools_call_missing_arguments_returns_32602(self):
        """Negative: tools/call without arguments field returns -32602."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 33,
            "params": {"name": "hello"},
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32602)
        self.assertIn("arguments", data["error"]["message"])

    def test_batch_request_returns_parse_error(self):
        """Negative: JSON-RPC batch request (array) is not supported and returns -32600."""
        batch = [
            {"jsonrpc": "2.0", "method": "initialize", "id": 1, "params": {}},
            {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}},
        ]
        response = self.client.post(self.url, data=json.dumps(batch), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32600)

    def test_tools_call_invalid_params_returns_32602(self):
        """Negative: passing wrong argument types returns JSON-RPC -32602."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 31,
            "params": {"name": "hello", "arguments": {"message": 123, "unknown_param": "x"}},
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32602)

    # --- Authentication tests ---

    def test_hello_works_without_auth(self):
        """Positive: hello tool works without x-rh-identity header."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 10,
            "params": {"name": "hello", "arguments": {"message": "Hey!"}},
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = json.loads(response.json()["result"]["content"][0]["text"])
        self.assertEqual(tool_output["response"], "RBAC received your message: 'Hey!'")

    def test_list_principals_without_auth_returns_error(self):
        """Permission: list_principals without x-rh-identity returns auth error."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 11,
            "params": {"name": "list_principals", "arguments": {}},
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertNotIn("result", data)
        self.assertEqual(data["error"]["code"], -32000)

    # --- Edge cases ---

    def test_tools_call_with_default_arguments(self):
        """Edge case: tools/call with empty arguments uses defaults."""
        with patch(
            "management.principal.proxy.PrincipalProxy.request_principals",
            return_value={"status_code": 200, "data": [], "userCount": 0},
        ) as mock_request:
            body = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": 11,
                "params": {
                    "name": "list_principals",
                    "arguments": {},
                },
            }
            response = self.client.post(
                self.url, data=json.dumps(body), content_type="application/json", **self.headers
            )

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            mock_request.assert_called_once_with(
                org_id=self.customer_data["org_id"],
                limit=10,
                offset=0,
                options={
                    "limit": 10,
                    "offset": 0,
                    "sort_order": "asc",
                    "status": "enabled",
                    "username_only": "false",
                    "principal_type": "user",
                    "admin_only": "false",
                },
            )

    def test_tools_call_with_invalid_sort_order_returns_validation_error(self):
        """Edge case: Invalid sort_order returns validation error from PrincipalView."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 12,
            "params": {
                "name": "list_principals",
                "arguments": {"sort_order": "invalid"},
            },
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertNotIn("error", data)
        result = data["result"]
        self.assertFalse(result["isError"])
        tool_output = json.loads(result["content"][0]["text"])
        self.assertIn("errors", tool_output)
        self.assertIn("invalid", tool_output["errors"][0]["detail"])

    def test_tools_call_with_string_id(self):
        """Edge case: JSON-RPC request with string id works."""
        with patch(
            "management.principal.proxy.PrincipalProxy.request_principals",
            return_value={"status_code": 200, "data": [], "userCount": 0},
        ):
            body = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "id": "abc-123",
                "params": {
                    "name": "list_principals",
                    "arguments": {},
                },
            }
            response = self.client.post(
                self.url, data=json.dumps(body), content_type="application/json", **self.headers
            )

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            data = response.json()
            self.assertEqual(data["id"], "abc-123")

    # --- New read-only tools tests ---

    def test_tools_list_includes_non_v2_tools(self):
        """Positive: tools/list includes all non-V2-only tools when V2 is disabled."""
        body = {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_names = [t["name"] for t in response.json()["result"]["tools"]]
        expected_tools = [
            "get_status",
            "list_access",
            "list_permissions",
            "list_permission_options",
            "list_audit_logs",
            "search_roles",
            "get_role",
            "list_role_access",
            "list_groups",
            "get_group",
            "list_group_principals",
            "list_group_roles",
            "list_cross_account_requests",
            "get_cross_account_request",
            "list_workspaces",
            "get_workspace",
            "check_user_permission",
        ]
        for tool in expected_tools:
            self.assertIn(tool, tool_names, f"Tool '{tool}' missing from tools/list")

    def test_tools_list_excludes_v2_only_tools_when_v2_disabled(self):
        """Negative: V2-only tools are hidden when V2_APIS_ENABLED=False."""
        body = {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_names = [t["name"] for t in response.json()["result"]["tools"]]
        v2_only_tools = [name for name, cfg in _TOOL_CONFIG.items() if cfg.api_version == ApiVersion.V2]
        for tool in v2_only_tools:
            self.assertNotIn(tool, tool_names, f"V2-only tool '{tool}' should be hidden")

    # --- get_status ---

    def test_get_status_returns_server_info(self):
        """Positive: get_status returns server status with auth."""
        response = self._call_tool("get_status")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("api_version", tool_output)
        self.assertIn("commit", tool_output)

    # --- list_permissions ---

    def test_list_permissions_success(self):
        """Positive: list_permissions returns permission data."""
        Permission.objects.create(
            application="rbac",
            resource_type="roles",
            verb="read",
            permission="rbac:roles:read",
            tenant=self.tenant,
        )
        response = self._call_tool("list_permissions")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("meta", tool_output)
        self.assertIn("data", tool_output)

    def test_list_permissions_filters_by_application(self):
        """Positive: list_permissions filters results by application argument."""
        Permission.objects.create(
            application="rbac",
            resource_type="roles",
            verb="read",
            permission="rbac:roles:read",
            tenant=self.tenant,
        )
        Permission.objects.create(
            application="cost-management",
            resource_type="reports",
            verb="read",
            permission="cost-management:reports:read",
            tenant=self.tenant,
        )
        response = self._call_tool("list_permissions", {"application": "rbac"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        permissions = tool_output["data"]
        self.assertTrue(len(permissions) >= 1)
        for perm in permissions:
            self.assertTrue(perm["permission"].startswith("rbac:"))

    def test_list_permissions_without_auth_returns_error(self):
        """Permission: list_permissions without auth returns auth error."""
        response = self._call_tool("list_permissions", use_auth=False)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)

    # --- list_audit_logs ---

    def test_list_audit_logs_success(self):
        """Positive: list_audit_logs returns audit log data."""
        response = self._call_tool("list_audit_logs")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("meta", tool_output)
        self.assertIn("data", tool_output)

    def test_list_audit_logs_without_auth_returns_error(self):
        """Permission: list_audit_logs without auth returns auth error."""
        response = self._call_tool("list_audit_logs", use_auth=False)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)

    def test_list_audit_logs_filter_by_principal_username(self):
        """Positive: list_audit_logs filters by principal_username."""
        AuditLog.objects.create(
            principal_username="jdoe",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="role added to group",
            tenant=self.tenant,
        )
        AuditLog.objects.create(
            principal_username="other_user",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="other action",
            tenant=self.tenant,
        )

        response = self._call_tool("list_audit_logs", {"principal_username": "jdoe"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        self.assertEqual(len(tool_output["data"]), 1)
        self.assertEqual(tool_output["data"][0]["principal_username"], "jdoe")

    def test_list_audit_logs_filter_by_resource_type(self):
        """Positive: list_audit_logs filters by resource_type."""
        AuditLog.objects.create(
            principal_username="user1",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="group action",
            tenant=self.tenant,
        )
        AuditLog.objects.create(
            principal_username="user1",
            resource_type=AuditLog.ROLE,
            action=AuditLog.CREATE,
            description="role action",
            tenant=self.tenant,
        )

        response = self._call_tool("list_audit_logs", {"resource_type": "group"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        self.assertEqual(len(tool_output["data"]), 1)
        self.assertEqual(tool_output["data"][0]["resource_type"], "group")

    def test_list_audit_logs_filter_by_action(self):
        """Positive: list_audit_logs filters by action."""
        AuditLog.objects.create(
            principal_username="user1",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="add action",
            tenant=self.tenant,
        )
        AuditLog.objects.create(
            principal_username="user1",
            resource_type=AuditLog.GROUP,
            action=AuditLog.DELETE,
            description="delete action",
            tenant=self.tenant,
        )

        response = self._call_tool("list_audit_logs", {"action": "add"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        self.assertEqual(len(tool_output["data"]), 1)
        self.assertEqual(tool_output["data"][0]["action"], "add")

    @patch(
        "management.mcp_views.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"is_org_admin": False}]},
    )
    def test_list_audit_logs_include_authorization(self, mock_proxy):
        """Positive: list_audit_logs with include_authorization returns role and permission."""
        # Create audit log entry
        AuditLog.objects.create(
            principal_username=self.principal.username,
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="Vulnerability administrator role added to group Contractors",
            tenant=self.tenant,
        )

        # Set up authorization chain: principal -> group -> policy -> role -> access -> permission
        role = Role.objects.create(name="User Access administrator", tenant=self.tenant)
        perm = Permission.objects.create(
            application="rbac",
            resource_type="group",
            verb="write",
            permission="rbac:group:write",
            tenant=self.tenant,
        )
        Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        group = Group.objects.create(name="Access Governance", tenant=self.tenant)
        group.principals.add(self.principal)
        policy = Policy.objects.create(name="auth_policy", group=group, tenant=self.tenant)
        policy.roles.add(role)

        response = self._call_tool("list_audit_logs", {"include_authorization": True})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        self.assertEqual(len(tool_output["data"]), 1)
        entry = tool_output["data"][0]
        self.assertIn("authorized_by", entry)
        self.assertEqual(entry["authorized_by"]["role"], "User Access administrator")
        self.assertEqual(entry["authorized_by"]["via_group"], "Access Governance")
        self.assertEqual(entry["authorized_by"]["permission"], "rbac:group:write")

    @patch(
        "management.mcp_views.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_list_audit_logs_include_authorization_user_not_found(self, mock_proxy):
        """Positive: list_audit_logs handles deleted/unknown users."""
        AuditLog.objects.create(
            principal_username="deleted_user",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="action by deleted user",
            tenant=self.tenant,
        )

        response = self._call_tool("list_audit_logs", {"include_authorization": True})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        entry = tool_output["data"][0]
        self.assertIsNone(entry["authorized_by"])
        self.assertIn("note", entry)
        self.assertIn("deleted_user", entry["note"])

    @patch(
        "management.mcp_views.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"is_org_admin": True}]},
    )
    def test_list_audit_logs_include_authorization_org_admin(self, mock_proxy):
        """Positive: list_audit_logs shows org admin bypasses RBAC checks."""
        AuditLog.objects.create(
            principal_username="org_admin_user",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="action by org admin",
            tenant=self.tenant,
        )

        response = self._call_tool("list_audit_logs", {"include_authorization": True})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        entry = tool_output["data"][0]
        self.assertIsNotNone(entry["authorized_by"])
        self.assertEqual(entry["authorized_by"]["role"], "Org Admin")
        self.assertIn("bypasses all RBAC", entry["authorized_by"]["permission"])

    def test_list_audit_logs_invalid_order_by(self):
        """Negative: list_audit_logs with invalid order_by returns error."""
        response = self._call_tool("list_audit_logs", {"order_by": "invalid_field"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        self.assertIn("error", tool_output)
        self.assertIn("Invalid order_by", tool_output["error"])

    def test_list_audit_logs_empty_page_returns_total_count(self):
        """Positive: list_audit_logs returns total count even when offset is past end."""
        AuditLog.objects.create(
            principal_username="user1",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="test entry",
            tenant=self.tenant,
        )

        response = self._call_tool("list_audit_logs", {"offset": 1000, "limit": 10})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        self.assertEqual(len(tool_output["data"]), 0)
        self.assertEqual(tool_output["meta"]["count"], 1)

    def test_list_audit_logs_filter_by_group_name(self):
        """Positive: list_audit_logs filters by group_name in description."""
        AuditLog.objects.create(
            principal_username="user1",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="role test_role added to group: target_group_alpha",
            tenant=self.tenant,
        )
        AuditLog.objects.create(
            principal_username="user2",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="role other_role added to group: other_group_beta",
            tenant=self.tenant,
        )

        response = self._call_tool("list_audit_logs", {"group_name": "target_group_alpha"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        self.assertEqual(tool_output["meta"]["count"], 1)
        self.assertEqual(len(tool_output["data"]), 1)
        self.assertIn("target_group_alpha", tool_output["data"][0]["description"])

    def test_list_audit_logs_filter_by_role_name(self):
        """Positive: list_audit_logs filters by role_name in description."""
        AuditLog.objects.create(
            principal_username="user1",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="role target_role_alpha added to group: some_group",
            tenant=self.tenant,
        )
        AuditLog.objects.create(
            principal_username="user2",
            resource_type=AuditLog.GROUP,
            action=AuditLog.ADD,
            description="role other_role_beta added to group: some_group",
            tenant=self.tenant,
        )

        response = self._call_tool("list_audit_logs", {"role_name": "target_role_alpha"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        self.assertEqual(tool_output["meta"]["count"], 1)
        self.assertEqual(len(tool_output["data"]), 1)
        self.assertIn("target_role_alpha", tool_output["data"][0]["description"])

    # --- list_groups / get_group / list_group_principals ---

    def test_list_groups_success(self):
        """Positive: list_groups returns group data."""
        Group.objects.create(name="test_group", tenant=self.tenant)
        response = self._call_tool("list_groups")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("meta", tool_output)
        self.assertIn("data", tool_output)

    def test_list_groups_without_auth_returns_error(self):
        """Permission: list_groups without auth returns auth error."""
        response = self._call_tool("list_groups", use_auth=False)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)

    def test_get_group_success(self):
        """Positive: get_group returns group detail."""
        group = Group.objects.create(name="detail_group", tenant=self.tenant)
        response = self._call_tool("get_group", {"group_uuid": str(group.uuid)})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertEqual(tool_output["name"], "detail_group")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [{"username": "test_user"}],
        },
    )
    def test_list_group_principals_success(self, mock_request):
        """Positive: list_group_principals returns principals in group."""
        group = Group.objects.create(name="principals_group", tenant=self.tenant)
        group.principals.add(self.principal)
        response = self._call_tool("list_group_principals", {"group_uuid": str(group.uuid)})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("data", tool_output)

    # --- list_cross_account_requests / get_cross_account_request ---

    def test_list_cross_account_requests_success(self):
        """Positive: list_cross_account_requests returns request data."""
        response = self._call_tool("list_cross_account_requests")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("meta", tool_output)
        self.assertIn("data", tool_output)

    def test_list_cross_account_requests_without_auth_returns_error(self):
        """Permission: list_cross_account_requests without auth returns auth error."""
        response = self._call_tool("list_cross_account_requests", use_auth=False)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)

    # --- list_access ---

    def test_list_access_success(self):
        """Positive: list_access returns access data for the authenticated principal."""
        role = Role.objects.create(name="access_role", tenant=self.tenant)
        perm = Permission.objects.create(
            application="rbac",
            resource_type="roles",
            verb="read",
            permission="rbac:roles:read",
            tenant=self.tenant,
        )
        Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        group = Group.objects.create(name="access_group", tenant=self.tenant)
        group.principals.add(self.principal)
        policy = Policy.objects.create(name="access_policy", group=group, tenant=self.tenant)
        policy.roles.add(role)

        response = self._call_tool("list_access", {"application": "rbac"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("data", tool_output)

    def test_list_access_without_auth_returns_error(self):
        """Permission: list_access without auth returns auth error."""
        response = self._call_tool("list_access", {"application": "rbac"}, use_auth=False)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)

    # --- list_permission_options ---

    def test_list_permission_options_success(self):
        """Positive: list_permission_options returns distinct field values."""
        Permission.objects.create(
            application="rbac",
            resource_type="roles",
            verb="read",
            permission="rbac:roles:read",
            tenant=self.tenant,
        )
        Permission.objects.create(
            application="cost-management",
            resource_type="reports",
            verb="read",
            permission="cost-management:reports:read",
            tenant=self.tenant,
        )
        response = self._call_tool("list_permission_options", {"field": "application"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("data", tool_output)
        self.assertIn("meta", tool_output)

    def test_list_permission_options_without_auth_returns_error(self):
        """Permission: list_permission_options without auth returns auth error."""
        response = self._call_tool("list_permission_options", {"field": "application"}, use_auth=False)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)

    # --- list_group_roles ---

    def test_list_group_roles_success(self):
        """Positive: list_group_roles returns roles for a group."""
        group = Group.objects.create(name="roles_group", tenant=self.tenant)
        role = Role.objects.create(name="test_role", tenant=self.tenant)
        policy = Policy.objects.create(name="test_policy", group=group, tenant=self.tenant)
        policy.roles.add(role)

        response = self._call_tool("list_group_roles", {"group_uuid": str(group.uuid)})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("data", tool_output)

    def test_list_group_roles_without_auth_returns_error(self):
        """Permission: list_group_roles without auth returns auth error."""
        response = self._call_tool(
            "list_group_roles",
            {"group_uuid": "00000000-0000-0000-0000-000000000000"},
            use_auth=False,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)

    def test_list_group_roles_by_name(self):
        """Positive: list_group_roles accepts group_name instead of group_uuid."""
        group = Group.objects.create(name="group_for_roles_test", tenant=self.tenant)
        role = Role.objects.create(name="role_alpha", tenant=self.tenant)
        policy = Policy.objects.create(name="policy_alpha", group=group, tenant=self.tenant)
        policy.roles.add(role)

        response = self._call_tool("list_group_roles", {"group_name": "group_for_roles_test"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("data", tool_output)
        self.assertEqual(tool_output["meta"]["count"], 1)
        self.assertEqual(tool_output["data"][0]["name"], "role_alpha")

    def test_list_group_roles_by_name_case_insensitive(self):
        """Positive: list_group_roles group_name lookup is case-insensitive."""
        group = Group.objects.create(name="Group_With_Mixed_Case", tenant=self.tenant)
        role = Role.objects.create(name="role_beta", tenant=self.tenant)
        policy = Policy.objects.create(name="policy_beta", group=group, tenant=self.tenant)
        policy.roles.add(role)

        response = self._call_tool("list_group_roles", {"group_name": "group_with_mixed_case"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertEqual(tool_output["meta"]["count"], 1)
        self.assertEqual(tool_output["data"][0]["name"], "role_beta")

    def test_list_group_roles_missing_both_params_returns_error(self):
        """Negative: list_group_roles without group_uuid or group_name returns error."""
        response = self._call_tool("list_group_roles", {})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        self.assertIn("error", tool_output)
        self.assertIn("Either group_uuid or group_name is required", tool_output["error"])

    def test_list_group_roles_group_not_found_returns_error(self):
        """Negative: list_group_roles with non-existent group_name returns error."""
        response = self._call_tool("list_group_roles", {"group_name": "nonexistent_group_xyz"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)
        self.assertIn("error", tool_output)
        self.assertIn("not found", tool_output["error"])

    # --- list_role_access ---

    def test_list_role_access_success(self):
        """Positive: list_role_access returns access for a role."""
        role = Role.objects.create(name="access_detail_role", tenant=self.tenant)
        perm = Permission.objects.create(
            application="rbac",
            resource_type="principals",
            verb="read",
            permission="rbac:principals:read",
            tenant=self.tenant,
        )
        Access.objects.create(permission=perm, role=role, tenant=self.tenant)

        response = self._call_tool("list_role_access", {"role_uuid": str(role.uuid)})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("data", tool_output)
        self.assertTrue(len(tool_output["data"]) >= 1)

    def test_list_role_access_without_auth_returns_error(self):
        """Permission: list_role_access without auth returns auth error."""
        response = self._call_tool(
            "list_role_access",
            {"role_uuid": "00000000-0000-0000-0000-000000000000"},
            use_auth=False,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)


@override_settings(V2_APIS_ENABLED=True)
class MCPViewV2ToolsTests(MCPToolTestMixin, IdentityRequest):
    """Test the MCP V2 tools that require V2_APIS_ENABLED=True."""

    def setUp(self):
        """Set up the MCP V2 tool tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()
        self.principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        self.enterContext(
            patch(
                "management.permissions.role_v2_access.get_kessel_principal_id",
                return_value="localhost/test-user-id",
            )
        )
        self.enterContext(
            patch(
                "management.permissions.role_v2_access.WorkspaceInventoryAccessChecker.check_resource_access",
                return_value=True,
            )
        )

    def tearDown(self):
        """Tear down MCP V2 tool tests."""
        Principal.objects.all().delete()
        super().tearDown()

    # --- V2 gating: tools/list includes V2-only tools ---

    def test_tools_list_includes_v2_only_tools_when_v2_enabled(self):
        """Positive: V2-only tools are visible when V2_APIS_ENABLED=True."""
        body = {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_names = [t["name"] for t in response.json()["result"]["tools"]]
        self.assertIn("list_role_bindings", tool_names)
        self.assertIn("list_role_bindings_by_subject", tool_names)

    # --- list_workspaces / get_workspace ---

    def test_list_workspaces_success(self):
        """Positive: list_workspaces returns workspace data."""
        response = self._call_tool("list_workspaces")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("meta", tool_output)
        self.assertIn("data", tool_output)

    def test_list_workspaces_without_auth_returns_error(self):
        """Permission: list_workspaces without auth returns auth error."""
        response = self._call_tool("list_workspaces", use_auth=False)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)

    # --- list_role_bindings ---

    def test_list_role_bindings_success(self):
        """Positive: list_role_bindings returns role binding data."""
        response = self._call_tool("list_role_bindings")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("meta", tool_output)
        self.assertIn("data", tool_output)

    def test_list_role_bindings_without_auth_returns_error(self):
        """Permission: list_role_bindings without auth returns auth error."""
        response = self._call_tool("list_role_bindings", use_auth=False)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)

    # --- list_role_bindings_by_subject ---

    def test_list_role_bindings_by_subject_without_auth_returns_error(self):
        """Permission: list_role_bindings_by_subject without auth returns auth error."""
        response = self._call_tool(
            "list_role_bindings_by_subject",
            {"resource_id": "test-id", "resource_type": "workspace"},
            use_auth=False,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)


class PermissionMatchesTests(IdentityRequest):
    """Unit tests for the _permission_matches helper function."""

    def test_exact_match(self):
        """Positive: exact permission match returns True."""
        self.assertTrue(_permission_matches("cost-management:cost_model:write", "cost-management:cost_model:write"))

    def test_wildcard_all(self):
        """Positive: full wildcard matches any permission in the same app."""
        self.assertTrue(_permission_matches("cost-management:*:*", "cost-management:cost_model:write"))

    def test_wildcard_verb(self):
        """Positive: verb wildcard matches any verb."""
        self.assertTrue(_permission_matches("cost-management:cost_model:*", "cost-management:cost_model:write"))

    def test_mismatch_verb(self):
        """Negative: different verb does not match."""
        self.assertFalse(_permission_matches("cost-management:cost_model:read", "cost-management:cost_model:write"))

    def test_mismatch_app(self):
        """Negative: different application does not match."""
        self.assertFalse(_permission_matches("inventory:hosts:read", "cost-management:hosts:read"))

    def test_malformed_granted(self):
        """Negative: malformed granted permission returns False."""
        self.assertFalse(_permission_matches("invalid-format", "cost-management:cost_model:write"))

    def test_malformed_requested(self):
        """Negative: malformed requested permission returns False."""
        self.assertFalse(_permission_matches("cost-management:cost_model:write", "invalid"))


@override_settings(BYPASS_BOP_VERIFICATION=True)
class MCPCheckUserPermissionTests(MCPToolTestMixin, IdentityRequest):
    """Tests for the check_user_permission MCP tool."""

    def setUp(self):
        """Set up check_user_permission tests."""
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()
        self.test_username = self.user_data["username"]
        self.principal = Principal.objects.create(username=self.test_username, tenant=self.tenant)

        role = Role.objects.create(name="test_role", tenant=self.tenant)
        perm = Permission.objects.create(
            application="rbac",
            resource_type="roles",
            verb="read",
            permission="rbac:roles:read",
            tenant=self.tenant,
        )
        Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        group = Group.objects.create(name="test_group", tenant=self.tenant)
        group.principals.add(self.principal)
        policy = Policy.objects.create(name="test_policy", group=group, tenant=self.tenant)
        policy.roles.add(role)

    def tearDown(self):
        """Tear down check_user_permission tests."""
        Policy.objects.all().delete()
        Access.objects.all().delete()
        Role.objects.all().delete()
        Permission.objects.all().delete()
        Group.objects.all().delete()
        Principal.objects.all().delete()
        super().tearDown()

    def test_invalid_permission_format(self):
        """Negative: invalid permission format returns error."""
        response = self._call_tool("check_user_permission", {"username": self.test_username, "permission": "invalid"})

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertIn("error", tool_output)
        self.assertIn("application:resource_type:verb", tool_output["error"])

    def test_permission_allowed(self):
        """Positive: check_user_permission returns allowed=True when user has permission."""
        response = self._call_tool(
            "check_user_permission", {"username": self.test_username, "permission": "rbac:roles:read"}
        )

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertTrue(tool_output["allowed"])
        self.assertEqual(tool_output["username"], self.test_username)
        self.assertEqual(tool_output["matched_permission"], "rbac:roles:read")

    def test_permission_denied(self):
        """Negative: check_user_permission returns allowed=False when user lacks permission."""
        response = self._call_tool(
            "check_user_permission", {"username": self.test_username, "permission": "rbac:roles:write"}
        )

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertFalse(tool_output["allowed"])
        self.assertIn("hint", tool_output)

    def test_without_auth_returns_error(self):
        """Permission: check_user_permission without auth returns auth error."""
        response = self._call_tool(
            "check_user_permission",
            {"username": self.test_username, "permission": "rbac:roles:read"},
            use_auth=False,
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)


class MCPSearchRolesTests(MCPToolTestMixin, IdentityRequest):
    """Tests for the unified search_roles MCP tool (V1 path)."""

    def setUp(self):
        """Set up search_roles tests."""
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()

    def tearDown(self):
        """Tear down search_roles tests."""
        Role.objects.all().delete()
        super().tearDown()

    def test_search_roles_v1_success(self):
        """Positive: search_roles on V1 org returns role data with org_version=v1."""
        Role.objects.create(name="test_v1_role", tenant=self.tenant)
        response = self._call_tool("search_roles")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)
        self.assertIn("meta", tool_output)
        self.assertIn("data", tool_output)
        self.assertEqual(tool_output["org_version"], "v1")

    def test_search_roles_v1_filter_by_name(self):
        """Positive: search_roles on V1 org filters by name."""
        Role.objects.create(name="Patch Reviewer", tenant=self.tenant)
        Role.objects.create(name="Other Role", tenant=self.tenant)
        response = self._call_tool("search_roles", {"name": "Patch Reviewer"})

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertTrue(tool_output["meta"]["count"] >= 1)
        for role in tool_output["data"]:
            self.assertIn("Patch Reviewer", role["name"])
        self.assertEqual(tool_output["org_version"], "v1")

    def test_search_roles_without_auth_returns_error(self):
        """Permission: search_roles without auth returns auth error."""
        response = self._call_tool("search_roles", use_auth=False)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)


class MCPViewNonAdminTests(IdentityRequest):
    """Test the MCP endpoint for non-admin users via _private/_a2s/mcp/."""

    def setUp(self):
        """Set up the MCP view non-admin tests."""
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()

        non_admin_tenant_name = "acct1234"
        self.non_admin_tenant = Tenant.objects.create(
            tenant_name=non_admin_tenant_name, account_id="1234", org_id="4321"
        )

        self.user_data = {"username": "non_admin", "email": "non_admin@example.com"}
        self.customer = {"account_id": "1234", "org_id": "4321", "tenant_name": non_admin_tenant_name}
        self.request_context = self._create_request_context(self.customer, self.user_data, is_org_admin=False)

        request = self.request_context["request"]
        self.headers = request.META

        # Set up RBAC permission for non-admin to read principals
        self.non_admin_principal = Principal.objects.create(username="non_admin", tenant=self.non_admin_tenant)
        self.group = Group.objects.create(name="principal_readers", tenant=self.non_admin_tenant)
        self.group.principals.add(self.non_admin_principal)
        self.role = Role.objects.create(name="principal_reader_role", tenant=self.non_admin_tenant)
        self.permission = Permission.objects.create(
            application="rbac",
            resource_type="principals",
            verb="read",
            permission="rbac:principal:read",
            tenant=self.non_admin_tenant,
        )
        self.access = Access.objects.create(permission=self.permission, role=self.role, tenant=self.non_admin_tenant)
        self.policy = Policy.objects.create(
            name="principal_reader_policy", group=self.group, tenant=self.non_admin_tenant
        )
        self.policy.roles.add(self.role)

    def tearDown(self):
        """Tear down MCP view non-admin tests."""
        Policy.objects.all().delete()
        Access.objects.all().delete()
        Role.objects.all().delete()
        Permission.objects.all().delete()
        Group.objects.all().delete()
        Principal.objects.all().delete()
        super().tearDown()

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={"status_code": 200, "data": [], "userCount": 0},
    )
    def test_non_admin_can_call_list_principals(self, mock_request):
        """Positive: Non-admin users with principal:read permission can call list_principals tool."""
        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {
                "name": "list_principals",
                "arguments": {},
            },
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("result", data)
        result = data["result"]
        self.assertFalse(result["isError"])
        tool_output = json.loads(result["content"][0]["text"])
        self.assertIn("meta", tool_output)
        self.assertIn("data", tool_output)

    def test_non_admin_without_permission_gets_forbidden(self):
        """Permission: Non-admin without principal:read gets 403 from PrincipalView."""
        # Remove RBAC permission
        self.policy.roles.clear()

        body = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 2,
            "params": {
                "name": "list_principals",
                "arguments": {},
            },
        }
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertNotIn("error", data)
        # PrincipalView returns 403, which is captured in the tool response
        result = data["result"]
        self.assertFalse(result["isError"])
        tool_output = json.loads(result["content"][0]["text"])
        self.assertIn("errors", tool_output)
        self.assertIsInstance(tool_output["errors"], list)
        self.assertGreater(len(tool_output["errors"]), 0)
        self.assertEqual(tool_output["errors"][0]["status"], "403")


@override_settings(BYPASS_BOP_VERIFICATION=True, V2_APIS_ENABLED=True)
class MCPCheckUserPermissionV2Tests(MCPToolTestMixin, IdentityRequest):
    """Tests for check_user_permission auto-detecting V2 orgs and using role bindings."""

    def setUp(self):
        """Set up V2 check_user_permission tests with tenant mapping and role bindings."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()
        self.test_username = self.user_data["username"]
        self.principal = Principal.objects.create(username=self.test_username, tenant=self.tenant)

        self.enterContext(
            patch(
                "management.permissions.role_v2_access.get_kessel_principal_id",
                return_value="localhost/test-user-id",
            )
        )
        self.enterContext(
            patch(
                "management.permissions.role_v2_access.WorkspaceInventoryAccessChecker.check_resource_access",
                return_value=True,
            )
        )

        # Activate V2 for this tenant
        TenantMapping.objects.create(tenant=self.tenant, v2_write_activated_at=timezone.now())

        # Create V2 role with a permission
        self.v2_perm = Permission.objects.create(
            application="vulnerability",
            resource_type="vulnerability",
            verb="read",
            permission="vulnerability:vulnerability:read",
            tenant=self.tenant,
        )
        self.v2_role = RoleV2.objects.create(name="Vuln Reader", tenant=self.tenant)
        self.v2_role.permissions.add(self.v2_perm)

        # Create role binding assigning the role directly to the principal
        self.binding = RoleBinding.objects.create(
            tenant=self.tenant,
            role=self.v2_role,
            resource_type="workspace",
            resource_id="root-workspace-id",
        )
        RoleBindingPrincipal.objects.create(binding=self.binding, principal=self.principal, source="direct")

    def tearDown(self):
        """Tear down V2 check_user_permission tests."""
        RoleBindingPrincipal.objects.all().delete()
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.all().delete()
        RoleV2.objects.all().delete()
        Permission.objects.all().delete()
        TenantMapping.objects.all().delete()
        Principal.objects.all().delete()
        super().tearDown()

    def test_v2_permission_allowed(self):
        """Positive: V2 org auto-detects and returns allowed=True via role bindings."""
        response = self._call_tool(
            "check_user_permission",
            {"username": self.test_username, "permission": "vulnerability:vulnerability:read"},
        )

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertTrue(tool_output["allowed"])
        self.assertEqual(tool_output["username"], self.test_username)
        self.assertEqual(tool_output["matched_permission"], "vulnerability:vulnerability:read")
        self.assertEqual(tool_output["role_name"], "Vuln Reader")
        self.assertEqual(tool_output["org_version"], "v2")

    def test_v2_permission_denied(self):
        """Negative: V2 org returns allowed=False when user lacks the permission."""
        response = self._call_tool(
            "check_user_permission",
            {"username": self.test_username, "permission": "vulnerability:vulnerability:write"},
        )

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertFalse(tool_output["allowed"])
        self.assertEqual(tool_output["org_version"], "v2")
        self.assertIn("hint", tool_output)

    def test_v2_user_not_found(self):
        """Negative: V2 org returns hint when user doesn't exist."""
        response = self._call_tool(
            "check_user_permission",
            {"username": "nonexistent_user", "permission": "vulnerability:vulnerability:read"},
        )

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertFalse(tool_output["allowed"])
        self.assertEqual(tool_output["org_version"], "v2")
        self.assertIn("not found", tool_output["hint"])

    def test_v2_permission_via_group(self):
        """Positive: V2 org resolves permissions inherited through group membership."""
        # Create a group and add the principal to it
        group = Group.objects.create(name="vuln_readers_group", tenant=self.tenant)
        group.principals.add(self.principal)

        # Create a separate role binding assigned to the group
        write_perm = Permission.objects.create(
            application="vulnerability",
            resource_type="vulnerability",
            verb="write",
            permission="vulnerability:vulnerability:write",
            tenant=self.tenant,
        )
        write_role = RoleV2.objects.create(name="Vuln Writer", tenant=self.tenant)
        write_role.permissions.add(write_perm)
        group_binding = RoleBinding.objects.create(
            tenant=self.tenant,
            role=write_role,
            resource_type="workspace",
            resource_id="root-workspace-id",
        )
        RoleBindingGroup.objects.create(binding=group_binding, group=group)

        response = self._call_tool(
            "check_user_permission",
            {"username": self.test_username, "permission": "vulnerability:vulnerability:write"},
        )

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertTrue(tool_output["allowed"])
        self.assertEqual(tool_output["role_name"], "Vuln Writer")
        self.assertEqual(tool_output["org_version"], "v2")

    def test_v2_wildcard_match(self):
        """Positive: V2 wildcard permission matching works."""
        wildcard_perm = Permission.objects.create(
            application="vulnerability",
            resource_type="vulnerability",
            verb="*",
            permission="vulnerability:vulnerability:*",
            tenant=self.tenant,
        )
        wildcard_role = RoleV2.objects.create(name="Vuln Wildcard", tenant=self.tenant)
        wildcard_role.permissions.add(wildcard_perm)
        wildcard_binding = RoleBinding.objects.create(
            tenant=self.tenant,
            role=wildcard_role,
            resource_type="workspace",
            resource_id="root-workspace-id",
        )
        RoleBindingPrincipal.objects.create(binding=wildcard_binding, principal=self.principal, source="direct")

        response = self._call_tool(
            "check_user_permission",
            {"username": self.test_username, "permission": "vulnerability:vulnerability:write"},
        )

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertTrue(tool_output["allowed"])
        self.assertEqual(tool_output["matched_permission"], "vulnerability:vulnerability:*")
        self.assertEqual(tool_output["org_version"], "v2")


@override_settings(BYPASS_BOP_VERIFICATION=True, V2_APIS_ENABLED=True)
class MCPUnifiedSearchRolesV2Tests(MCPToolTestMixin, IdentityRequest):
    """Tests for the unified search_roles MCP tool routing to V2."""

    def setUp(self):
        """Set up V2 search_roles tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()
        self.enterContext(
            patch(
                "management.permissions.role_v2_access.get_kessel_principal_id",
                return_value="localhost/test-user-id",
            )
        )
        self.enterContext(
            patch(
                "management.permissions.role_v2_access.WorkspaceInventoryAccessChecker.check_resource_access",
                return_value=True,
            )
        )
        TenantMapping.objects.create(tenant=self.tenant, v2_write_activated_at=timezone.now())

    def tearDown(self):
        """Tear down V2 search_roles tests."""
        RoleV2.objects.all().delete()
        TenantMapping.objects.all().delete()
        super().tearDown()

    def test_search_roles_v2_success(self):
        """Positive: search_roles on V2 org returns role data with org_version=v2."""
        RoleV2.objects.create(name="V2 Custom Role", tenant=self.tenant, type=RoleV2.Types.CUSTOM)
        response = self._call_tool("search_roles")

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertIn("meta", tool_output)
        self.assertIn("data", tool_output)
        self.assertEqual(tool_output["org_version"], "v2")

    def test_search_roles_v2_filter_by_name(self):
        """Positive: search_roles on V2 org filters by name."""
        RoleV2.objects.create(name="Cost Reader", tenant=self.tenant, type=RoleV2.Types.CUSTOM)
        RoleV2.objects.create(name="Other V2 Role", tenant=self.tenant, type=RoleV2.Types.CUSTOM)
        response = self._call_tool("search_roles", {"name": "Cost Reader"})

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertEqual(tool_output["org_version"], "v2")
        role_names = [r["name"] for r in tool_output["data"]]
        self.assertIn("Cost Reader", role_names)


@override_settings(BYPASS_BOP_VERIFICATION=True, V2_APIS_ENABLED=True)
class MCPUnifiedGetRoleTests(MCPToolTestMixin, IdentityRequest):
    """Tests for the unified get_role MCP tool routing to V1 and V2."""

    def setUp(self):
        """Set up get_role tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()
        self.enterContext(
            patch(
                "management.permissions.role_v2_access.get_kessel_principal_id",
                return_value="localhost/test-user-id",
            )
        )
        self.enterContext(
            patch(
                "management.permissions.role_v2_access.WorkspaceInventoryAccessChecker.check_resource_access",
                return_value=True,
            )
        )

    def tearDown(self):
        """Tear down get_role tests."""
        RoleV2.objects.all().delete()
        Permission.objects.all().delete()
        TenantMapping.objects.all().delete()
        Role.objects.all().delete()
        super().tearDown()

    def test_get_role_v1_returns_role_with_permissions(self):
        """Positive: get_role on V1 org returns role details with permissions and org_version=v1."""
        perm = Permission.objects.create(
            application="cost-management",
            resource_type="cost_model",
            verb="read",
            permission="cost-management:cost_model:read",
            tenant=self.tenant,
        )
        role = Role.objects.create(name="Cost Reader V1", tenant=self.tenant)
        access = Access.objects.create(role=role, permission=perm, tenant=self.tenant)
        Policy.objects.create(name="auto_policy", group=None, tenant=self.tenant).roles.add(role)

        response = self._call_tool("get_role", {"role_uuid": str(role.uuid)})

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertEqual(tool_output["uuid"], str(role.uuid))
        self.assertEqual(tool_output["org_version"], "v1")
        self.assertIn("permissions", tool_output)

        access.delete()
        perm.delete()

    def test_get_role_v2_returns_role_with_permissions(self):
        """Positive: get_role on V2 org returns role details with permissions and org_version=v2."""
        TenantMapping.objects.create(tenant=self.tenant, v2_write_activated_at=timezone.now())

        perm = Permission.objects.create(
            application="vulnerability",
            resource_type="vulnerability",
            verb="read",
            permission="vulnerability:vulnerability:read",
            tenant=self.tenant,
        )
        role = RoleV2.objects.create(name="Vuln Reader V2", tenant=self.tenant)
        role.permissions.add(perm)

        response = self._call_tool("get_role", {"role_uuid": str(role.uuid)})

        self.assertEqual(response.status_code, 200)
        tool_output = self._get_tool_output(response)
        self.assertEqual(tool_output["id"], str(role.uuid))
        self.assertEqual(tool_output["org_version"], "v2")
        self.assertIn("permissions", tool_output)


class MCPDeploymentGatingTests(MCPToolTestMixin, IdentityRequest):
    """Tests for deployment-level V2 tool gating."""

    def setUp(self):
        """Set up gating tests."""
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()

    def test_calling_v2_tool_when_v2_disabled_returns_error(self):
        """Negative: calling a V2-only tool when V2 is disabled returns a clear error."""
        response = self._call_tool("list_role_bindings")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("error", data)
        self.assertIn("V2 APIs", data["error"]["message"])

    def test_api_version_classification(self):
        """Verify all tools have an api_version set."""
        for tool_name, config in _TOOL_CONFIG.items():
            self.assertIn(
                config.api_version,
                (ApiVersion.UNIFIED, ApiVersion.COMMON, ApiVersion.V1, ApiVersion.V2, ApiVersion.UNVERSIONED),
                f"Tool '{tool_name}' has unexpected api_version: {config.api_version}",
            )

    def test_unified_tools_are_always_listed(self):
        """Positive: unified tools appear in tools/list regardless of V2 setting."""
        body = {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}}
        response = self.client.post(self.url, data=json.dumps(body), content_type="application/json", **self.headers)

        tool_names = [t["name"] for t in response.json()["result"]["tools"]]
        self.assertIn("search_roles", tool_names)
        self.assertIn("get_role", tool_names)
        self.assertIn("check_user_permission", tool_names)


class MCPToolDescriptionOverrideTests(MCPToolTestMixin, IdentityRequest):
    """Test that Redis-backed description overrides are applied in tools/list."""

    def setUp(self):
        """Set up."""
        super().setUp()
        self.mcp_url = "/_private/_a2s/mcp/"
        self.client = APIClient()

    @patch(
        "management.mcp_views._get_all_description_overrides",
        return_value={"hello": "Overridden description for MCP"},
    )
    def test_override_appears_in_tools_list(self, mock_overrides):
        """After setting an override, tools/list returns the overridden description."""
        body = {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}}
        response = self.client.post(
            self.mcp_url, data=json.dumps(body), content_type="application/json", **self.headers
        )
        self.assertEqual(response.status_code, 200)
        tools = response.json()["result"]["tools"]
        hello_tool = next(t for t in tools if t["name"] == "hello")
        self.assertEqual(hello_tool["description"], "Overridden description for MCP")

    @patch(
        "management.mcp_views._get_all_description_overrides",
        return_value={"hello": "custom hello"},
    )
    def test_non_overridden_tools_keep_defaults(self, mock_overrides):
        """Overriding one tool does not affect other tools."""
        body = {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}}
        response = self.client.post(
            self.mcp_url, data=json.dumps(body), content_type="application/json", **self.headers
        )
        tools = response.json()["result"]["tools"]
        principals_tool = next(t for t in tools if t["name"] == "list_principals")
        self.assertIn("List principals", principals_tool["description"])


class MCPToolDescriptionEndpointTests(MCPToolTestMixin, IdentityRequest):
    """Test the internal endpoint for managing MCP tool description overrides."""

    def setUp(self):
        """Set up."""
        super().setUp()
        self.base_url = "/_private/api/utils/mcp_tool_descriptions/"
        self.client = APIClient()
        internal_context = self._create_request_context(self.customer_data, self.user_data, is_internal=True)
        self.internal_headers = internal_context["request"].META

        self._override_store = {}
        patcher_get_all = patch(
            "management.mcp_views._get_all_description_overrides",
            side_effect=lambda: dict(self._override_store),
        )
        patcher_get = patch(
            "management.mcp_views._get_description_override",
            side_effect=lambda name: self._override_store.get(name),
        )
        patcher_set = patch(
            "management.mcp_views._set_description_override",
            side_effect=lambda name, desc: self._override_store.__setitem__(name, desc),
        )
        patcher_delete = patch(
            "management.mcp_views._delete_description_override",
            side_effect=lambda name: self._override_store.pop(name, None),
        )
        patcher_get_all.start()
        patcher_get.start()
        patcher_set.start()
        patcher_delete.start()
        self.addCleanup(patcher_get_all.stop)
        self.addCleanup(patcher_get.stop)
        self.addCleanup(patcher_set.stop)
        self.addCleanup(patcher_delete.stop)

    def test_list_descriptions_returns_all_tools(self):
        """GET list returns all registered tools with default descriptions."""
        response = self.client.get(self.base_url, **self.internal_headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        tool_names = [t["tool_name"] for t in data["tools"]]
        self.assertIn("hello", tool_names)
        self.assertIn("list_principals", tool_names)
        hello_tool = next(t for t in data["tools"] if t["tool_name"] == "hello")
        self.assertIsNotNone(hello_tool["default_description"])
        self.assertIsNone(hello_tool["override_description"])
        self.assertEqual(hello_tool["active_description"], hello_tool["default_description"])

    def test_get_single_tool_description(self):
        """GET single tool returns its default description."""
        response = self.client.get(f"{self.base_url}hello/", **self.internal_headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["tool_name"], "hello")
        self.assertIsNone(data["override_description"])
        self.assertIn("RBAC service", data["default_description"])

    def test_set_description_override(self):
        """PUT sets description override for a tool."""
        new_desc = "Custom hello description for testing"
        response = self.client.put(
            f"{self.base_url}hello/",
            data=json.dumps({"description": new_desc}),
            content_type="application/json",
            **self.internal_headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["tool_name"], "hello")
        self.assertEqual(data["override_description"], new_desc)

    def test_delete_override_reverts_to_default(self):
        """DELETE removes override and reverts to default description."""
        self._override_store["hello"] = "temporary override"

        response = self.client.delete(f"{self.base_url}hello/", **self.internal_headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsNone(data["override_description"])

        response = self.client.get(f"{self.base_url}hello/", **self.internal_headers)
        data = response.json()
        self.assertIsNone(data["override_description"])

    def test_unknown_tool_returns_404(self):
        """PUT/DELETE/GET for unknown tool returns 404."""
        response = self.client.get(f"{self.base_url}nonexistent_tool/", **self.internal_headers)
        self.assertEqual(response.status_code, 404)

        response = self.client.put(
            f"{self.base_url}nonexistent_tool/",
            data=json.dumps({"description": "test"}),
            content_type="application/json",
            **self.internal_headers,
        )
        self.assertEqual(response.status_code, 404)

    def test_put_without_description_returns_400(self):
        """PUT without description field returns 400."""
        response = self.client.put(
            f"{self.base_url}hello/",
            data=json.dumps({}),
            content_type="application/json",
            **self.internal_headers,
        )
        self.assertEqual(response.status_code, 400)


@override_settings(BYPASS_BOP_VERIFICATION=True)
class MCPGetUserStateTests(MCPToolTestMixin, IdentityRequest):
    """Tests for the get_user_state MCP tool."""

    def setUp(self):
        """Set up get_user_state tests."""
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()
        self.test_username = self.user_data["username"]
        self.principal = Principal.objects.create(username=self.test_username, tenant=self.tenant)

        # Create a group and add the principal
        self.group = Group.objects.create(name="Wilson Project", description="Test project group", tenant=self.tenant)
        self.group.principals.add(self.principal)

        # Create a role with permissions
        self.role = Role.objects.create(
            name="Project Contributor", display_name="Project Contributor", tenant=self.tenant
        )
        self.permission = Permission.objects.create(
            application="project",
            resource_type="tasks",
            verb="write",
            permission="project:tasks:write",
            tenant=self.tenant,
        )
        self.access = Access.objects.create(permission=self.permission, role=self.role, tenant=self.tenant)

        # Assign role to group via policy
        self.policy = Policy.objects.create(name="project_policy", group=self.group, tenant=self.tenant)
        self.policy.roles.add(self.role)

        # Create audit log entries for actions BY the user (with resource_uuid for exact matching)
        AuditLog.objects.create(
            principal_username=self.test_username,
            resource_type=AuditLog.GROUP,
            resource_uuid=self.group.uuid,
            action=AuditLog.ADD,
            description="Added jsmith to Wilson Project",
            tenant=self.tenant,
        )
        AuditLog.objects.create(
            principal_username=self.test_username,
            resource_type=AuditLog.GROUP,
            resource_uuid=self.group.uuid,
            action=AuditLog.REMOVE,
            description="Removed old_user from Wilson Project",
            tenant=self.tenant,
        )

    def tearDown(self):
        """Tear down get_user_state tests."""
        AuditLog.objects.all().delete()
        Policy.objects.all().delete()
        Access.objects.all().delete()
        Role.objects.all().delete()
        Permission.objects.all().delete()
        Group.objects.all().delete()
        Principal.objects.all().delete()
        super().tearDown()

    def test_get_user_state_success(self):
        """Positive: get_user_state returns comprehensive user state."""
        response = self._call_tool("get_user_state", {"username": self.test_username})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data["result"]["isError"])
        tool_output = self._get_tool_output(response)

        # Verify basic structure
        self.assertEqual(tool_output["username"], self.test_username)
        self.assertEqual(tool_output["org_version"], "v1")
        self.assertIn("groups", tool_output)
        self.assertIn("access", tool_output)
        self.assertIn("user_actions", tool_output)
        self.assertIn("summary", tool_output)

    def test_get_user_state_includes_groups(self):
        """Positive: get_user_state includes user's groups with roles."""
        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        self.assertEqual(tool_output["summary"]["group_count"], 1)
        self.assertEqual(len(tool_output["groups"]), 1)

        group = tool_output["groups"][0]
        self.assertEqual(group["name"], "Wilson Project")
        self.assertEqual(group["description"], "Test project group")
        self.assertIn("roles", group)
        self.assertEqual(len(group["roles"]), 1)
        self.assertEqual(group["roles"][0]["name"], "Project Contributor")

    def test_get_user_state_includes_access(self):
        """Positive: get_user_state includes user's access permissions."""
        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        self.assertGreater(len(tool_output["access"]), 0)

        # Find the permission we created
        permissions = [a["permission"] for a in tool_output["access"]]
        self.assertIn("project:tasks:write", permissions)

    def test_get_user_state_includes_user_actions(self):
        """Positive: get_user_state includes actions performed BY the user."""
        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        user_actions = tool_output["user_actions"]

        self.assertEqual(user_actions["total_count"], 2)
        self.assertIn("by_group", user_actions)
        self.assertIn("Wilson Project", user_actions["by_group"])
        self.assertEqual(len(user_actions["by_group"]["Wilson Project"]), 2)
        self.assertIn("by_type", user_actions)
        self.assertIn("group:add", user_actions["by_type"])
        self.assertIn("group:remove", user_actions["by_type"])

    def test_get_user_state_summary(self):
        """Positive: get_user_state returns correct summary counts."""
        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        summary = tool_output["summary"]

        self.assertEqual(summary["group_count"], 1)
        self.assertGreaterEqual(summary["permission_count"], 1)
        self.assertEqual(summary["actions_by_user"], 2)

    def test_get_user_state_user_not_found(self):
        """Negative: get_user_state returns error for non-existent user."""
        response = self._call_tool("get_user_state", {"username": "nonexistent_user"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tool_output = self._get_tool_output(response)

        self.assertIn("error", tool_output)
        self.assertIn("not found", tool_output["error"])
        self.assertIn("hint", tool_output)

    def test_get_user_state_without_auth_returns_error(self):
        """Permission: get_user_state without auth returns auth error."""
        response = self._call_tool("get_user_state", {"username": self.test_username}, use_auth=False)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32000)

    def test_get_user_state_without_group_roles(self):
        """Positive: get_user_state with include_group_roles=false omits roles."""
        response = self._call_tool(
            "get_user_state",
            {"username": self.test_username, "include_group_roles": False},
        )

        tool_output = self._get_tool_output(response)
        group = tool_output["groups"][0]
        self.assertNotIn("roles", group)
        self.assertNotIn("role_count", group)

    def test_get_user_state_without_permissions(self):
        """Positive: get_user_state with include_permissions=false omits access."""
        response = self._call_tool(
            "get_user_state",
            {"username": self.test_username, "include_permissions": False},
        )

        tool_output = self._get_tool_output(response)
        self.assertEqual(len(tool_output["access"]), 0)
        self.assertEqual(tool_output["summary"]["permission_count"], 0)

    def test_get_user_state_audit_log_limit(self):
        """Positive: get_user_state respects audit_log_limit parameter."""
        # Add more audit log entries with resource_uuid for exact matching
        for i in range(5):
            AuditLog.objects.create(
                principal_username=self.test_username,
                resource_type=AuditLog.GROUP,
                resource_uuid=self.group.uuid,
                action=AuditLog.ADD,
                description=f"Added user{i} to Wilson Project",
                tenant=self.tenant,
            )

        response = self._call_tool(
            "get_user_state",
            {"username": self.test_username, "audit_log_limit": 3},
        )

        tool_output = self._get_tool_output(response)
        # recent should be limited to 3
        self.assertLessEqual(len(tool_output["user_actions"]["recent"]), 3)

    def test_get_user_state_multiple_groups(self):
        """Positive: get_user_state handles user in multiple groups."""
        # Create another group
        group2 = Group.objects.create(name="Platform Default", tenant=self.tenant)
        group2.principals.add(self.principal)

        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        self.assertEqual(tool_output["summary"]["group_count"], 2)
        group_names = [g["name"] for g in tool_output["groups"]]
        self.assertIn("Wilson Project", group_names)
        self.assertIn("Platform Default", group_names)

    def test_get_user_state_includes_hints(self):
        """Positive: get_user_state includes helpful hints for further investigation."""
        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        self.assertIn("hints", tool_output)
        self.assertIn("check_specific_permission", tool_output["hints"])
        self.assertIn("view_audit_details", tool_output["hints"])
        self.assertIn("trace_role_permissions", tool_output["hints"])


@override_settings(BYPASS_BOP_VERIFICATION=True, V2_APIS_ENABLED=True)
class MCPGetUserStateV2Tests(MCPToolTestMixin, IdentityRequest):
    """Tests for get_user_state on V2 organizations."""

    def setUp(self):
        """Set up V2 get_user_state tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()
        self.test_username = self.user_data["username"]
        self.principal = Principal.objects.create(username=self.test_username, tenant=self.tenant)

        self.enterContext(
            patch(
                "management.permissions.role_v2_access.get_kessel_principal_id",
                return_value="localhost/test-user-id",
            )
        )
        self.enterContext(
            patch(
                "management.permissions.role_v2_access.WorkspaceInventoryAccessChecker.check_resource_access",
                return_value=True,
            )
        )

        # Activate V2 for this tenant
        TenantMapping.objects.create(tenant=self.tenant, v2_write_activated_at=timezone.now())

        # Create a group and add the principal
        self.group = Group.objects.create(name="V2 Test Group", tenant=self.tenant)
        self.group.principals.add(self.principal)

        # Create V2 role with permission
        self.v2_perm = Permission.objects.create(
            application="inventory",
            resource_type="hosts",
            verb="read",
            permission="inventory:hosts:read",
            tenant=self.tenant,
        )
        self.v2_role = RoleV2.objects.create(name="Host Reader", tenant=self.tenant)
        self.v2_role.permissions.add(self.v2_perm)

        # Create role binding
        self.binding = RoleBinding.objects.create(
            tenant=self.tenant,
            role=self.v2_role,
            resource_type="workspace",
            resource_id="root-workspace-id",
        )
        RoleBindingPrincipal.objects.create(binding=self.binding, principal=self.principal, source="direct")

    def tearDown(self):
        """Tear down V2 get_user_state tests."""
        RoleBindingPrincipal.objects.all().delete()
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.all().delete()
        RoleV2.objects.all().delete()
        Permission.objects.all().delete()
        TenantMapping.objects.all().delete()
        Group.objects.all().delete()
        Principal.objects.all().delete()
        super().tearDown()

    def test_get_user_state_v2_returns_org_version(self):
        """Positive: get_user_state on V2 org returns org_version=v2."""
        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        self.assertEqual(tool_output["org_version"], "v2")

    def test_get_user_state_v2_includes_role_binding_permissions(self):
        """Positive: get_user_state on V2 org includes permissions from role bindings."""
        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        self.assertGreater(len(tool_output["access"]), 0)

        # Find the V2 permission
        permissions = [a["permission"] for a in tool_output["access"]]
        self.assertIn("inventory:hosts:read", permissions)

        # Verify role info is included
        access_entry = next(a for a in tool_output["access"] if a["permission"] == "inventory:hosts:read")
        self.assertEqual(access_entry["role_name"], "Host Reader")

    def test_get_user_state_v2_includes_resource_scope(self):
        """Positive: get_user_state on V2 org includes resource scope in access."""
        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        access_entry = next(a for a in tool_output["access"] if a["permission"] == "inventory:hosts:read")

        self.assertIn("resource_scope", access_entry)
        self.assertEqual(access_entry["resource_scope"]["type"], "workspace")
        self.assertEqual(access_entry["resource_scope"]["id"], "root-workspace-id")

    def test_get_user_state_v2_includes_group_based_role_bindings(self):
        """Positive: get_user_state on V2 org includes permissions from group-based role bindings."""
        group_perm = Permission.objects.create(
            application="cost-management",
            resource_type="cost_model",
            verb="write",
            permission="cost-management:cost_model:write",
            tenant=self.tenant,
        )
        group_role = RoleV2.objects.create(name="Cost Manager", tenant=self.tenant)
        group_role.permissions.add(group_perm)

        group_binding = RoleBinding.objects.create(
            tenant=self.tenant,
            role=group_role,
            resource_type="workspace",
            resource_id="group-workspace-id",
        )
        RoleBindingGroup.objects.create(binding=group_binding, group=self.group)

        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        permissions = [a["permission"] for a in tool_output["access"]]
        self.assertIn("cost-management:cost_model:write", permissions)

        access_entry = next(a for a in tool_output["access"] if a["permission"] == "cost-management:cost_model:write")
        self.assertEqual(access_entry["role_name"], "Cost Manager")
        self.assertEqual(access_entry["resource_scope"]["type"], "workspace")
        self.assertEqual(access_entry["resource_scope"]["id"], "group-workspace-id")

    def test_get_user_state_v2_multi_scope_bindings_preserved(self):
        """Positive: Same permission on different scopes is returned for each scope."""
        binding_b = RoleBinding.objects.create(
            tenant=self.tenant,
            role=self.v2_role,
            resource_type="workspace",
            resource_id="workspace-b-id",
        )
        RoleBindingPrincipal.objects.create(binding=binding_b, principal=self.principal, source="direct")

        response = self._call_tool("get_user_state", {"username": self.test_username})

        tool_output = self._get_tool_output(response)
        hosts_read_entries = [a for a in tool_output["access"] if a["permission"] == "inventory:hosts:read"]
        self.assertEqual(len(hosts_read_entries), 2)

        scope_ids = {e["resource_scope"]["id"] for e in hosts_read_entries}
        self.assertEqual(scope_ids, {"root-workspace-id", "workspace-b-id"})


class MCPTimeoutTests(MCPToolTestMixin, IdentityRequest):
    """Test MCP tool execution timeout behavior."""

    def setUp(self):
        """Set up timeout tests."""
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()

    # --- _execute_with_timeout unit tests ---

    def test_execute_with_timeout_returns_result(self):
        """Positive: Fast function returns its result within timeout."""
        result = _execute_with_timeout(lambda: "ok", timeout=5)
        self.assertEqual(result, "ok")

    def test_execute_with_timeout_passes_args(self):
        """Positive: Arguments are forwarded to the function."""
        result = _execute_with_timeout(lambda x, y: x + y, 5, 3, 4)
        self.assertEqual(result, 7)

    def test_execute_with_timeout_passes_kwargs(self):
        """Positive: Keyword arguments are forwarded to the function."""
        result = _execute_with_timeout(lambda name="world": f"hello {name}", 5, name="test")
        self.assertEqual(result, "hello test")

    def test_execute_with_timeout_raises_on_slow_function(self):
        """Negative: Slow function raises ToolTimeoutError."""
        with self.assertRaises(ToolTimeoutError):
            _execute_with_timeout(lambda: time.sleep(0.5), timeout=0.1)

    def test_execute_with_timeout_propagates_exceptions(self):
        """Negative: Exceptions from the function propagate unchanged."""

        def raise_value_error():
            raise ValueError("test error")

        with self.assertRaises(ValueError):
            _execute_with_timeout(raise_value_error, timeout=5)

    # --- Integration tests via MCP endpoint ---

    @override_settings(MCP_TOOL_TIMEOUT_SECONDS=0.1)
    @patch("management.mcp_views._TOOL_CONFIG")
    def test_tool_call_returns_timeout_error(self, mock_config):
        """Negative: Slow tool returns JSON-RPC timeout error."""
        mock_config.get.return_value = ToolConfig(
            fn=lambda: time.sleep(0.5),
            requires_auth=False,
            passes_request=False,
        )
        response = self._call_tool("slow_tool")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32603)
        self.assertEqual(data["error"]["message"], "Tool execution timed out after 0.1s")

    @override_settings(MCP_TOOL_TIMEOUT_SECONDS=0.1)
    @patch("management.mcp_views._TOOL_CONFIG")
    def test_tool_call_timeout_with_passes_request(self, mock_config):
        """Negative: Slow tool with passes_request=True also times out correctly."""
        mock_config.get.return_value = ToolConfig(
            fn=lambda request: time.sleep(0.5),
            requires_auth=False,
            passes_request=True,
        )
        response = self._call_tool("slow_auth_tool")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"]["code"], -32603)
        self.assertIn("timed out", data["error"]["message"])

    @override_settings(MCP_TOOL_TIMEOUT_SECONDS=0.1)
    @patch("management.mcp_views._TOOL_CONFIG")
    def test_timeout_records_prometheus_metric(self, mock_config):
        """Positive: Timeout records metric with status='timeout'."""
        mock_config.get.return_value = ToolConfig(
            fn=lambda: time.sleep(0.5),
            requires_auth=False,
            passes_request=False,
        )

        with patch("management.mcp_views._record_metric") as mock_metric:
            self._call_tool("slow_tool")
            mock_metric.assert_called_once()
            args = mock_metric.call_args[0]
            self.assertEqual(args[0], "slow_tool")
            self.assertEqual(args[1], "timeout")

    def test_hello_skips_timeout_tracking(self):
        """Edge case: hello tool still works and skips metric tracking."""
        response = self._call_tool("hello")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("result", data)
        self.assertFalse(data["result"]["isError"])

    @override_settings(MCP_TOOL_TIMEOUT_SECONDS=30)
    def test_default_timeout_allows_normal_tools(self):
        """Positive: Normal tools complete within default timeout."""
        response = self._call_tool("hello")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("result", data)
        self.assertFalse(data["result"]["isError"])
