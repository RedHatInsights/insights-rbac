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
from unittest.mock import patch

from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant
from management.mcp_views import ToolConfig
from management.models import Access, Group, Permission, Policy, Principal, Role
from tests.identity_request import IdentityRequest


class MCPViewTests(IdentityRequest):
    """Test the MCP endpoint at /_private/_a2s/mcp/ (agent-to-service with public auth)."""

    def setUp(self):
        """Set up the MCP view tests."""
        super().setUp()
        self.url = "/_private/_a2s/mcp/"
        self.client = APIClient()
        self.principal = Principal.objects.create(username="test_user", tenant=self.tenant)

    def tearDown(self):
        """Tear down MCP view tests."""
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
