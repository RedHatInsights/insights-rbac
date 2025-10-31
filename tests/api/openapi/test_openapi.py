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
"""Test the openapi API."""

from unittest.mock import mock_open, patch

from django.urls import reverse

from tests.identity_request import IdentityRequest


class OpenAPIViewTest(IdentityRequest):
    """Tests the openapi view."""

    def test_openapi_endpoint_success(self):
        """Test the openapi endpoint returns 200 and valid JSON."""
        url = reverse("v1_api:openapi")
        response = self.client.get(url, **self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")

        # Verify response is valid JSON
        data = response.json()
        self.assertIsInstance(data, dict)

        # Verify it contains OpenAPI spec structure
        self.assertIn("openapi", data)
        self.assertIn("info", data)
        self.assertIn("paths", data)

    def test_openapi_endpoint_allows_anonymous(self):
        """Test the openapi endpoint allows anonymous access."""
        url = reverse("v1_api:openapi")
        # Don't provide any authentication headers
        response = self.client.get(url)

        # Should still return 200 (AllowAny permission)
        self.assertEqual(response.status_code, 200)

    def test_openapi_spec_includes_itself(self):
        """Test that the openapi spec includes documentation for the /openapi.json endpoint."""
        url = reverse("v1_api:openapi")
        response = self.client.get(url, **self.headers)

        data = response.json()
        paths = data.get("paths", {})

        # Verify that /openapi.json is documented in the spec
        self.assertIn("/openapi.json", paths)

        # Verify it has a GET method
        openapi_endpoint = paths["/openapi.json"]
        self.assertIn("get", openapi_endpoint)

        # Verify basic metadata
        get_method = openapi_endpoint["get"]
        self.assertIn("summary", get_method)
        self.assertIn("operationId", get_method)
        self.assertEqual(get_method["operationId"], "getOpenAPISpec")

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_openapi_file_not_found(self, mock_file):
        """Test that missing openapi.json file returns proper error response."""
        url = reverse("v1_api:openapi")
        response = self.client.get(url, **self.headers)

        # Should return 500 error
        self.assertEqual(response.status_code, 500)

        # Verify error response structure
        data = response.json()
        self.assertIn("errors", data)
        self.assertEqual(len(data["errors"]), 1)

        error = data["errors"][0]
        self.assertIn("OpenAPI specification file not found", error["detail"])
        self.assertEqual(error["status"], "500")

    @patch("builtins.open", new_callable=mock_open, read_data="invalid json {{{")
    def test_openapi_invalid_json(self, mock_file):
        """Test that malformed openapi.json file returns proper error response."""
        url = reverse("v1_api:openapi")
        response = self.client.get(url, **self.headers)

        # Should return 500 error
        self.assertEqual(response.status_code, 500)

        # Verify error response structure
        data = response.json()
        self.assertIn("errors", data)
        self.assertEqual(len(data["errors"]), 1)

        error = data["errors"][0]
        self.assertIn("invalid JSON", error["detail"])
        self.assertEqual(error["status"], "500")
