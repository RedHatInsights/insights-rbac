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
"""Test the metrics endpoint."""

from tests.identity_request import IdentityRequest


class MetricsEndpointTest(IdentityRequest):
    """Tests for the Prometheus metrics endpoint."""

    def test_metrics_endpoint_accessible_with_auth(self):
        """Test that the /metrics endpoint is accessible."""
        response = self.client.get("/metrics", **self.headers)
        self.assertEqual(response.status_code, 200)

    def test_metrics_endpoint_no_auth_required(self):
        """Test that /metrics endpoint does not require authentication."""
        # Should work without any headers
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)

    def test_metrics_endpoint_content_type(self):
        """Test that /metrics returns Prometheus text format."""
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)

        # Prometheus metrics should be text/plain
        content_type = response.get("Content-Type", "")
        self.assertTrue(content_type.startswith("text/plain"), f"Expected text/plain, got {content_type}")

    def test_metrics_endpoint_returns_prometheus_format(self):
        """Test that /metrics returns data in Prometheus format."""
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)

        # Convert response to string
        content = response.content.decode("utf-8")

        # Should contain Prometheus metric indicators
        # HELP and TYPE are standard Prometheus comment lines
        self.assertTrue(
            "# HELP" in content or "# TYPE" in content, "Response should contain Prometheus metric format markers"
        )

    def test_metrics_endpoint_contains_python_metrics(self):
        """Test that /metrics contains basic Python/Django metrics."""
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)

        content = response.content.decode("utf-8")

        # django-prometheus should expose these basic metrics
        expected_metrics = [
            "python_",  # Python runtime metrics
            "django_",  # Django metrics
        ]

        found_metrics = [metric for metric in expected_metrics if metric in content]

        self.assertTrue(
            len(found_metrics) > 0, f"Expected to find at least one of {expected_metrics} in metrics output"
        )

    def test_metrics_endpoint_after_request(self):
        """Test that metrics endpoint tracks requests after making one."""
        # Make a request to status endpoint to generate some metrics
        self.client.get("/api/rbac/v1/status/")

        # Now check metrics
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)

        content = response.content.decode("utf-8")

        # After making requests, we should see HTTP-related metrics
        self.assertTrue(
            "django_http_requests" in content or "http_requests" in content,
            "Metrics should contain HTTP request counters after making requests",
        )
