#
# Copyright 2019 Red Hat, Inc.
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
"""Test the principal proxy."""
from unittest.mock import Mock, patch

from django.test import TestCase
from rest_framework import status
import requests
from management.principal.proxy import PrincipalProxy


class MockResponse:  # pylint: disable=too-few-public-methods
    """Mock response object for testing."""

    def __init__(self, json_data, status_code, exception=None):
        """Create object."""
        self.json_data = json_data
        self.status_code = status_code
        self.exception = exception

    def json(self):
        """Return json data."""
        if self.exception:
            raise self.exception
        return self.json_data


def mocked_requests_get_404_json(*args, **kwargs):  # pylint: disable=unused-argument
    """Mock invalid response that returns json."""
    json_response = {"details": "Invalid path."}
    return MockResponse(json_response, status.HTTP_404_NOT_FOUND)


def mocked_requests_get_500_json(*args, **kwargs):  # pylint: disable=unused-argument
    """Mock invalid response that returns json."""
    json_response = {"details": "Internal server error."}
    return MockResponse(json_response, status.HTTP_500_INTERNAL_SERVER_ERROR)


def mocked_requests_get_500_except(*args, **kwargs):  # pylint: disable=unused-argument
    """Mock invalid response that raises an exception."""
    raise requests.exceptions.ConnectionError()


def mocked_requests_get_200_json(*args, **kwargs):  # pylint: disable=unused-argument
    """Mock valid response that returns json."""
    user = {
        "username": "test_user1",
        "email": "test_user1@email.foo",
        "first_name": "test",
        "last_name": "user1",
        "is_active": "true",
    }
    json_response = [user]
    return MockResponse(json_response, status.HTTP_200_OK)


def mocked_requests_get_200_json_count(*args, **kwargs):  # pylint: disable=unused-argument
    """Mock valid response that returns json with usercount."""
    user1 = {
        "username": "test_user1",
        "email": "test_user1@email.foo",
        "first_name": "test",
        "last_name": "user1",
        "is_active": "true",
    }
    user2 = {
        "username": "test_user2",
        "email": "test_user2@email.foo",
        "first_name": "test",
        "last_name": "user2",
        "is_active": "true",
    }
    json_response = {"userCount": 2, "users": [user1, user2]}
    return MockResponse(json_response, status.HTTP_200_OK)


def mocked_requests_get_200_except(*args, **kwargs):  # pylint: disable=unused-argument
    """Mock valid response that returns exception on json."""
    json_response = {}
    return MockResponse(json_response, status.HTTP_200_OK, ValueError)


class PrincipalProxyTest(TestCase):
    """Test PrincipalProxy object."""

    @patch(
        "management.principal.proxy.PrincipalProxy._request_principals",
        return_value={"status_code": status.HTTP_200_OK, "data": []},
    )
    def test_request_principals(self, mock_request):
        """Test the call to request principals."""
        proxy = PrincipalProxy()
        result = proxy.request_principals(account="1234", limit=20, offset=10)
        expected = {"status_code": status.HTTP_200_OK, "data": []}
        self.assertEqual(expected, result)

    @patch(
        "management.principal.proxy.PrincipalProxy._request_principals",
        return_value={"status_code": status.HTTP_200_OK, "data": []},
    )
    def test_request_filtered_principals(self, mock_request):
        """Test the call to request filtered principals."""
        proxy = PrincipalProxy()
        result = proxy.request_filtered_principals(principals=["test_user"], account="1234")
        expected = {"status_code": status.HTTP_200_OK, "data": []}
        self.assertEqual(expected, result)

    def test_request_filtered_principals_empty(self):
        """Test the call to request filtered principals."""
        proxy = PrincipalProxy()
        result = proxy.request_filtered_principals(principals=[], account="1234")
        expected = {"status_code": status.HTTP_200_OK, "data": []}
        self.assertEqual(expected, result)

    def test__request_principals_404(self):
        """Test request with expected 404."""
        proxy = PrincipalProxy()
        result = proxy._request_principals(url="http://localhost:8080/v1/users", method=mocked_requests_get_404_json)
        expected = {"status_code": 404, "errors": [{"detail": "Not Found.", "status": "404", "source": "principals"}]}
        self.assertEqual(expected, result)

    def test__request_principals_500(self):
        """Test request with expected 500."""
        proxy = PrincipalProxy()
        result = proxy._request_principals(url="http://localhost:8080/v1/users", method=mocked_requests_get_500_json)
        expected = {
            "status_code": 500,
            "errors": [{"detail": "Unexpected error.", "status": "500", "source": "principals"}],
        }
        self.assertEqual(expected, result)

    def test__request_principals_500_except(self):
        """Test request with expected 500 on connection exception."""
        proxy = PrincipalProxy()
        result = proxy._request_principals(url="http://localhost:8080/v1/users", method=mocked_requests_get_500_except)
        expected = {
            "status_code": 500,
            "errors": [{"detail": "Unexpected error.", "status": "500", "source": "principals"}],
        }
        self.assertEqual(expected, result)

    def test__request_principals_200_success(self):
        """Test request with expected 200 and good data."""
        proxy = PrincipalProxy()
        result = proxy._request_principals(url="http://localhost:8080/v1/users", method=mocked_requests_get_200_json)
        user = {
            "username": "test_user1",
            "email": "test_user1@email.foo",
            "first_name": "test",
            "last_name": "user1",
            "is_active": "true",
        }
        expected = {"data": [user], "status_code": 200}
        self.assertEqual(expected, result)

    def test__request_principals_200_count(self):
        """Test request with 200 and good data including userCount."""
        proxy = PrincipalProxy()
        result = proxy._request_principals(
            url="http://localhost:8080/v1/users", method=mocked_requests_get_200_json_count
        )
        user1 = {
            "username": "test_user1",
            "email": "test_user1@email.foo",
            "first_name": "test",
            "last_name": "user1",
            "is_active": "true",
        }
        user2 = {
            "username": "test_user2",
            "email": "test_user2@email.foo",
            "first_name": "test",
            "last_name": "user2",
            "is_active": "true",
        }
        expected = {"data": {"userCount": 2, "users": [user1, user2]}, "status_code": 200}
        self.assertEqual(expected, result)

    def test__request_principals_200_fail(self):
        """Test request with expected 200 and bad data."""
        proxy = PrincipalProxy()
        result = proxy._request_principals(url="http://localhost:8080/v1/users", method=mocked_requests_get_200_except)
        expected = {
            "status_code": 500,
            "errors": [{"detail": "Unexpected error.", "status": "500", "source": "principals"}],
        }
        self.assertEqual(expected, result)
