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
"""Test the API exception handler module."""

from django.test import TestCase
from management.authorization.missing_authorization import MissingAuthorizationError
from rest_framework import status
from rest_framework.views import Response
from unittest.mock import Mock

from api.common.exception_handler import _generate_errors_from_dict, custom_exception_handler


class ExceptionHandlerTest(TestCase):
    """Tests against the exception handler functions."""

    def test_generate_errors_from_dict(self):
        """Test generating errors from dictionary errors."""
        kwargs = {"status_code": 400}
        response = {"non_field_errors": ["Cannot access AWS bucket with ARN", "ARN format is incorrect"]}
        formatted_errors = _generate_errors_from_dict(response, **kwargs)
        expected = [
            {"detail": "Cannot access AWS bucket with ARN", "source": "non_field_errors", "status": 400},
            {"detail": "ARN format is incorrect", "source": "non_field_errors", "status": 400},
        ]
        self.assertEqual(formatted_errors, expected)

        kwargs = {"status_code": 400}
        response = {"provider_type": "Must be either OCP or AWS"}
        formatted_errors = _generate_errors_from_dict(response, **kwargs)
        expected = [{"detail": "Must be either OCP or AWS", "source": "provider_type", "status": 400}]
        self.assertEqual(formatted_errors, expected)

        kwargs = {"status_code": 400}
        response = {"tiered_rate": {"unit": ['"UD" is not a valid choice.']}}
        formatted_errors = _generate_errors_from_dict(response, **kwargs)
        expected = [{"detail": '"UD" is not a valid choice.', "source": "tiered_rate.unit", "status": 400}]
        self.assertEqual(formatted_errors, expected)

        kwargs = {"status_code": 400}
        response = {"tiered_rate": {"value": ["Ensure that there are no more than 10 decimal places."]}}
        formatted_errors = _generate_errors_from_dict(response, **kwargs)
        expected = [
            {
                "detail": "Ensure that there are no more than 10 decimal places.",
                "source": "tiered_rate.value",
                "status": 400,
            }
        ]
        self.assertEqual(formatted_errors, expected)

        kwargs = {"status_code": 400}
        response = {"tiered_rate": {"value": {"key": "Ensure that there are no more than 10 decimal places."}}}
        formatted_errors = _generate_errors_from_dict(response, **kwargs)
        expected = [
            {
                "detail": "Ensure that there are no more than 10 decimal places.",
                "source": "tiered_rate.value.key",
                "status": 400,
            }
        ]
        self.assertEqual(formatted_errors, expected)

        kwargs = {"status_code": 400}
        response = {"tiered_rate": {"value": [["key"], ["Ensure that there are no more than 10 decimal places."]]}}
        formatted_errors = _generate_errors_from_dict(response, **kwargs)
        expected = [
            {"detail": "key", "source": "tiered_rate.value", "status": 400},
            {
                "detail": "Ensure that there are no more than 10 decimal places.",
                "source": "tiered_rate.value",
                "status": 400,
            },
        ]
        self.assertEqual(formatted_errors, expected)

    def test_missing_authorization_exception_handled(self):
        """Test that a missing authorization exception gets properly handled"""
        # Mock the view and the context.
        mocked_view = Mock()
        mocked_view.basename = "some-view-handler"

        context = {"view": mocked_view}

        # Call the function under test.
        response: Response = custom_exception_handler(exc=MissingAuthorizationError(), context=context)

        # Assert that the correct response was returned for the exception.
        self.assertEqual(
            status.HTTP_401_UNAUTHORIZED,
            response.status_code,
            "unexpected status code in the response for the 'MissingAuthorizationError' exception handling",
        )

        self.assertEqual(
            "A Bearer token in an authorization header is required when performing service account operations.",
            str(response.data.get("errors")[0].get("detail")),
            "unexpected error message in the response for the 'MissingAuthorizationError' exception handling",
        )

        self.assertEqual(
            mocked_view.basename,
            str(response.data.get("errors")[0].get("source")),
            "unexpected source view in the response for the 'MissingAuthorizationError' exception handling",
        )
