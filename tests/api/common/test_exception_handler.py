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
from management.authorization.invalid_token import InvalidTokenError
from management.authorization.missing_authorization import MissingAuthorizationError
from management.authorization.unable_meet_prerequisites import UnableMeetPrerequisitesError
from rest_framework import status
from rest_framework.views import Response
from unittest.mock import Mock

from api.common.exception_handler import custom_exception_handler
from api.common.exception_handler import _generate_errors_from_dict, _generate_error_data_payload_response


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

    def test_invalid_token_exception_handled(self):
        """Test that an "invalid token" exception gets properly handled."""
        # Mock the view and the context.
        mocked_view = Mock()
        mocked_view.basename = "some-view-handler"

        context = {"view": mocked_view}

        # Call the function under test.
        response: Response = custom_exception_handler(exc=InvalidTokenError(), context=context)

        # Assert that the correct response was returned for the exception.
        self.assertEqual(
            status.HTTP_401_UNAUTHORIZED,
            response.status_code,
            "unexpected status code in the response for the 'InvalidTokenError' exception handling",
        )

        self.assertEqual(
            "Invalid token provided.",
            str(response.data.get("errors")[0].get("detail")),
            "unexpected error message in the response for the 'InvalidTokenError' exception handling",
        )

        self.assertEqual(
            mocked_view.basename,
            str(response.data.get("errors")[0].get("source")),
            "unexpected source view in the response for the 'MissingAuthorizationError' exception handling",
        )

    def test_missing_authorization_exception_handled(self):
        """Test that a "missing authorization" exception gets properly handled."""
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

    def test_unable_meet_prerequisites_exception_handled(self):
        """Test that an "unable to meet prerequisites" exception gets properly handled."""
        # Mock the view and the context.
        mocked_view = Mock()
        mocked_view.basename = "some-view-handler"

        context = {"view": mocked_view}

        # Call the function under test.
        response: Response = custom_exception_handler(exc=UnableMeetPrerequisitesError(), context=context)

        # Assert that the correct response was returned for the exception.
        self.assertEqual(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            response.status_code,
            "unexpected status code in the response for the 'UnableMeetPrerequisitesError' exception handling",
        )

        self.assertEqual(
            "Unable to validate the provided token.",
            str(response.data.get("errors")[0].get("detail")),
            "unexpected error message in the response for the 'UnableMeetPrerequisitesError' exception handling",
        )

        self.assertEqual(
            mocked_view.basename,
            str(response.data.get("errors")[0].get("source")),
            "unexpected source view in the response for the 'UnableMeetPrerequisitesError' exception handling",
        )

    def test_generate_error_data_payload_with_view_response(self):
        """Tests that the function under test generates the data payload correctly when a view is passed in the context."""
        # Prepare a payload with a view in the context.
        detail = "some error message"
        mocked_view = Mock()
        mocked_view.basename = "some-view-handler"
        context = {"view": mocked_view}
        http_status_code = status.HTTP_200_OK

        # Call the function under test.
        result = _generate_error_data_payload_response(
            detail=detail, context=context, http_status_code=http_status_code
        )

        # Assert that the correct structure is returned.
        errors = result.get("errors")
        if not errors:
            self.fail(f"the errors array was not present in the payload: {result}")

        if len(errors) != 1:
            self.fail(f"only one error was expected in the payload: {result}")

        only_error = errors[0]

        self.assertEqual(detail, only_error.get("detail"), f"unexpected detail message in the payload: {result}")

        self.assertEqual(
            mocked_view.basename, only_error.get("source"), f"unexpected detail message in the payload: {result}"
        )

        self.assertEqual(
            str(http_status_code), only_error.get("status"), f"unexpected status code in the payload: {result}"
        )

    def test_generate_error_data_payload_without_view_response(self):
        """Tests that the function under test generates the data payload correctly when no view is passed in the context."""
        # Prepare a payload without a view in the context.
        detail = "some error message"
        context = {}
        http_status_code = status.HTTP_200_OK

        # Call the function under test.
        result = _generate_error_data_payload_response(
            detail=detail, context=context, http_status_code=http_status_code
        )

        # Assert that the correct structure is returned.
        errors = result.get("errors")
        if not errors:
            self.fail(f"the errors array was not present in the payload: {result}")

        if len(errors) != 1:
            self.fail(f"only one error was expected in the payload: {result}")

        only_error = errors[0]

        self.assertEqual(detail, only_error.get("detail"), f"unexpected detail message in the payload: {result}")

        self.assertEqual(
            str(http_status_code), only_error.get("status"), f"unexpected status code in the payload: {result}"
        )
