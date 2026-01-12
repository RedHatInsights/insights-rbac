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
"""Tests for kessel_principal_utils module."""

from unittest.mock import MagicMock, Mock, patch

from django.test import TestCase
from management.authorization.invalid_token import InvalidTokenError
from management.authorization.missing_authorization import MissingAuthorizationError
from management.permissions.kessel_principal_utils import (
    _get_user_id_from_bearer_token,
    get_kessel_principal_id_for_v2_access,
)
from management.principal.model import Principal


class GetKesselPrincipalIdForV2AccessTests(TestCase):
    """Tests for get_kessel_principal_id_for_v2_access function."""

    @patch("management.permissions.kessel_principal_utils.get_kessel_principal_id")
    def test_returns_principal_id_from_standard_lookup(self, mock_get_principal_id):
        """Test that principal_id is returned from standard lookup when available."""
        mock_get_principal_id.return_value = "localhost/user-123"

        mock_request = Mock()

        result = get_kessel_principal_id_for_v2_access(mock_request)

        self.assertEqual(result, "localhost/user-123")
        mock_get_principal_id.assert_called_once_with(mock_request)

    @patch("management.permissions.kessel_principal_utils._get_user_id_from_bearer_token")
    @patch("management.permissions.kessel_principal_utils.get_kessel_principal_id")
    def test_falls_back_to_bearer_token_for_service_account(self, mock_get_principal_id, mock_get_bearer_token):
        """Test that bearer token is used when standard lookup fails for service accounts."""
        mock_get_principal_id.return_value = None
        mock_get_bearer_token.return_value = "sa-user-456"

        mock_request = Mock()
        mock_request.user.is_service_account = True

        result = get_kessel_principal_id_for_v2_access(mock_request)

        expected_principal_id = Principal.user_id_to_principal_resource_id("sa-user-456")
        self.assertEqual(result, expected_principal_id)
        mock_get_bearer_token.assert_called_once_with(mock_request)

    @patch("management.permissions.kessel_principal_utils._get_user_id_from_bearer_token")
    @patch("management.permissions.kessel_principal_utils.get_kessel_principal_id")
    def test_does_not_try_bearer_token_for_non_service_account(self, mock_get_principal_id, mock_get_bearer_token):
        """Test that bearer token is not tried for non-service account users."""
        mock_get_principal_id.return_value = None

        mock_request = Mock()
        mock_request.user.is_service_account = False

        result = get_kessel_principal_id_for_v2_access(mock_request)

        self.assertIsNone(result)
        mock_get_bearer_token.assert_not_called()

    @patch("management.permissions.kessel_principal_utils._get_user_id_from_bearer_token")
    @patch("management.permissions.kessel_principal_utils.get_kessel_principal_id")
    def test_returns_none_when_bearer_token_fails_for_service_account(
        self, mock_get_principal_id, mock_get_bearer_token
    ):
        """Test that None is returned when bearer token extraction fails for service accounts."""
        mock_get_principal_id.return_value = None
        mock_get_bearer_token.return_value = None

        mock_request = Mock()
        mock_request.user.is_service_account = True

        result = get_kessel_principal_id_for_v2_access(mock_request)

        self.assertIsNone(result)
        mock_get_bearer_token.assert_called_once_with(mock_request)

    @patch("management.permissions.kessel_principal_utils.get_kessel_principal_id")
    def test_handles_missing_is_service_account_attribute(self, mock_get_principal_id):
        """Test that missing is_service_account attribute defaults to False."""
        mock_get_principal_id.return_value = None

        mock_request = Mock(spec=[])
        mock_request.user = Mock(spec=[])  # No is_service_account attribute

        result = get_kessel_principal_id_for_v2_access(mock_request)

        self.assertIsNone(result)


class GetUserIdFromBearerTokenTests(TestCase):
    """Tests for _get_user_id_from_bearer_token function."""

    @patch("management.permissions.kessel_principal_utils._token_validator")
    def test_returns_user_id_from_bearer_token(self, mock_validator):
        """Test that user_id is extracted from bearer token successfully."""
        mock_user = Mock()
        mock_user.user_id = "bearer-user-789"

        mock_validator.get_user_from_bearer_token.return_value = mock_user

        mock_request = Mock()

        result = _get_user_id_from_bearer_token(mock_request)

        self.assertEqual(result, "bearer-user-789")
        mock_validator.get_user_from_bearer_token.assert_called_once_with(mock_request)

    @patch("management.permissions.kessel_principal_utils._token_validator")
    def test_returns_none_when_user_is_none(self, mock_validator):
        """Test that None is returned when token validator returns no user."""
        mock_validator.get_user_from_bearer_token.return_value = None

        mock_request = Mock()

        result = _get_user_id_from_bearer_token(mock_request)

        self.assertIsNone(result)

    @patch("management.permissions.kessel_principal_utils._token_validator")
    def test_returns_none_when_user_id_is_none(self, mock_validator):
        """Test that None is returned when user has no user_id."""
        mock_user = Mock()
        mock_user.user_id = None

        mock_validator.get_user_from_bearer_token.return_value = mock_user

        mock_request = Mock()

        result = _get_user_id_from_bearer_token(mock_request)

        self.assertIsNone(result)

    @patch("management.permissions.kessel_principal_utils._token_validator")
    def test_returns_none_on_invalid_token_error(self, mock_validator):
        """Test that None is returned when InvalidTokenError is raised."""
        mock_validator.get_user_from_bearer_token.side_effect = InvalidTokenError("Invalid token")

        mock_request = Mock()

        result = _get_user_id_from_bearer_token(mock_request)

        self.assertIsNone(result)

    @patch("management.permissions.kessel_principal_utils._token_validator")
    def test_returns_none_on_missing_authorization_error(self, mock_validator):
        """Test that None is returned when MissingAuthorizationError is raised."""
        mock_validator.get_user_from_bearer_token.side_effect = MissingAuthorizationError("Missing auth")

        mock_request = Mock()

        result = _get_user_id_from_bearer_token(mock_request)

        self.assertIsNone(result)

    @patch("management.permissions.kessel_principal_utils.logger")
    @patch("management.permissions.kessel_principal_utils._token_validator")
    def test_logs_warning_on_unexpected_exception(self, mock_validator, mock_logger):
        """Test that unexpected exceptions are logged with exc_info=True."""
        mock_validator.get_user_from_bearer_token.side_effect = RuntimeError("Unexpected error")

        mock_request = Mock()

        result = _get_user_id_from_bearer_token(mock_request)

        self.assertIsNone(result)
        # Verify warning was logged with exc_info=True
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        self.assertIn("Unexpected error extracting user_id from bearer token", call_args[0][0])
        self.assertEqual(call_args[1]["exc_info"], True)

    @patch("management.permissions.kessel_principal_utils.logger")
    @patch("management.permissions.kessel_principal_utils._token_validator")
    def test_logs_debug_on_successful_extraction(self, mock_validator, mock_logger):
        """Test that debug message is logged on successful user_id extraction."""
        mock_user = Mock()
        mock_user.user_id = "success-user-123"

        mock_validator.get_user_from_bearer_token.return_value = mock_user

        mock_request = Mock()

        result = _get_user_id_from_bearer_token(mock_request)

        self.assertEqual(result, "success-user-123")
        mock_logger.debug.assert_called_with(
            "Retrieved user_id from bearer token via ITSSOTokenValidator: %s", "success-user-123"
        )


class ServiceAccountIntegrationTests(TestCase):
    """Integration tests for service account flow through get_kessel_principal_id_for_v2_access."""

    @patch("management.permissions.kessel_principal_utils._token_validator")
    @patch("management.permissions.kessel_principal_utils.get_kessel_principal_id")
    def test_full_service_account_flow_success(self, mock_get_principal_id, mock_validator):
        """Test full service account flow when standard lookup fails but bearer token succeeds."""
        mock_get_principal_id.return_value = None

        mock_user = Mock()
        mock_user.user_id = "sa-bearer-user-999"
        mock_validator.get_user_from_bearer_token.return_value = mock_user

        mock_request = Mock()
        mock_request.user.is_service_account = True

        result = get_kessel_principal_id_for_v2_access(mock_request)

        expected_principal_id = Principal.user_id_to_principal_resource_id("sa-bearer-user-999")
        self.assertEqual(result, expected_principal_id)

    @patch("management.permissions.kessel_principal_utils._token_validator")
    @patch("management.permissions.kessel_principal_utils.get_kessel_principal_id")
    def test_full_service_account_flow_both_fail(self, mock_get_principal_id, mock_validator):
        """Test that None is returned when both standard lookup and bearer token fail."""
        mock_get_principal_id.return_value = None

        mock_validator.get_user_from_bearer_token.side_effect = InvalidTokenError("Bad token")

        mock_request = Mock()
        mock_request.user.is_service_account = True

        result = get_kessel_principal_id_for_v2_access(mock_request)

        self.assertIsNone(result)

    @patch("management.permissions.kessel_principal_utils.get_kessel_principal_id")
    def test_standard_lookup_takes_precedence_for_service_account(self, mock_get_principal_id):
        """Test that standard lookup takes precedence even for service accounts."""
        mock_get_principal_id.return_value = "localhost/standard-user-111"

        mock_request = Mock()
        mock_request.user.is_service_account = True

        result = get_kessel_principal_id_for_v2_access(mock_request)

        # Standard lookup should be used, bearer token should not be tried
        self.assertEqual(result, "localhost/standard-user-111")
