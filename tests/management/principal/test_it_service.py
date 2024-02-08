#
# Copyright 2024 Red Hat, Inc.
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
"""Test the principal model."""
import uuid

from django.conf import settings

from management.principal.it_service import ITService
from rest_framework import serializers
from tests.identity_request import IdentityRequest
from unittest import mock

from api.models import User


class ITServiceTests(IdentityRequest):
    """Test the IT service class"""

    def setUp(self):
        self.it_service = ITService()

    @mock.patch("management.principal.it_service.ITService._is_service_account_valid")
    def test_is_service_account_valid_by_username_client_id(self, _is_service_account_valid: mock.Mock):
        """Test that the function under test calls the underlying function with the unmodified client ID."""
        client_uuid = str(uuid.uuid4())
        user = User()

        self.it_service.is_service_account_valid_by_username(user=user, service_account_username=client_uuid)

        _is_service_account_valid.assert_called_with(user=user, client_id=client_uuid)

    @mock.patch("management.principal.it_service.ITService._is_service_account_valid")
    def test_is_service_account_valid_by_username_full(self, _is_service_account_valid: mock.Mock):
        """Test that the function under test calls the underlying function by stripping the service account prefix."""
        client_uuid = uuid.uuid4()
        username = f"service-account-{client_uuid}"
        user = User()

        self.it_service.is_service_account_valid_by_username(user=user, service_account_username=username)

        _is_service_account_valid.assert_called_with(user=user, client_id=str(client_uuid))

    @mock.patch("management.principal.it_service.ITService.request_service_accounts")
    def test_is_service_account_valid_bypass_it_calls(self, _):
        """Test that the function under test assumes service accounts to always be valid when bypassing IT calls."""
        original_bypass_it_calls_value = settings.IT_BYPASS_IT_CALLS
        try:
            settings.IT_BYPASS_IT_CALLS = True

            self.assertEqual(
                True,
                self.it_service._is_service_account_valid(user=User(), client_id="mocked-cid"),
                "when IT calls are bypassed, a service account should always be validated as if it existed",
            )
        finally:
            settings.IT_BYPASS_IT_CALLS = original_bypass_it_calls_value

    @mock.patch("management.principal.it_service.ITService.request_service_accounts")
    def test_is_service_account_valid_zero_results_from_it(self, request_service_accounts: mock.Mock):
        """Test that the function under test treats an empty result from IT as an invalid service account."""
        request_service_accounts.return_value = []
        user = User()
        user.bearer_token = "mocked-bt"

        self.assertEqual(
            False,
            self.it_service._is_service_account_valid(user=user, client_id="mocked-cid"),
            "when IT returns an empty array for the given client ID, the service account should be considered invalid",
        )

    @mock.patch("management.principal.it_service.ITService.request_service_accounts")
    def test_is_service_account_valid_one_matching_result_from_it(self, request_service_accounts: mock.Mock):
        """Test that the function under test positively validates the given service account if IT responds with that service account."""
        client_id = "client-id-123"
        request_service_accounts.return_value = [{"clientId": client_id}]
        user = User()
        user.bearer_token = "mocked-bt"

        self.assertEqual(
            True,
            self.it_service._is_service_account_valid(user=user, client_id=client_id),
            "when IT returns the requested service account via the client ID, the function under test should return True",
        )

    @mock.patch("management.principal.it_service.ITService.request_service_accounts")
    def test_is_service_account_valid_not_matching_result_from_it(self, request_service_accounts: mock.Mock):
        """Test that the function under test does not validate the given service account if IT does not return a response with a proper service account."""
        client_id = "client-id-123"
        request_service_accounts.return_value = [{"clientId": "different-client-id"}]
        user = User()
        user.bearer_token = "mocked-bt"

        self.assertEqual(
            False,
            self.it_service._is_service_account_valid(user=user, client_id=client_id),
            "when IT returns a service account which doesn't match the provided client ID, the function under test should return False",
        )

    @mock.patch("management.principal.it_service.ITService.request_service_accounts")
    def test_is_service_account_valid_multiple_results_from_it(self, request_service_accounts: mock.Mock):
        """Test that the function under retunrs False when IT returns multiple service accounts for a single client ID."""
        request_service_accounts.return_value = [{}, {}]
        user = User()
        user.bearer_token = "mocked-bt"

        self.assertEqual(
            False,
            self.it_service._is_service_account_valid(user=user, client_id="mocked_cid"),
            "when IT returns more service accounts than the ones requested, the function under test should return False",
        )

    def test_username_is_service_account(self) -> None:
        """Test that the username is correctly identified as a service account."""
        username = f"service-account-{uuid.uuid4()}"
        self.assertEqual(
            ITService.is_username_service_account(username),
            True,
            f"the given username '{username}' should have been identified as a service account username",
        )

    def test_username_is_not_service_account(self) -> None:
        """Test that the provided usernames are correctly identified as not service accounts."""
        usernames: list[str] = [
            "foo",
            "bar",
            f"serivce-account-{uuid.uuid4()}",
            f"service-acount-{uuid.uuid4()}",
            str(uuid.uuid4()),
        ]

        for username in usernames:
            self.assertEqual(
                ITService.is_username_service_account(username),
                False,
                f"the given username '{username}' should have not been identified as a service account username",
            )

    def test_extract_client_id_service_account_username(self) -> None:
        """Test that the client ID is correctly extracted from the service account's username"""
        client_id = uuid.uuid4()

        # Call the function under test with just the client ID. It should return it as is.
        self.assertEqual(
            client_id,
            ITService.extract_client_id_service_account_username(username=str(client_id)),
            "the client ID should be returned when it is passed to the function under test",
        )

        # Call the function under test with the whole prefix, and check that the client ID is correctly identified.
        self.assertEqual(
            client_id,
            ITService.extract_client_id_service_account_username(username=f"service-account-{client_id}"),
            "the client ID was not correctly extracted from a full username",
        )

        # Call the function under test with an invalid username which contains a bad formed UUID.
        try:
            ITService.extract_client_id_service_account_username(username="abcde")
            self.fail(
                "when providing an invalid UUID as the client ID to be extracted, the function under test should raise an error"
            )
        except serializers.ValidationError as ve:
            self.assertEqual(
                "unable to extract the client ID from the service account's username because the provided UUID is invalid",
                str(ve.detail.get("detail")),
                "unexpected error message when providing an invalid UUID as the client ID",
            )
