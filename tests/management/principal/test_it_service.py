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

from management.models import Group, Principal
from management.principal.it_service import ITService
from rest_framework import serializers
from tests.identity_request import IdentityRequest
from unittest import mock

from api.models import User


class ITServiceTests(IdentityRequest):
    """Test the IT service class"""

    def setUp(self):
        self.it_service = ITService()

    def test_it_service_singleton(self):
        """Test that the IT Service class only gets instantiated once."""
        class_instances = [
            ITService(),
            ITService(),
            ITService(),
            ITService(),
            ITService(),
        ]

        for instance in class_instances:
            self.assertEqual(
                self.it_service,
                instance,
                "no new instances of the IT service class should have been created since it is supposed to be a singleton",
            )

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

    def test_generate_service_accounts_report_in_group_zero_matches(self):
        """Test that the function under test is able to flag service accounts as not present in a group"""
        principal_1 = Principal.objects.create(username="user-1", tenant=self.tenant)
        principal_2 = Principal.objects.create(username="user-2", tenant=self.tenant)
        principal_3 = Principal.objects.create(username="user-3", tenant=self.tenant)

        # Create three service accounts for the group. Since these will not be specified in the "client_ids" parameter
        # of the function under test, they should not show up in the results.
        sa_1 = Principal.objects.create(
            username=f"service-account-{uuid.uuid4()}",
            service_account_id=uuid.uuid4(),
            type="service-account",
            tenant=self.tenant,
        )
        sa_2 = Principal.objects.create(
            username=f"service-account-{uuid.uuid4()}",
            service_account_id=uuid.uuid4(),
            type="service-account",
            tenant=self.tenant,
        )
        sa_3 = Principal.objects.create(
            username=f"service-account-{uuid.uuid4()}",
            service_account_id=uuid.uuid4(),
            type="service-account",
            tenant=self.tenant,
        )

        # Create a group for the principals.
        group = Group(name="it-service-group", platform_default=False, system=False, tenant=self.tenant)
        group.save()
        # Add the principal accounts to make sure that we are only working with service accounts. If we weren't, these
        # principals below should give us unexpected results in our assertions.
        group.principals.add(principal_1)
        group.principals.add(principal_2)
        group.principals.add(principal_3)

        # Add the service account principals.
        group.principals.add(sa_1)
        group.principals.add(sa_2)
        group.principals.add(sa_3)
        group.save()

        # Simulate that a few client IDs were specified in the request.
        request_client_ids = set[uuid.UUID]()
        request_client_ids.add(uuid.uuid4())
        request_client_ids.add(uuid.uuid4())
        request_client_ids.add(uuid.uuid4())

        # Call the function under test.
        result: dict[str, bool] = self.it_service.generate_service_accounts_report_in_group(
            group=group, client_ids=request_client_ids
        )
        # Assert that only the specified client IDs are present in the result.
        self.assertEqual(3, len(result))

        # Transform the UUIDs to strings to match the generated result and be able to create assertions.
        request_client_ids_str: set[str] = set()
        for rci in request_client_ids:
            request_client_ids_str.add(str(rci))

        # Assert that all the service accounts were flagged as not present in the group.
        for client_id, is_present_in_group in result.items():
            # Make sure the specified client IDs are in the set.
            self.assertEqual(
                True,
                client_id in request_client_ids_str,
                "expected to find the specified client ID from the request in the returning result",
            )
            # Make sure they are all set to "false" since there shouldn't be any of those client IDs in the group.
            self.assertEqual(
                False,
                is_present_in_group,
                "the client ID should have not been found in the group, since the group had no service accounts",
            )

    def test_generate_service_accounts_report_in_group_mixed_results(self):
        """Test that the function under test is able to correctly flag the sevice accounts when there are mixed results"""
        principal_1 = Principal.objects.create(username="user-1", tenant=self.tenant)
        principal_2 = Principal.objects.create(username="user-2", tenant=self.tenant)
        principal_3 = Principal.objects.create(username="user-3", tenant=self.tenant)

        client_uuid_1 = uuid.uuid4()
        client_uuid_2 = uuid.uuid4()
        sa_1 = Principal.objects.create(
            username=f"service-account-{client_uuid_1}",
            service_account_id=client_uuid_1,
            type="service-account",
            tenant=self.tenant,
        )
        sa_2 = Principal.objects.create(
            username=f"service-account-{client_uuid_2}",
            service_account_id=client_uuid_2,
            type="service-account",
            tenant=self.tenant,
        )
        # Create more service accounts that should not show in the results, since they're not going to be specified in
        # the "client_ids" parameter.
        sa_3 = Principal.objects.create(
            username=f"service-account-{uuid.uuid4()}",
            service_account_id=uuid.uuid4(),
            type="service-account",
            tenant=self.tenant,
        )
        sa_4 = Principal.objects.create(
            username=f"service-account-{uuid.uuid4()}",
            service_account_id=uuid.uuid4(),
            type="service-account",
            tenant=self.tenant,
        )
        sa_5 = Principal.objects.create(
            username=f"service-account-{uuid.uuid4()}",
            service_account_id=uuid.uuid4(),
            type="service-account",
            tenant=self.tenant,
        )

        # Create a set with the service accounts that will go in the group. It will make it easier to make assertions
        # below.
        group_service_accounts_set = {str(sa_1.service_account_id), str(sa_2.service_account_id)}

        # Create a group and associate principals to it.
        group = Group(name="it-service-group", platform_default=False, system=False, tenant=self.tenant)
        group.save()
        # Add the principal accounts to make sure that we are only working with service accounts. If we weren't, these
        # principals below should give us unexpected results in our assertions.
        group.principals.add(principal_1)
        group.principals.add(principal_2)
        group.principals.add(principal_3)
        # Add the service accounts to the group.
        group.principals.add(sa_1)
        group.principals.add(sa_2)
        # Add the service accounts that should not show up in the results.
        group.principals.add(sa_3)
        group.principals.add(sa_4)
        group.principals.add(sa_5)

        group.save()

        # Simulate that a few client IDs were specified in the request.
        request_client_ids = set[uuid.UUID]()
        not_in_group = uuid.uuid4()
        not_in_group_2 = uuid.uuid4()
        not_in_group_3 = uuid.uuid4()

        request_client_ids.add(not_in_group)
        request_client_ids.add(not_in_group_2)
        request_client_ids.add(not_in_group_3)

        # Also, create a set with the service accounts that will NOT go in the group to make it easier to assert that
        # the results flag them as such.
        service_accounts_not_in_group_set = {
            str(not_in_group),
            str(not_in_group_2),
            str(not_in_group_3),
        }

        # Specify the service accounts' UUIDs here too, because the function under test should flag them as present in
        # the group.
        request_client_ids.add(client_uuid_1)
        request_client_ids.add(client_uuid_2)

        # Call the function under test.
        result: dict[str, bool] = self.it_service.generate_service_accounts_report_in_group(
            group=group, client_ids=request_client_ids
        )

        # Assert that all the specified client IDs are present in the result.
        self.assertEqual(5, len(result))

        # Transform the UUIDs to strings to match the generated result and be able to create assertions.
        request_client_ids_str: set[str] = set()
        for rci in request_client_ids:
            request_client_ids_str.add(str(rci))

        # Assert that the mixed matches are identified correctly.
        for client_id, is_it_present_in_group in result.items():
            # If the value is "true" it should be present in the service accounts' result set from above. Else, it
            # means that the specified client IDs were not part of the group, and that they should have been flagged
            # as such.
            if is_it_present_in_group:
                self.assertEqual(
                    True,
                    client_id in group_service_accounts_set,
                    "a client ID which was not part of the group was incorrectly flagged as if it was",
                )
            else:
                self.assertEqual(
                    True,
                    client_id in service_accounts_not_in_group_set,
                    "a client ID which was part of the group was incorrectly flagged as if it wasn't",
                )

    def test_generate_service_accounts_report_in_group_full_match(self):
        """Test that the function under test is able to flag service accounts as all being present in the group."""
        principal_1 = Principal.objects.create(username="user-1", tenant=self.tenant)
        principal_2 = Principal.objects.create(username="user-2", tenant=self.tenant)
        principal_3 = Principal.objects.create(username="user-3", tenant=self.tenant)

        client_uuid_1 = uuid.uuid4()
        client_uuid_2 = uuid.uuid4()
        client_uuid_3 = uuid.uuid4()
        client_uuid_4 = uuid.uuid4()
        client_uuid_5 = uuid.uuid4()
        sa_1 = Principal.objects.create(
            username=f"service-account-{client_uuid_1}",
            service_account_id=client_uuid_1,
            type="service-account",
            tenant=self.tenant,
        )
        sa_2 = Principal.objects.create(
            username=f"service-account-{client_uuid_2}",
            service_account_id=client_uuid_2,
            type="service-account",
            tenant=self.tenant,
        )
        sa_3 = Principal.objects.create(
            username=f"service-account-{client_uuid_3}",
            service_account_id=client_uuid_3,
            type="service-account",
            tenant=self.tenant,
        )
        sa_4 = Principal.objects.create(
            username=f"service-account-{client_uuid_4}",
            service_account_id=client_uuid_4,
            type="service-account",
            tenant=self.tenant,
        )
        sa_5 = Principal.objects.create(
            username=f"service-account-{client_uuid_5}",
            service_account_id=client_uuid_5,
            type="service-account",
            tenant=self.tenant,
        )

        # Create a set with the service accounts that will go in the group. It will make it easier to make assertions
        # below.
        group_service_accounts_set = {
            str(sa_1.service_account_id),
            str(sa_2.service_account_id),
            str(sa_3.service_account_id),
            str(sa_4.service_account_id),
            str(sa_5.service_account_id),
        }

        # Create a group and associate principals to it.
        group = Group(name="it-service-group", platform_default=False, system=False, tenant=self.tenant)
        group.save()
        # Add the principal accounts to make sure that we are only working with service accounts. If we weren't, these
        # principals below should give us unexpected results in our assertions.
        group.principals.add(principal_1)
        group.principals.add(principal_2)
        group.principals.add(principal_3)
        # Add the service accounts to the group.
        group.principals.add(sa_1)
        group.principals.add(sa_2)
        group.principals.add(sa_3)
        group.principals.add(sa_4)
        group.principals.add(sa_5)
        group.save()

        # Simulate that a few client IDs were specified in the request.
        request_client_ids = set[uuid.UUID]()
        request_client_ids.add(client_uuid_1)
        request_client_ids.add(client_uuid_2)
        request_client_ids.add(client_uuid_3)
        request_client_ids.add(client_uuid_4)
        request_client_ids.add(client_uuid_5)

        # Call the function under test.
        result: dict[str, bool] = self.it_service.generate_service_accounts_report_in_group(
            group=group, client_ids=request_client_ids
        )

        # Assert that all the specified client IDs are present in the result.
        self.assertEqual(5, len(result))

        # Transform the UUIDs to strings to match the generated result and be able to create assertions.
        request_client_ids_str: set[str] = set()
        for rci in request_client_ids:
            request_client_ids_str.add(str(rci))

        # Assert that all the results are flagged as being part of the group.
        for client_id, is_present_in_group in result.items():
            self.assertEqual(
                True,
                client_id in request_client_ids_str,
                "expected to find the specified client ID from the request in the returning result",
            )
            self.assertEqual(
                True,
                client_id in group_service_accounts_set,
                "expected to find the client ID from the result set in the service accounts' group set",
            )
            # Make sure they are all set to "true" since all the specified client IDs should be in the group.
            self.assertEqual(
                True,
                is_present_in_group,
                "the client ID should have been found in the group, since the group had all the service accounts added to it",
            )
