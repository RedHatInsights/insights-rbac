#
# Copyright 2023 Red Hat, Inc.
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
"""Class to manage interactions with the IT service accounts service."""
import logging
import time
import uuid

import requests
from django.conf import settings
from django.db.models import Q
from management.models import Group, Principal
from prometheus_client import Counter, Histogram
from rest_framework import status

from api.models import User
from .unexpected_status_code_from_it import UnexpectedStatusCodeFromITError

# Constants or global variables.
LOGGER = logging.getLogger(__name__)
TYPE_SERVICE_ACCOUNT = "service-account"

# IT path to fetch the service accounts.
IT_PATH_GET_SERVICE_ACCOUNTS = "/service_accounts/v1"

# Set up the metrics for the IT calls.
it_request_all_service_accounts_time_tracking = Histogram(
    "it_request_all_service_accounts_processing_seconds",
    "Time spent processing requests from IT when requesting all the service accounts of a tenant",
)

it_request_status_count = Counter(
    "it_request_status_total",
    "Number of requests from IT to BOP and resulting status",
    ["method", "status"],
)


class ITService:
    """A class to handle interactions with the IT service."""

    def __init__(self):
        """Establish IT connection information."""
        self.host = settings.IT_SERVICE_HOST
        self.base_path = settings.IT_SERVICE_BASE_PATH
        self.port = settings.IT_SERVICE_PORT
        self.protocol = settings.IT_SERVICE_PROTOCOL_SCHEME
        self.it_request_timeout = settings.IT_SERVICE_TIMEOUT_SECONDS

    @it_request_all_service_accounts_time_tracking.time()
    def request_service_accounts(self, bearer_token: str) -> list[dict]:
        """Request the service accounts for a tenant and returns the entire list that IT has."""
        received_service_accounts: list[dict] = []
        # Prepare the URL to fetch the service accounts.
        url = f"{self.protocol}://{self.host}:{self.port}{self.base_path}{IT_PATH_GET_SERVICE_ACCOUNTS}"

        # Attempt fetching all the service accounts for the tenant.
        try:
            offset = 0
            limit = 100

            # If the offset is zero, that means that we need to call the service at least once to get the first
            # service accounts. If it equals the limit, that means that there are more pages to fetch.
            while offset == 0 or offset == limit:
                response = requests.get(
                    url=url,
                    headers={"Authorization": f"Bearer {bearer_token}"},
                    params={"first": offset, "max": limit},
                    timeout=self.it_request_timeout,
                )

                if not status.is_success(response.status_code):
                    LOGGER.error(
                        "Unexpected status code '%s' received from IT when fetching service accounts. "
                        "Response body: %s",
                        response.status_code,
                        response.content,
                    )

                    raise UnexpectedStatusCodeFromITError()

                # Extract the body contents.
                body_contents = response.json()

                # Recalculate the offset to decide whether to get more service accounts or not. If the offset is zero,
                # it means that there were no service accounts in IT for the tenant.
                offset = offset + len(body_contents)
                if offset == 0:
                    break

                # Merge the previously received service accounts with the new ones.
                received_service_accounts = received_service_accounts + body_contents
        except requests.exceptions.ConnectionError as exception:
            LOGGER.error(
                "Unable to connect to IT to fetch the service accounts. Attempted URL %s with error: %s",
                url,
                exception,
            )

            # Increment the error count.
            it_request_status_count.labels(method=requests.get.__name__.upper(), status=response.status_code).inc()

            # Raise the exception again to return a proper response to the client
            raise exception
        except requests.exceptions.Timeout as exception:
            LOGGER.error(
                "The connection to IT timed out when trying to fetch service accounts. Attempted URL %s with error: %s",
                url,
                exception,
            )

            # Increment the error count.
            it_request_status_count.labels(method=requests.get.__name__.upper(), error="timeout").inc()

        # Transform the incoming payload into our model's service accounts.
        service_accounts: list[dict] = []
        for incoming_service_account in received_service_accounts:
            service_accounts.append(self._transform_incoming_payload(incoming_service_account))

        return service_accounts

    def get_service_accounts(self, user: User, bearer_token: str, options: dict = {}) -> list[dict]:
        """Request and returns the service accounts for the given tenant."""
        # We might want to bypass calls to the IT service on ephemeral or test environments.
        it_service_accounts: list[dict] = []
        if not settings.IT_BYPASS_IT_CALLS:
            it_service_accounts = self.request_service_accounts(bearer_token=bearer_token)

        # Get the service accounts from the database. The weird filter is to fetch the service accounts depending on
        # the account number or the organization ID the user gave.
        service_account_principals = Principal.objects.filter(type=TYPE_SERVICE_ACCOUNT).filter(
            (Q(tenant__isnull=False) & Q(tenant__account_id=user.account))
            | (Q(tenant__isnull=False) & Q(tenant__org_id=user.org_id))
        )

        # The following filters do not make sense for service accounts, because we either do not have the
        # corresponding fields to filter with, or it only applies to principals.
        # - Admin only
        # - Email
        # - Status
        usernames: [str] = []
        specified_usernames = options.get("usernames")
        if specified_usernames:
            usernames = specified_usernames.split(",")

        # If "match_criteria" is specified, only the first username is taken into account.
        match_criteria = options.get("match_criteria")
        if match_criteria:
            match_criteria: str = options["match_criteria"]
            username = usernames[0]

            if match_criteria == "partial":
                service_account_principals = service_account_principals.filter(username__startswith=username)
            else:
                service_account_principals = service_account_principals.filter(username=username)
        elif len(usernames) > 0:
            service_account_principals = service_account_principals.filter(username__in=usernames)

        # Sort order which defaults to ascending.
        sort_order_ascending = True
        sort_order = options.get("sort_order")
        if sort_order:
            sort_order_ascending = sort_order == "asc"

        asc_order_by_enabled = True
        order_by = options.get("order_by")
        if order_by:
            asc_order_by_enabled = not order_by.startswith("-")

        if sort_order_ascending and asc_order_by_enabled:
            service_account_principals = service_account_principals.order_by("username")
        else:
            service_account_principals = service_account_principals.order_by("-username")

        # We always set a default offset and a limit if the user doesn't specify them so it is safe to simply put the
        # two parameters in the query to slice it.
        offset = options.get("offset")
        limit = options.get("limit")

        service_account_principals[offset:limit]

        # If we are in an ephemeral or test environment, we will take all the service accounts of the user that are
        # stored in the database and generate a mocked response for them, simulating that IT has the corresponding
        # service account to complement the information.
        if settings.IT_BYPASS_IT_CALLS:
            it_service_accounts = self._get_mock_service_accounts(
                service_account_principals=service_account_principals
            )

        # Put the service accounts in a dict by for a quicker search.
        sap_dict: dict[str, dict] = {}
        for sap in service_account_principals:
            sap_dict[sap.service_account_id] = sap

        # Filter the incoming service accounts. Also, transform them to the payload we will
        # be returning.
        service_accounts: [dict] = self._merge_principals_it_service_accounts(
            service_account_principals=sap_dict, it_service_accounts=it_service_accounts, options=options
        )

        return service_accounts

    def get_service_accounts_group(self, group: Group, bearer_token: str, options: dict = {}) -> list[dict]:
        """Get the service accounts for the given group."""
        # We might want to bypass calls to the IT service on ephemeral or test environments.
        it_service_accounts: list[dict] = []
        if not settings.IT_BYPASS_IT_CALLS:
            it_service_accounts = self.request_service_accounts(bearer_token=bearer_token)

        # Fetch the service accounts from the group.
        group_service_account_principals = group.principals.filter(type=TYPE_SERVICE_ACCOUNT)

        # Apply the specified query pamareters for the collection. Begin with the sort order.
        sort_order = options.get("sort_order")
        if sort_order:
            if sort_order == "asc":
                order_by = "username"
            else:
                order_by = "-username"

            group_service_account_principals = group_service_account_principals.order_by(order_by)

        # Check if we should filter the service accounts by the username that the user specified.
        principal_username = options.get("principal_username")
        if principal_username:
            group_service_account_principals = group_service_account_principals.filter(
                username__contains=principal_username
            )

        # Get the limit and the offset. We always have default values for these, so it is safe to simply fetch them.
        limit = options["limit"]
        offset = options["offset"]

        # Filter the service accounts with the offset and the limit.
        group_service_account_principals[offset:limit]

        # If we are in an ephemeral or test environment, we will take all the service accounts of the user that are
        # stored in the database and generate a mocked response for them, simulating that IT has the corresponding
        # service account to complement the information.
        if settings.IT_BYPASS_IT_CALLS:
            it_service_accounts = self._get_mock_service_accounts(
                service_account_principals=group_service_account_principals
            )

        # Put the service accounts in a dict by for a quicker search.
        sap_dict: dict[str, dict] = {}
        for sap in group_service_account_principals:
            sap_dict[sap.service_account_id] = sap

        # Filter the incoming service accounts. Also, transform them to the payload we will
        # be returning.
        service_accounts: [dict] = self._merge_principals_it_service_accounts(
            service_account_principals=sap_dict, it_service_accounts=it_service_accounts, options=options
        )

        return service_accounts

    def _transform_incoming_payload(self, input: dict) -> dict:
        """Transform the incoming service account from IT into a dict which fits our response structure."""
        service_account: dict = {}

        client_id = input.get("clientId")
        name = input.get("name")
        description = input.get("description")
        created_by = input.get("createdBy")
        created_at = input.get("createdAt")

        if client_id:
            service_account["clientID"] = client_id

        if name:
            service_account["name"] = name

        if description:
            service_account["description"] = description

        if created_by:
            service_account["owner"] = created_by

        if created_at:
            service_account["time_created"] = created_at

        # Hard code the type for every service account.
        service_account["type"] = "service-account"

        return service_account

    def _merge_principals_it_service_accounts(
        self, service_account_principals: dict[str, dict], it_service_accounts: list[dict], options: dict
    ) -> list[dict]:
        """Merge the database principals with the service account principals and return the response payload."""
        service_accounts: [dict] = []

        # If the "username_only" parameter was set, we should only return that for the user.
        username_only = options.get("username_only")

        for it_service_account in it_service_accounts:
            try:
                sa_principal = service_account_principals[it_service_account["clientID"]]

                if username_only and username_only == "true":
                    service_accounts.append({"username": sa_principal.username})
                else:
                    # Get the principal's username from the database and set it in the response for the user.
                    it_service_account["username"] = sa_principal.username

                    service_accounts.append(it_service_account)
            # If we cannot find a requested service account to IT in the database, we simply
            # skip them.
            except KeyError:
                continue

        return service_accounts

    def _get_mock_service_accounts(self, service_account_principals: list[Principal]) -> list[dict]:
        """Mock an IT service call which returns service accounts. Useful for development or testing."""
        mocked_service_accounts: list[dict] = []
        for sap in service_account_principals:
            generated_uuid = uuid.uuid4()

            # Transform the service account to the structure our logic works with and then append it to the list of
            # mocked service accounts we will be returning.
            mocked_service_accounts.append(
                self._transform_incoming_payload(
                    {
                        "id": generated_uuid,
                        "clientId": sap.service_account_id,
                        "name": f"{generated_uuid}-name",
                        "description": f"{generated_uuid}-description",
                        "createdBy": sap.username,
                        "createdAt": round(time.time()),
                    }
                )
            )

        return mocked_service_accounts
