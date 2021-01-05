#
# Copyright 2020 Red Hat, Inc.
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
"""Test the cross account request model."""
from api.models import CrossAccountRequest, Tenant
from django.urls import reverse
from django.utils import timezone
from management.models import Role
from rest_framework import status
from rest_framework.test import APIClient
from tenant_schemas.utils import tenant_context

from datetime import datetime, timedelta
from unittest.mock import patch
from tests.identity_request import IdentityRequest


URL_LIST = reverse("cross-list")


class CrossAccountRequestViewTests(IdentityRequest):
    """Test the cross account request view."""

    def format_date(self, date):
        return date.strftime("%m/%d/%Y")

    def setUp(self):
        """Set up the cross account request for tests."""
        super().setUp()

        self.ref_time = timezone.now()
        self.account = self.customer_data["account_id"]
        self.associate_non_admin_request_context = self._create_request_context(
            self.customer_data, self.user_data, create_customer=False, is_org_admin=False, is_internal=True
        )
        self.associate_non_admin_request = self.associate_non_admin_request_context["request"]

        """
            Create cross account requests
            | target_account | user_id | start_date | end_date  |  status  | roles |
            |     xxxxxx     | 1111111 |    now     | now+10day | approved |
            |     xxxxxx     | 2222222 |    now     | now+10day | pending  |
            |     123456     | 1111111 |    now     | now+10day | approved |
            |     123456     | 2222222 |    now     | now+10day | pending  |
        """
        self.another_account = "123456"
        with tenant_context(Tenant.objects.get(schema_name="public")):
            self.role_1 = Role.objects.create(name="role_1")
            self.role_2 = Role.objects.create(name="role_2")
            self.request_1 = CrossAccountRequest.objects.create(
                target_account=self.account,
                user_id="1111111",
                end_date=self.ref_time + timedelta(10),
                status="approved",
            )
            self.request_1.roles.add(*(self.role_1, self.role_2))
            self.request_2 = CrossAccountRequest.objects.create(
                target_account=self.account, user_id="2222222", end_date=self.ref_time + timedelta(10)
            )
            self.request_2.roles.add(*(self.role_1, self.role_2))
            self.request_3 = CrossAccountRequest.objects.create(
                target_account=self.another_account,
                user_id="1111111",
                end_date=self.ref_time + timedelta(10),
                status="approved",
            )
            self.request_4 = CrossAccountRequest.objects.create(
                target_account=self.another_account, user_id="2222222", end_date=self.ref_time + timedelta(10)
            )
        self.data4create = {
            "target_account": "012345",
            "start_date": self.format_date(self.ref_time),
            "end_date": self.format_date(self.ref_time + timedelta(90)),
            "roles": ["role_1", "role_2"],
        }

    def tearDown(self):
        """Tear down cross account request model tests."""
        CrossAccountRequest.objects.all().delete()

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@email.com",
                    "first_name": "user",
                    "last_name": "test",
                    "account_number": "567890",
                    "user_id": "1111111",
                },
                {
                    "username": "test_user_2",
                    "email": "test_user_2@email.com",
                    "first_name": "user_2",
                    "last_name": "test",
                    "account_number": "123456",
                    "user_id": "2222222",
                },
            ],
        },
    )
    def test_list_requests_query_by_account_success(self, mock_request):
        """Test listing of cross account request based on account number of identity."""
        client = APIClient()
        response = client.get(URL_LIST, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 2)
        self.assertEqual(response.data["data"][0].get("email"), "test_user@email.com")
        self.assertEqual(response.data["data"][1].get("email"), "test_user_2@email.com")

    def test_list_requests_query_by_account_fail_if_not_admin(self):
        """Test listing cross account request based on account number of identity would fail for non org admin."""
        client = APIClient()
        response = client.get(URL_LIST, **self.associate_non_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["errors"][0]["detail"].code, "permission_denied")

    def test_list_requests_query_by_user_id_success(self):
        """Test listing cross account request based on user id of identity."""
        client = APIClient()
        response = client.get(f"{URL_LIST}?query_by=user_id", **self.associate_non_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 2)
        self.assertEqual(response.data["data"][0].get("email"), None)
        self.assertEqual(response.data["data"][0].get("user_id"), "1111111")
        self.assertEqual(response.data["data"][0].get("target_account"), self.account)
        self.assertEqual(response.data["data"][1].get("email"), None)
        self.assertEqual(response.data["data"][0].get("user_id"), "1111111")
        self.assertEqual(response.data["data"][1].get("target_account"), self.another_account)

    def test_list_requests_query_by_user_id_filter_by_account_success(self):
        """Test listing cross account request based on user id of identity."""
        client = APIClient()
        response = client.get(
            f"{URL_LIST}?query_by=user_id&account={self.account}", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)
        self.assertEqual(response.data["data"][0].get("user_id"), "1111111")
        self.assertEqual(response.data["data"][0].get("target_account"), self.account)
        self.assertEqual(response.data["data"][0].get("status"), "approved")

        response = client.get(
            f"{URL_LIST}?query_by=user_id&account={self.account},{self.another_account}",
            **self.associate_non_admin_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 2)

    def test_list_requests_query_by_user_id_with_combined_filters_success(self):
        """Test listing cross account request based on user id of identity."""
        expired_request = CrossAccountRequest.objects.create(
            target_account="098765", user_id="1111111", end_date=self.ref_time + timedelta(10), status="approved"
        )
        CrossAccountRequest.objects.filter(request_id=expired_request.request_id).update(end_date=timezone.now())

        client = APIClient()
        response = client.get(
            f"{URL_LIST}?query_by=user_id&account=098765&approved_only=True", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 0)

        response = client.get(
            f"{URL_LIST}?query_by=user_id&account={self.another_account}&approved_only=True",
            **self.associate_non_admin_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)
        self.assertEqual(response.data["data"][0].get("user_id"), "1111111")
        self.assertEqual(response.data["data"][0].get("target_account"), self.another_account)
        self.assertEqual(response.data["data"][0].get("status"), "approved")

    def test_list_requests_query_by_user_id_fail_if_not_associate(self):
        """Test listing cross account request based on user id of identity would fail for non associate."""
        client = APIClient()
        response = client.get(f"{URL_LIST}?query_by=user_id", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["errors"][0]["detail"].code, "permission_denied")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@email.com",
                    "first_name": "user",
                    "last_name": "test",
                    "account_number": "567890",
                    "user_id": "1111111",
                }
            ],
        },
    )
    def test_retrieve_request_query_by_account_success(self, mock_request):
        """Test retrieve of cross account request based on account number of identity."""
        client = APIClient()
        response = client.get(f"{URL_LIST}{self.request_1.request_id}/", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("email"), "test_user@email.com")
        self.assertEqual(response.data.get("target_account"), self.account)
        self.assertEqual(len(response.data.get("roles")), 2)

    def test_retrieve_request_query_by_account_fail_if_request_in_another_account(self):
        """Test retrieve cross account request based on account number of identity would fail for non org admin."""
        client = APIClient()
        response = client.get(f"{URL_LIST}{self.request_3.request_id}/", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_request_query_by_account_fail_if_not_admin(self):
        """Test retrieve cross account request based on account number of identity would fail for non org admin."""
        client = APIClient()
        response = client.get(f"{URL_LIST}{self.request_1.request_id}/", **self.associate_non_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["errors"][0]["detail"].code, "permission_denied")

    def test_retrieve_request_query_by_user_id_success(self):
        """Test retrieve cross account request based on user id of identity."""
        client = APIClient()
        response = client.get(
            f"{URL_LIST}{self.request_1.request_id}/?query_by=user_id", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("email"), None)
        self.assertEqual(response.data.get("user_id"), "1111111")
        self.assertEqual(response.data.get("target_account"), self.account)
        self.assertEqual(len(response.data.get("roles")), 2)

    def test_retrieve_request_query_by_user_id_fail_if_request_by_another_associate(self):
        """Test retrieve cross account request based on user id of identity would fail for non associate."""
        client = APIClient()
        response = client.get(
            f"{URL_LIST}{self.request_2.request_id}/?query_by=user_id", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_request_query_by_user_id_fail_if_not_associate(self):
        """Test retrieve cross account request based on user id of identity would fail for non associate."""
        client = APIClient()
        response = client.get(f"{URL_LIST}{self.request_1.request_id}/?query_by=user_id", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["errors"][0]["detail"].code, "permission_denied")

    def test_create_requests_success(self):
        """Test the creation of cross account request success."""
        with tenant_context(Tenant.objects.get(schema_name="public")):
            Tenant.objects.create(schema_name=f"acct{self.data4create['target_account']}")
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["target_account"], self.data4create["target_account"])
        self.assertEqual(response.data["status"], "pending")
        self.assertEqual(response.data["start_date"], self.data4create["start_date"])
        self.assertEqual(response.data["end_date"], self.data4create["end_date"])
        self.assertEqual(len(response.data["roles"]), 2)

    def test_create_requests_fail_for_no_account(self):
        """Test the creation of cross account request fails when the account doesn't exist."""
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_requests_fail_for_none_associate(self):
        """Test the creation of cross account request fail for none red hat associate."""
        client = APIClient()
        response = client.post(f"{URL_LIST}?", self.data4create, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_requests_fail_for_over_a_year_period(self):
        """Test the creation of cross account request fail for not supported period."""
        self.data4create["end_date"] = self.format_date(self.ref_time + timedelta(366))
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_requests_fail_for_end_date_being_past_value(self):
        """Test the creation of cross account request fail for end_date being past value."""
        self.data4create["end_date"] = "05/01/2020"
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_requests_fail_for_not_exist_role(self):
        """Test the creation of cross account request fail for not supported period."""
        self.data4create["roles"] = ["role_1", "role_3"]
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
