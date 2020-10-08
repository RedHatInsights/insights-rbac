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
from api.models import CrossAccountRequest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from datetime import timedelta
from unittest.mock import patch
from tests.identity_request import IdentityRequest


URL_LIST = reverse("cross-list")


class CrossAccountRequestViewTests(IdentityRequest):
    """Test the cross account request view."""

    def setUp(self):
        """Set up the cross account request for tests."""
        super().setUp()

        self.ref_time = timezone.now()
        self.account = self.customer_data["account_id"]
        self.associate_non_admin_request_context = self._create_request_context(
            self.customer_data, self.user_data, create_customer=False, is_org_admin=False, is_internal=True
        )
        self.associate_non_admin_request = self.associate_non_admin_request_context["request"]

        self.another_account = "123456"
        self.request_1 = CrossAccountRequest.objects.create(
            target_account=self.account, user_id="1111111", end_date=self.ref_time + timedelta(10), status="approved"
        )
        self.request_2 = CrossAccountRequest.objects.create(
            target_account=self.account, user_id="2222222", end_date=self.ref_time + timedelta(10)
        )
        self.request_3 = CrossAccountRequest.objects.create(
            target_account=self.another_account,
            user_id="1111111",
            end_date=self.ref_time + timedelta(10),
            status="approved",
        )
        self.request_4 = CrossAccountRequest.objects.create(
            target_account=self.another_account, user_id="2222222", end_date=self.ref_time + timedelta(10)
        )

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
