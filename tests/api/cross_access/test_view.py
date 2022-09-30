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
from api.cross_access.util import get_cross_principal_name
from api.serializers import create_tenant_name
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from management.models import Role, Principal
from rest_framework import status
from rest_framework.test import APIClient

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
        self.org_id = self.customer_data["org_id"]
        self.associate_non_admin_request_context = self._create_request_context(
            self.customer_data, self.user_data, create_customer=False, is_org_admin=False, is_internal=True
        )
        self.associate_non_admin_request = self.associate_non_admin_request_context["request"]

        self.not_anemic_customer_data = self._create_customer_data()
        self.not_anemic_account = "21112"
        self.not_anemic_org_id = self.not_anemic_customer_data["org_id"]
        self.not_anemic_customer_data["account_id"] = self.not_anemic_account
        self.not_anemic_customer_data["tenant_name"] = f"acct{self.not_anemic_account}"
        self.associate_not_anemic_request_context = self._create_request_context(
            self.not_anemic_customer_data, self.user_data, create_customer=False, is_org_admin=False, is_internal=True
        )
        self.associate_not_anemic_request = self.associate_not_anemic_request_context["request"]
        self.not_anemic_headers = self.associate_not_anemic_request_context["request"].META

        self.associate_admin_request_context = self._create_request_context(
            self.customer_data, self.user_data, create_customer=False, is_org_admin=True, is_internal=True
        )
        self.associate_admin_request = self.associate_admin_request_context["request"]

        """
            Create cross account requests 1 to 6: request_1 to request_6
            self.associate_admin_request has user_id 1111111, and account nubmer xxxxxx
            It would be approver for request_1, request_2, request_5;
            It would be requestor for request_3, request_6
            | target_account | user_id | start_date | end_date  |  status  | roles |
            |     xxxxxx     | 1111111 |    now     | now+10day | approved |       |
            |     xxxxxx     | 2222222 |    now     | now+10day | pending  |       |
            |     123456     | 1111111 |    now     | now+10day | approved |       |
            |     123456     | 2222222 |    now     | now+10day | pending  |       |
            |     xxxxxx     | 2222222 |    now     | now+10day | expired  |       |
            |     123456     | 1111111 |    now     | now_10day | pending  |       |
        """
        self.another_account = "123456"
        self.another_org_id = "54321"

        self.data4create = {
            "target_account": "012345",
            "target_org": "054321",
            "start_date": self.format_date(self.ref_time),
            "end_date": self.format_date(self.ref_time + timedelta(90)),
            "roles": ["role_1", "role_2"],
        }

        public_tenant = Tenant.objects.get(tenant_name="public")

        t = Tenant.objects.create(
            tenant_name=f"acct{self.data4create['target_account']}",
            account_id=self.data4create["target_account"],
            org_id=self.data4create["target_org"],
        )
        t.ready = True
        t.save()
        self.role_1 = Role.objects.create(name="role_1", system=True, tenant=public_tenant)
        self.role_2 = Role.objects.create(name="role_2", system=True, tenant=public_tenant)
        self.role_9 = Role.objects.create(name="role_9", system=True, tenant=public_tenant)
        self.role_8 = Role.objects.create(name="role_8", system=True, tenant=public_tenant)

        self.request_1 = CrossAccountRequest.objects.create(
            target_account=self.account,
            target_org=self.org_id,
            user_id="1111111",
            end_date=self.ref_time + timedelta(10),
            status="approved",
        )
        self.request_1.roles.add(*(self.role_1, self.role_2))
        self.request_2 = CrossAccountRequest.objects.create(
            target_account=self.account,
            target_org=self.org_id,
            user_id="2222222",
            end_date=self.ref_time + timedelta(10),
        )
        self.request_2.roles.add(*(self.role_1, self.role_2))
        self.request_3 = CrossAccountRequest.objects.create(
            target_account=self.another_account,
            target_org=self.another_org_id,
            user_id="1111111",
            end_date=self.ref_time + timedelta(10),
            status="approved",
        )
        self.request_4 = CrossAccountRequest.objects.create(
            target_account=self.account,
            target_org=self.org_id,
            user_id="2222222",
            end_date=self.ref_time + timedelta(10),
            status="pending",
        )
        self.request_5 = CrossAccountRequest.objects.create(
            target_account=self.account,
            target_org=self.org_id,
            user_id="2222222",
            end_date=self.ref_time + timedelta(10),
            status="expired",
        )
        self.request_6 = CrossAccountRequest.objects.create(
            target_account=self.another_account,
            target_org=self.another_org_id,
            user_id="1111111",
            end_date=self.ref_time + timedelta(10),
            status="pending",
        )
        self.not_anemic_request_1 = CrossAccountRequest.objects.create(
            target_account=self.not_anemic_account,
            target_org=self.not_anemic_org_id,
            user_id="1111111",
            end_date=self.ref_time + timedelta(10),
            status="approved",
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
        self.assertEqual(len(response.data["data"]), 4)
        email_list = [data.get("email") for data in response.data["data"]]
        self.assertTrue("test_user@email.com" in email_list)
        self.assertTrue("test_user_2@email.com" in email_list)

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
    def test_list_requests_query_by_account_with_status_filter_success(self, mock_request):
        """Test listing of cross account request based on account number of identity and filter status."""
        client = APIClient()

        # Single status filter
        response = client.get(f"{URL_LIST}?status=pending", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 2)
        self.assertEqual(response.data["data"][0].get("status"), "pending")
        self.assertEqual(response.data["data"][1].get("status"), "pending")

        # Multiple statuses filter
        response = client.get(f"{URL_LIST}?status=approved,expired", **self.headers)
        statuses = [data.get("status") for data in response.data["data"]]
        self.assertTrue("approved" in statuses)
        self.assertTrue("expired" in statuses)
        self.assertTrue("pending" not in statuses)

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
        self.assertEqual(len(response.data["data"]), 4)
        request_ids = [data.get("request_id") for data in response.data["data"]]
        for request_id in request_ids:
            self.assertTrue(
                request_id
                in [
                    str(self.request_1.request_id),
                    str(self.request_3.request_id),
                    str(self.request_6.request_id),
                    str(self.not_anemic_request_1.request_id),
                ]
            )

    def test_list_requests_query_by_user_id_filter_by_account_success(self):
        """Test listing cross account request based on user id of identity."""
        client = APIClient()
        response = client.get(
            f"{URL_LIST}?query_by=user_id&account={self.not_anemic_account}", **self.associate_not_anemic_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 1)
        self.assertEqual(response.data["data"][0].get("user_id"), "1111111")
        self.assertEqual(response.data["data"][0].get("target_account"), self.not_anemic_account)
        self.assertEqual(response.data["data"][0].get("status"), "approved")

        response = client.get(
            f"{URL_LIST}?query_by=user_id&account={self.not_anemic_account},{self.another_account}",
            **self.associate_not_anemic_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 3)

    def test_list_requests_query_by_user_id_with_combined_filters_success(self):
        """Test listing cross account request based on user id of identity."""
        expired_request = CrossAccountRequest.objects.create(
            target_account="098765",
            target_org="567890",
            user_id="1111111",
            end_date=self.ref_time + timedelta(10),
            status="approved",
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
        self.data4create["target_account"] = self.another_account
        self.data4create["target_org"] = self.another_org_id
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        if settings.AUTHENTICATE_WITH_ORG_ID:
            self.assertEqual(
                response.data.get("errors")[0].get("detail"), f"Org ID '{self.another_org_id}' does not exist."
            )
        else:
            self.assertEqual(
                response.data.get("errors")[0].get("detail"), f"Account '{self.another_account}' does not exist."
            )

    def test_create_requests_towards_their_own_account_fail(self):
        """Test the creation of cross account request towards their own account fails."""
        self.data4create["target_account"] = self.account
        self.data4create["target_org"] = self.org_id
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        if settings.AUTHENTICATE_WITH_ORG_ID:
            self.assertEqual(
                response.data.get("errors")[0].get("detail"),
                "Creating a cross access request for your own org id is not allowed.",
            )
        else:
            self.assertEqual(
                response.data.get("errors")[0].get("detail"),
                "Creating a cross access request for your own account is not allowed.",
            )

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
        self.assertEqual(
            response.data.get("errors")[0].get("detail"), "Access duration may not be longer than one year."
        )

    def test_create_requests_fail_for_end_date_being_past_value(self):
        """Test the creation of cross account request fail for end_date being past value."""
        self.data4create["end_date"] = self.format_date(self.ref_time + timedelta(-1))
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("errors")[0].get("detail"), "Please verify the end dates are not in the past."
        )

    def test_create_requests_fail_for_not_exist_role(self):
        """Test the creation of cross account request fail for not supported period."""
        self.data4create["roles"] = ["role_1", "role_3"]
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), "Role 'role_3' does not exist.")

    def test_create_requests_fail_for_not_canned_role(self):
        """Test the creation of cross account request fail for not supported period."""
        self.role_2.system = False
        self.role_2.save()
        self.data4create["roles"] = ["role_1", "role_2"]
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("errors")[0].get("detail"),
            "Only system roles may be assigned to a cross-account-request.",
        )

    def test_create_requests_fail_for_over_60_day_start_date(self):
        """Test the creation of cross account request fails when the start date is > 60 days out."""
        self.data4create["start_date"] = self.format_date(self.ref_time + timedelta(61))
        client = APIClient()
        response = client.post(
            f"{URL_LIST}?", self.data4create, format="json", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), "Start date must be within 60 days of today.")

    def test_update_request_denied_for_approver(self):
        """Test updating an entire CAR denied for approver."""
        self.data4create["target_account"] = self.account
        self.data4create["start_date"] = self.format_date(self.ref_time + timedelta(3))
        self.data4create["end_date"] = self.format_date(self.ref_time + timedelta(5))
        self.data4create["roles"] = ["role_8", "role_9"]

        car_uuid = self.request_2.request_id
        url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})

        client = APIClient()
        response = client.put(url, self.data4create, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("errors")[0].get("detail"), "Only the requestor may update the cross access request."
        )

    def test_update_request_success_for_requestor(self):
        """Test updating an entire CAR."""
        self.data4create["target_account"] = self.another_account
        self.data4create["target_org"] = self.another_org_id
        Tenant.objects.create(
            tenant_name=f"acct{self.another_account}", account_id=self.another_account, org_id=self.another_org_id
        )
        self.data4create["start_date"] = self.format_date(self.ref_time + timedelta(3))
        self.data4create["end_date"] = self.format_date(self.ref_time + timedelta(5))
        self.data4create["roles"] = ["role_8", "role_9"]
        self.data4create["status"] = "pending"

        car_uuid = self.request_1.request_id
        self.request_1.target_account = self.another_account
        self.request_1.target_org = self.another_org_id
        self.request_1.status = "pending"
        self.request_1.save()
        url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})

        client = APIClient()
        response = client.put(url, self.data4create, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for field in self.data4create:
            if field == "roles":
                for role in response.data.get("roles"):
                    self.assertIn(role.get("display_name"), self.data4create["roles"])
                continue
            self.assertEqual(self.data4create.get(field), response.data.get(field))

    def test_update_request_fail_acct_for_requestor(self):
        """Test that updating the account of a CAR fails."""
        self.data4create["target_account"] = "10001"
        self.data4create["target_org"] = self.another_org_id

        car_uuid = self.request_6.request_id
        url = reverse("cross-detail", kwargs={"pk": car_uuid})

        client = APIClient()
        response = client.put(url, self.data4create, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), "Target account must stay the same.")

    def test_update_request_fail_org_for_requestor(self):
        """Test that updating the target org of a CAR fails."""
        self.data4create["target_org"] = "1000001"

        car_uuid = self.request_6.request_id
        url = reverse("cross-detail", kwargs={"pk": car_uuid})

        client = APIClient()
        response = client.put(url, self.data4create, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), "Target org must stay the same.")

    def test_update_request_expired_for_requestor(self):
        """Test that updating an expired CAR fails."""
        self.data4create["end_date"] = self.format_date(self.ref_time + timedelta(20))

        car_uuid = self.request_3.request_id
        self.request_3.status = "expired"
        self.request_3.save()
        url = reverse("cross-detail", kwargs={"pk": car_uuid})

        client = APIClient()
        response = client.put(url, self.data4create, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), "Only pending requests may be updated.")

    def test_partial_update_denied_for_updating_CAR_belong_to_others(self):
        """Test updating part of a CAR does not have relation with api caller."""
        update_data = {"start_date": self.format_date(self.ref_time + timedelta(2))}

        # request_4's user_id is "2222222", associate_admin_request'user_id is "1111111"
        # request_4's target_account is "123456", associate_admin_request's account is "xxxxxx"
        car_uuid = self.request_4.request_id
        url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})

        client = APIClient()
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_partial_update_success_for_approver(self):
        """Test updating part of a CAR."""
        # request_2's account is "xxxxxx" same as associate_admin_request's account
        car_uuid = self.request_2.request_id
        url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})

        client = APIClient()

        # From pending to approved
        update_data = {"status": "approved"}
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("status"), update_data.get("status"))

        # From approved to denied
        update_data = {"status": "denied"}
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("status"), update_data.get("status"))

        # From denied to approved
        update_data = {"status": "approved"}
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("status"), update_data.get("status"))

        # From approved to cancelled would fail
        update_data = {"status": "cancelled"}
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_partial_update_invalid_update_denied_for_approver(self):
        """Test updating part of a CAR fail due to invalid update for approver."""
        # request_2's account is "xxxxxx" same as associate_admin_request's account
        car_uuid = self.request_2.request_id
        url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})
        client = APIClient()

        # fail to update if approver is not admin
        update_data = {"status": "approved"}
        response = client.patch(url, update_data, format="json", **self.associate_non_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # fail to update field other than status
        update_data = {"start_date": self.format_date(self.ref_time + timedelta(2))}
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # fail to update fields more than just status
        update_data = {"start_date": self.format_date(self.ref_time + timedelta(2)), "status": "approved"}
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # approver fail to update status from pending to cancelled
        update_data = {"status": "cancelled"}
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_partial_update_success_for_requestor(self):
        """Test updating part of a CAR."""
        # request_6's user_id is "1111111" same as associate_admin_request's user_id
        car_uuid = self.request_6.request_id
        url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})

        client = APIClient()
        update_data = {"status": "cancelled"}
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("status"), update_data.get("status"))

    def test_partial_update_approved_request_for_requestor(self):
        """Test that updating protected fields of a CAR fails."""
        car_uuid = self.request_3.request_id
        url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})

        client = APIClient()

        # Can not partial update status from approved to other status
        update_data = {"status": "cancelled"}
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_partial_update_expired_for_requestor(self):
        """Test that PATCHing an expired CAR fails."""
        update_data = {"end_date": self.format_date(self.ref_time + timedelta(18))}

        car_uuid = self.request_3.request_id
        self.request_3.status = "expired"
        self.request_3.save()
        url = reverse("cross-detail", kwargs={"pk": car_uuid})

        client = APIClient()
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_partial_update_bmi_for_requestor(self):
        """Test that PATCH with extra fields in body fails."""
        update_data = {"start_date": self.format_date(self.ref_time + timedelta(2)), "cup": "cake"}

        car_uuid = self.request_6.request_id
        url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})

        client = APIClient()
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_bad_date_spec_for_requestor(self):
        """Test that PUT with body fields not matching spec fails."""
        self.data4create["target_account"] = self.another_account
        self.data4create["target_org"] = self.another_org_id
        Tenant.objects.get_or_create(
            tenant_name=f"acct{self.another_account}", account_id=self.another_account, org_id=self.another_org_id
        )
        self.data4create["end_date"] = 12252021

        car_uuid = self.request_1.request_id
        self.request_1.target_account = self.another_account
        self.request_1.target_org = self.another_org_id
        self.request_1.status = "pending"
        self.request_1.save()
        url = reverse("cross-detail", kwargs={"pk": car_uuid})

        client = APIClient()
        response = client.put(url, self.data4create, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("errors")[0].get("detail"),
            "Datetime has wrong format. Use one of these formats instead: MM/DD/YYYY.",
        )

    def test_partial_update_bad_date_spec_for_requestor(self):
        """Test that PATCH with body fields not matching spec fails."""
        update_data = {"start_date": 12252021}

        car_uuid = self.request_6.request_id
        url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})

        client = APIClient()
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_bad_uuid(self):
        """Test that update endpoints reject invalid UUIDs."""
        bad_uuids = [
            "imateapot!",  # Not even close
            str(self.request_5.request_id).replace("-", ""),  # Malformed but valid UUID
            "7g895hq3-6204-43e6-9g4c-20de5f61e021",  # Non-hex values in UUID
            None,
        ]

        client = APIClient()
        for bad_uuid in bad_uuids:
            url = reverse("cross-detail", kwargs={"pk": bad_uuid})
            response = client.put(url, self.data4create, format="json", **self.associate_admin_request.META)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            response = client.patch(url, self.data4create, format="json", **self.associate_admin_request.META)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_principal_on_approval(self):
        """Test that moving a car to approved creates a principal."""
        update_data = {"status": "approved"}
        if settings.AUTHENTICATE_WITH_ORG_ID:
            principal_name = get_cross_principal_name(self.request_2.target_org, self.request_2.user_id)
            car_uuid = self.request_2.request_id
            url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})
            tenant = Tenant.objects.get(org_id=self.request_2.target_org)
        else:
            tenant_name = create_tenant_name(self.request_2.target_account)
            principal_name = get_cross_principal_name(self.request_2.target_account, self.request_2.user_id)
            car_uuid = self.request_2.request_id
            url = reverse("cross-detail", kwargs={"pk": str(car_uuid)})
            tenant = Tenant.objects.get(tenant_name=tenant_name)

        client = APIClient()
        response = client.patch(url, update_data, format="json", **self.associate_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("status"), update_data.get("status"))
        # Principal created in public schema
        princ = Principal.objects.get(username__iexact=principal_name)
        self.assertEqual(princ.username, principal_name)
        self.assertEqual(princ.tenant, tenant)
        self.assertTrue(princ.cross_account)
        if not settings.AUTHENTICATE_WITH_ORG_ID:
            self.assertTrue(princ.tenant.tenant_name, tenant_name)

    def test_cross_account_request_ordering_filter(self):
        "Test ordering filter for request id, created/start/end date."
        client = APIClient()
        # Sort by Request ID
        response = client.get(
            f"{URL_LIST}?query_by=user_id&order_by=request_id", **self.associate_non_admin_request.META
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data["data"]), 4)
        self.assertTrue(response.data["data"][0].get("request_id") < response.data["data"][1].get("request_id"))

        # Sorting the dates
        ## request_1 is created a little bit ealier than request_6, therefore, the
        ## first should be not_anemic_request_1
        response = client.get(
            f"{URL_LIST}?query_by=user_id&order_by=-created", **self.associate_non_admin_request.META
        )
        self.assertEqual(response.data["data"][0].get("request_id"), str(self.not_anemic_request_1.request_id))

        ## set start_date of request_3 to a day later
        self.request_3.start_date = self.ref_time + timedelta(1)
        self.request_3.save()
        response = client.get(
            f"{URL_LIST}?query_by=user_id&order_by=start_date", **self.associate_non_admin_request.META
        )
        self.assertEqual(response.data["data"][0].get("request_id"), str(self.request_1.request_id))

        ## set start_date of request_3 to 21 days later so its end_date bigger than request_1
        self.request_3.end_date = self.ref_time + timedelta(21)
        self.request_3.save()
        response = client.get(
            f"{URL_LIST}?query_by=user_id&order_by=-end_date", **self.associate_non_admin_request.META
        )
        self.assertEqual(response.data["data"][0].get("request_id"), str(self.request_3.request_id))

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
    def test_list_requests_query_by_org_id_success(self, mock_request):
        """Test that cross account request stores org_id."""
        client = APIClient()
        response = client.get(f"{URL_LIST}{self.request_2.request_id}/", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("email"), "test_user@email.com")
        self.assertEqual(response.data.get("target_org"), self.org_id)
        self.assertEqual(len(response.data.get("roles")), 2)
