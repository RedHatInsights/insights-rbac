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
"""Test the principal viewset."""

from unittest.mock import patch, ANY

from django.urls import reverse
from django.test.utils import override_settings
from rest_framework import status
from rest_framework.test import APIClient

from api.common.pagination import StandardResultsSetPagination
from api.models import Tenant, User
from management.models import *
from management.principal.unexpected_status_code_from_it import UnexpectedStatusCodeFromITError
from tests.identity_request import IdentityRequest
from management.principal.proxy import PrincipalProxy


class PrincipalViewNonAdminTests(IdentityRequest):
    """Test the principal view for nonadmin user."""

    def setUp(self):
        """Set up the principal view nonadmin tests."""
        super().setUp()
        non_admin_tenant_name = "acct1234"
        self.non_admin_tenant = Tenant.objects.create(
            tenant_name=non_admin_tenant_name, account_id="1234", org_id="4321"
        )

        self.user_data = {"username": "non_admin", "email": "non_admin@example.com"}
        self.customer = {"account_id": "1234", "org_id": "4321", "tenant_name": non_admin_tenant_name}
        self.request_context = self._create_request_context(self.customer, self.user_data, is_org_admin=False)

        request = self.request_context["request"]
        self.headers = request.META

        self.principal = Principal(username="test_user", tenant=self.tenant)
        self.principal.save()

    def tearDown(self):
        """Tear down principal nonadmin viewset tests."""
        Principal.objects.all().delete()

    def test_non_admin_cannot_read_principal_list_without_permissions(self):
        """Test that we can not read a list of principals as a non-admin without permissions."""
        url = reverse("v1_management:principals")
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={"status_code": 200, "data": {"userCount": "1", "users": [{"username": "test_user"}]}},
    )
    def test_non_admin_can_read_principal_list_with_permissions(self, mock_request):
        """Test that we can read a list of principals as a non-admin with proper permissions."""
        non_admin_principal = Principal.objects.create(username="non_admin", tenant=self.non_admin_tenant)
        group = Group.objects.create(name="Non-admin group", tenant=self.non_admin_tenant)
        group.principals.add(non_admin_principal)
        policy = Policy.objects.create(name="Non-admin policy", group=group, tenant=self.non_admin_tenant)
        role = Role.objects.create(name="Non-admin role", tenant=self.non_admin_tenant)
        policy.roles.add(role)
        permission = Permission.objects.create(
            application="rbac",
            resource_type="principals",
            verb="read",
            permission="rbac:principal:read",
            tenant=self.non_admin_tenant,
        )
        access = Access.objects.create(permission=permission, role=role, tenant=self.non_admin_tenant)

        url = reverse("v1_management:principals")
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "admin_only": "false",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer["org_id"],
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 1)
        self.assertEqual(len(response.data.get("data")), 1)

        principal = response.data.get("data")[0]
        self.assertIsNotNone(principal.get("username"))
        self.assertEqual(principal.get("username"), self.principal.username)


class PrincipalViewsetTests(IdentityRequest):
    """Test the principal viewset."""

    def setUp(self):
        """Set up the principal viewset tests."""
        super().setUp()
        request = self.request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        user.org_id = self.customer_data["org_id"]
        request.user = user

        self.principal = Principal(username="test_user", tenant=self.tenant)
        self.principal.save()

    def tearDown(self):
        """Tear down principal viewset tests."""
        Principal.objects.all().delete()

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": [{"username": "test_user", "account_number": "1234", "org_id": "4321"}],
        },
    )
    def test_read_principal_list_success(self, mock_request):
        """Test that we can read a list of principals."""
        # Create a cross_account user in rbac.
        cross_account_principal = Principal.objects.create(
            username="cross_account_user", cross_account=True, tenant=self.tenant
        )

        url = reverse("v1_management:principals")
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "admin_only": "false",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer_data["org_id"],
        )
        # /principals/ endpoint won't return the cross_account_principal, which does not exist in IT.
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 1)
        self.assertEqual(len(response.data.get("data")), 1)

        principal = response.data.get("data")[0]
        self.assertCountEqual(list(principal.keys()), ["username", "account_number", "org_id"])
        self.assertIsNotNone(principal.get("username"))
        self.assertEqual(principal.get("username"), self.principal.username)

        cross_account_principal.delete()

    def test_read_principal_list_username_only_true_success(self):
        """Test that we can read a list of principals with username_only=true."""
        url = f'{reverse("v1_management:principals")}?username_only=true'
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 1)
        self.assertEqual(len(response.data.get("data")), 1)

        principal = response.data.get("data")[0]
        self.assertCountEqual(list(principal.keys()), ["username"])
        self.assertIsNotNone(principal.get("username"))
        self.assertEqual(principal.get("username"), self.principal.username)

    @override_settings(BYPASS_BOP_VERIFICATION=True)
    def test_read_principal_list_username_only_false_success(self):
        """Test that we can read a list of principals with username_only=false."""
        url = f'{reverse("v1_management:principals")}?username_only=false'
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 1)
        self.assertEqual(len(response.data.get("data")), 1)

        principal = response.data.get("data")[0]
        self.assertCountEqual(
            list(principal.keys()), ["username", "first_name", "last_name", "email", "user_id", "type"]
        )
        self.assertIsNotNone(principal.get("username"))
        self.assertEqual(principal.get("username"), self.principal.username)

    def test_read_principal_list_username_only_invalid(self):
        """Test that we get a 400 back with username_only=foo."""
        url = f'{reverse("v1_management:principals")}?username_only=foo'
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_principal_list_username_only_pagination(self):
        """Test the pagination is correct when we read a list of principals with username_only=true."""
        # Create few principals for the pagination test
        for i in range(5):
            Principal.objects.create(username=f"test_user{i}", tenant=self.tenant)
        # now in DB we have these principals:
        # 1) test_user   2) test_user0  3) test_user1
        # 4) test_user2  5) test_user3  6) test_user4

        client = APIClient()
        base_url = f'{reverse("v1_management:principals")}?username_only=true'

        # TEST 1
        limit = 2
        url = f"{base_url}&limit={limit}"
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # With limit=2 the response contains 2 principals from 6
        self.assertEqual(int(response.data.get("meta").get("count")), 6)
        self.assertEqual(len(response.data.get("data")), limit)

        principals = response.data.get("data")
        self.assertEqual(principals[0].get("username"), "test_user")
        self.assertEqual(principals[1].get("username"), "test_user0")

        # test that data contains only the 'username' and nothing else
        self.assertEqual(len(principals[0].keys()), 1)
        self.assertEqual(len(principals[1].keys()), 1)

        # TEST 2
        offset = 2
        limit = 3
        url = f"{base_url}&limit={limit}&offset={offset}"
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # With limit=3 the response contains 3 principals from 6
        self.assertEqual(int(response.data.get("meta").get("count")), 6)
        self.assertEqual(len(response.data.get("data")), limit)

        principals = response.data.get("data")
        self.assertEqual(principals[0].get("username"), "test_user1")
        self.assertEqual(principals[1].get("username"), "test_user2")
        self.assertEqual(principals[2].get("username"), "test_user3")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": {
                "userCount": "2",
                "users": [
                    {"username": "test_user1", "is_org_admin": "true"},
                    {"username": "test_user2", "is_org_admin": "false"},
                ],
            },
        },
    )
    def test_check_principal_admin(self, mock_request):
        """Test that we can read a list of principals."""
        url = reverse("v1_management:principals")
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "admin_only": "false",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer_data["org_id"],
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 2)
        self.assertEqual(len(response.data.get("data")), 2)

        principal = response.data.get("data")[0]
        self.assertIsNotNone(principal.get("username"))
        self.assertEqual(principal.get("username"), "test_user1")
        self.assertIsNotNone(principal.get("is_org_admin"))
        self.assertTrue(principal.get("is_org_admin"))

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_read_principal_filtered_list_success_without_cross_account_user(self, mock_request):
        """Test that we can read a filtered list of principals."""
        # Create a cross_account user in rbac.
        cross_account_principal = Principal.objects.create(
            username="cross_account_user", cross_account=True, tenant=self.tenant
        )

        url = f'{reverse("v1_management:principals")}?usernames=test_user,cross_account_user&offset=30'
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            ["test_user", "cross_account_user"],
            org_id=ANY,
            limit=10,
            offset=30,
            options={
                "limit": 10,
                "offset": 30,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": "user",
            },
        )
        # Cross account user won't be returned.
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("meta").get("count"), 1)

        principal = response.data.get("data")[0]
        self.assertIsNotNone(principal.get("username"))
        self.assertEqual(principal.get("username"), "test_user")

        cross_account_principal.delete()

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user1"}, {"username": "test_user2"}]},
    )
    def test_read_principal_filtered_list_with_untrimmed_values(self, mock_request):
        """Test that we can read a filtered list of principals and username values are processed as trimmed values."""
        client = APIClient()
        for gap in ("", " ", "     "):
            url = f'{reverse("v1_management:principals")}?usernames=test_user1,{gap}test_user2'
            response = client.get(url, **self.headers)
            # Regardless of the size of the gap between the values, the function is called with the same parameters
            # => the spaces are correctly removed before the function call.
            mock_request.assert_called_with(
                ["test_user1", "test_user2"],
                org_id=ANY,
                limit=10,
                offset=0,
                options={
                    "limit": 10,
                    "offset": 0,
                    "sort_order": "asc",
                    "status": "enabled",
                    "username_only": "false",
                    "principal_type": "user",
                },
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(len(response.data.get("data")), 2)

        # The function is called three times in this test.
        self.assertEqual(mock_request.call_count, 3)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_read_principal_filtered_list_success(self, mock_request):
        """Test that we can read a filtered list of principals."""
        url = f'{reverse("v1_management:principals")}?usernames=test_user75&offset=30'
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            ["test_user75"],
            org_id=ANY,
            limit=10,
            offset=30,
            options={
                "limit": 10,
                "offset": 30,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": "user",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("meta").get("count"), 1)

        principal = response.data.get("data")[0]
        self.assertIsNotNone(principal.get("username"))
        self.assertEqual(principal.get("username"), "test_user")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_read_principal_partial_matching(self, mock_request):
        """Test that we can read a list of principals by partial matching."""
        url = f'{reverse("v1_management:principals")}?usernames=test_us,no_op&offset=30&match_criteria=partial'
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            input={"principalStartsWith": "test_us"},
            limit=10,
            offset=30,
            options={
                "limit": 10,
                "offset": 30,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer_data["org_id"],
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("meta").get("count"), 1)

        principal = response.data.get("data")[0]
        self.assertIsNotNone(principal.get("username"))
        self.assertEqual(principal.get("username"), "test_user")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_read_principal_multi_filter(self, mock_request):
        """Test that we can read a list of principals by partial matching."""
        url = f'{reverse("v1_management:principals")}?usernames=test_us&email=test&offset=30&match_criteria=partial'
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            input={"principalStartsWith": "test_us", "emailStartsWith": "test"},
            limit=10,
            offset=30,
            options={
                "limit": 10,
                "offset": 30,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer_data["org_id"],
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("meta").get("count"), 1)

        principal = response.data.get("data")[0]
        self.assertIsNotNone(principal.get("username"))
        self.assertEqual(principal.get("username"), "test_user")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_bad_query_param_limit(self, mock_request):
        """Test handling of bad limit. Invalid limit value should be replaced by the default limit."""
        default_limit = StandardResultsSetPagination.default_limit
        client = APIClient()

        for limit in ["foo", -10, 0, ""]:
            url = f'{reverse("v1_management:principals")}?limit={limit}'
            response = client.get(url, **self.headers)

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data.get("meta").get("limit"), default_limit)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_bad_query_param_offset(self, mock_request):
        """Test handling of bad offset. Invalid offset value should be replaced by the default offset value."""
        client = APIClient()

        for offset in ["foo", -10, 0, ""]:
            url = f'{reverse("v1_management:principals")}?offset={offset}'
            response = client.get(url, **self.headers)

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data.get("meta").get("offset"), 0)

    def test_bad_query_param_of_sort_order(self):
        """Test handling of bad query params."""
        url = f'{reverse("v1_management:principals")}?sort_order=det'
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={"status_code": status.HTTP_500_INTERNAL_SERVER_ERROR, "errors": [{"detail": "error"}]},
    )
    def test_read_principal_list_fail(self, mock_request):
        """Test that we can handle a failure with listing principals."""
        url = reverse("v1_management:principals")
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        error = response.data.get("errors")[0]
        self.assertIsNotNone(error.get("detail"))

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [{"username": "test_user", "account_number": "1234", "org_id": "4321", "id": "5678"}],
        },
    )
    def test_read_principal_list_account(self, mock_request):
        """Test that we can handle a request with matching accounts"""
        url = f'{reverse("v1_management:principals")}?usernames=test_user&offset=30&sort_order=desc'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            ["test_user"],
            org_id=ANY,
            limit=10,
            offset=30,
            options={
                "limit": 10,
                "offset": 30,
                "sort_order": "desc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": "user",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        resp = proxy._process_data(response.data.get("data"), org_id="4321", org_id_filter=True, return_id=True)
        self.assertEqual(len(resp), 1)

        self.assertEqual(resp[0]["username"], "test_user")
        self.assertEqual(resp[0]["user_id"], "5678")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [{"username": "test_user", "account_number": "54321", "org_id": "54322"}],
        },
    )
    def test_read_principal_list_account_fail(self, mock_request):
        """Test that we can handle a request with matching accounts"""
        url = f'{reverse("v1_management:principals")}?usernames=test_user&offset=30'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        resp = proxy._process_data(response.data.get("data"), org_id="4321", org_id_filter=True)
        self.assertEqual(len(resp), 0)

        self.assertNotEqual(resp, "test_user")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [{"username": "test_user", "account_number": "54321", "org_id": "54322"}],
        },
    )
    def test_read_principal_list_account_filter(self, mock_request):
        """Test that we can handle a request with matching accounts"""
        url = f'{reverse("v1_management:principals")}?usernames=test_user&offset=30'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        resp = proxy._process_data(response.data.get("data"), org_id="4321", org_id_filter=False)

        self.assertEqual(len(resp), 1)

        self.assertEqual(resp[0]["username"], "test_user")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": [{"username": "test_user", "account_number": "54321", "org_id": "54322"}],
        },
    )
    def test_read_principal_list_by_email(self, mock_request):
        """Test that we can handle a request with an email address"""
        url = f'{reverse("v1_management:principals")}?email=test_user@example.com'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        resp = proxy._process_data(response.data.get("data"), org_id="54322", org_id_filter=False)
        self.assertEqual(len(resp), 1)

        mock_request.assert_called_once_with(
            input={"primaryEmail": "test_user@example.com"},
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer_data["org_id"],
        )

        self.assertEqual(resp[0]["username"], "test_user")

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": {"userCount": "1", "users": [{"username": "test_user", "is_org_admin": "true"}]},
        },
    )
    def test_read_users_of_desired_status(self, mock_request):
        """Test that we can return users of desired status within an account"""
        url = f'{reverse("v1_management:principals")}?status=disabled'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), "1")
        mock_request.assert_called_once_with(
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "disabled",
                "admin_only": "false",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer_data["org_id"],
        )

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": {"userCount": "1", "users": [{"username": "test_user", "is_org_admin": "true"}]},
        },
    )
    def test_principal_default_status_enabled(self, mock_request):
        """Tests when not passing in status the user active status will be enabled"""
        url = f'{reverse("v1_management:principals")}'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), "1")
        mock_request.assert_called_once_with(
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "admin_only": "false",
                "status": "enabled",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer_data["org_id"],
        )

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": {"userCount": "1", "users": [{"username": "test_user", "is_org_admin": "true"}]},
        },
    )
    def test_read_list_of_admins(self, mock_request):
        """Test that we can return only org admins within an account"""
        url = f'{reverse("v1_management:principals")}?admin_only=true'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), "1")
        mock_request.assert_called_once_with(
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "admin_only": "true",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer_data["org_id"],
        )

    def test_read_users_with_invalid_status_value(self):
        """Test that reading user with invalid status value returns 400"""
        url = f'{reverse("v1_management:principals")}?status=invalid'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_users_with_invalid_admin_only_value(self):
        """Test that reading user with invalid status value returns 400"""
        url = f'{reverse("v1_management:principals")}?admin_only=invalid'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "account_number": "54321",
                    "org_id": "54322",
                    "email": "test_user@example.com",
                }
            ],
        },
    )
    def test_read_principal_list_by_email_partial_matching(self, mock_request):
        """Test that we can handle a request with a partial email address"""
        url = f'{reverse("v1_management:principals")}?email=test_use&match_criteria=partial'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        resp = proxy._process_data(response.data.get("data"), org_id="54322", org_id_filter=False)
        self.assertEqual(len(resp), 1)

        mock_request.assert_called_once_with(
            input={"emailStartsWith": "test_use"},
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer_data["org_id"],
        )

        self.assertEqual(resp[0]["username"], "test_user")

    def test_read_principal_invalid_type_query_params(self):
        """
        Test that when an invalid "principal type" query parameter is specified,
        a bad request response is returned
        """
        url = reverse("v1_management:principals")
        client = APIClient()

        invalidQueryParams = ["hello", "world", "service-accounts", "users"]
        for invalidQueryParam in invalidQueryParams:
            response = client.get(url, {"type": invalidQueryParam}, **self.headers)

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={
            "status_code": 200,
            "data": [{"username": "test_user", "account_number": "1234", "org_id": "4321"}],
        },
    )
    def test_read_principal_users(self, mock_request):
        """Test that when the "user" query parameter is specified, the real users are returned."""
        # Create a cross_account user in rbac.
        cross_account_principal = Principal.objects.create(
            username="cross_account_user", cross_account=True, tenant=self.tenant
        )

        url = reverse("v1_management:principals")
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "admin_only": "false",
                "username_only": "false",
                "principal_type": "user",
            },
            org_id=self.customer_data["org_id"],
        )
        # /principals/ endpoint won't return the cross_account_principal, which does not exist in IT.
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 1)
        self.assertEqual(len(response.data.get("data")), 1)

        principal = response.data.get("data")[0]
        self.assertCountEqual(list(principal.keys()), ["username", "account_number", "org_id"])
        self.assertIsNotNone(principal.get("username"))
        self.assertEqual(principal.get("username"), self.principal.username)

        cross_account_principal.delete()

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_read_principal_service_account_list_success(self, mock_request):
        """Test that we can read a list of service accounts."""
        # Create SA in the database
        sa_client_id = "b6636c60-a31d-013c-b93d-6aa2427b506c"
        sa_username = "service_account-" + sa_client_id

        Principal.objects.create(
            username=sa_username,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_id,
        )

        mock_request.return_value = [
            {
                "clientId": sa_client_id,
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "jsmith",
                "username": sa_username,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]

        url = f"{reverse('v1_management:principals')}?type=service-account"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 1)
        self.assertEqual(len(response.data.get("data")), 1)

        sa = response.data.get("data")[0]
        self.assertCountEqual(
            list(sa.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa.get("clientId"), sa_client_id)
        self.assertEqual(sa.get("name"), "service_account_name")
        self.assertEqual(sa.get("description"), "Service Account description")
        self.assertEqual(sa.get("owner"), "jsmith")
        self.assertEqual(sa.get("type"), "service-account")
        self.assertEqual(sa.get("username"), sa_username)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_read_principal_service_account_list_empty_response(self, mock_request):
        """Test that empty response is returned when tenant doesn't have a service account in RBAC database."""

        sa_client_id = "026f5290-a3d3-013c-b93f-6aa2427b506c"
        mock_request.return_value = [
            {
                "clientId": sa_client_id,
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "jsmith",
                "username": "service_account-" + sa_client_id,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]

        url = f"{reverse('v1_management:principals')}?type=service-account"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 0)
        self.assertEqual(len(response.data.get("data")), 0)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_read_principal_service_account_valid_limit_offset(self, mock_request):
        """Test that we can read a list of service accounts according to the given limit and offset."""
        # Create 3 SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        for uuid in sa_client_ids:
            Principal.objects.create(
                username="service_account-" + uuid,
                tenant=self.tenant,
                type="service-account",
                service_account_id=uuid,
            )

        # create a return value for the mock
        mocked_values = []
        for uuid in sa_client_ids:
            mocked_values.append(
                {
                    "clientId": uuid,
                    "name": f"service_account_name_{uuid.split('-')[0]}",
                    "description": f"Service Account description {uuid.split('-')[0]}",
                    "owner": "jsmith",
                    "username": "service_account-" + uuid,
                    "time_created": 1706784741,
                    "type": "service-account",
                }
            )

        mock_request.return_value = mocked_values

        # without limit and offset the default values are used
        # limit=10, offset=0
        url = f"{reverse('v1_management:principals')}?type=service-account"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(int(response.data.get("meta").get("count")), 3)
        self.assertEqual(len(response.data.get("data")), 3)

        # set custom limit and offset
        test_values = [(1, 1), (2, 2), (5, 5)]
        for limit, offset in test_values:
            url = f"{reverse('v1_management:principals')}?type=service-account&limit={limit}&offset={offset}"
            client = APIClient()
            response = client.get(url, **self.headers)

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(int(response.data.get("meta").get("count")), 3)
            # for limit=1, offset=1, count=3 is the result min(1, max(0, 2)) = 1
            # for limit=2, offset=2, count=3 is the result min(2, max(0, 1)) = 1
            # for limit=5, offset=5, count=3 is the result min(5, max(0, -2)) = 0
            self.assertEqual(len(response.data.get("data")), min(limit, max(0, 3 - offset)))

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_read_principal_service_account_invalid_limit_offset(self, mock_request):
        """Test that default values are used for invalid limit and offset"""
        sa_client_id = "026f5290-a3d3-013c-b93f-6aa2427b506c"
        mock_request.return_value = [
            {
                "clientId": sa_client_id,
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "jsmith",
                "username": "service_account-" + sa_client_id,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]

        test_values = [(-1, -1), ("foo", "foo"), (0, 0)]
        default_limit = StandardResultsSetPagination.default_limit
        client = APIClient()

        for limit, offset in test_values:
            url = f"{reverse('v1_management:principals')}?type=service-account&limit={limit}&offset={offset}"
            response = client.get(url, **self.headers)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data.get("meta").get("offset"), 0)
            self.assertEqual(response.data.get("meta").get("limit"), default_limit)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch(
        "management.principal.it_service.ITService.get_service_accounts",
        side_effect=UnexpectedStatusCodeFromITError("Mocked error"),
    )
    def test_read_principal_service_account_unexpected_internal_error(self, mock_request):
        """
        Test the expected error message is returned in case of unexpected internal error that is returned from
        method ITService.get_service_accounts().
        """
        expected_message = "Unexpected internal error."
        url = f"{reverse('v1_management:principals')}?type=service-account"
        client = APIClient()
        response = client.get(url, **self.headers)
        err = response.json()["errors"][0]
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(err["detail"], expected_message)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_read_principal_service_account_usernames_only(self, mock_request):
        """Test the pagination is correct when we read a list of service accounts with username_only=true."""
        # Create 5 SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
            "1a67d137-374a-4aeb-8f27-83a321e876f9",
            "eb594f55-3a84-436b-8d3a-36d0f1f3dc2e",
        ]
        for uuid in sa_client_ids:
            Principal.objects.create(
                username="service_account-" + uuid,
                tenant=self.tenant,
                type="service-account",
                service_account_id=uuid,
            )

        # create a return value for the mock
        mocked_values = []
        for uuid in sa_client_ids:
            mocked_values.append(
                {
                    "clientId": uuid,
                    "name": f"service_account_name_{uuid.split('-')[0]}",
                    "description": f"Service Account description {uuid.split('-')[0]}",
                    "owner": "jsmith",
                    "username": "service_account-" + uuid,
                    "time_created": 1706784741,
                    "type": "service-account",
                }
            )

        mock_request.return_value = mocked_values

        client = APIClient()
        base_url = f"{reverse('v1_management:principals')}?type=service-account&username_only=true"

        # TEST 1
        limit = 2
        url = f"{base_url}&limit={limit}"
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # With limit=2 the response contains 2 principals from 5
        self.assertEqual(int(response.data.get("meta").get("count")), 5)
        self.assertEqual(len(response.data.get("data")), limit)

        sa = response.data.get("data")
        self.assertEqual(sa[0].get("username"), "service_account-" + sa_client_ids[0])
        self.assertEqual(sa[1].get("username"), "service_account-" + sa_client_ids[1])
        # test that data contains only the 'username' and nothing else
        self.assertEqual(len(sa[0].keys()), 1)
        self.assertEqual(len(sa[1].keys()), 1)

        # TEST 2
        offset = 2
        limit = 3
        url = f"{base_url}&limit={limit}&offset={offset}"
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # With limit=3 the response contains principals from 5
        self.assertEqual(int(response.data.get("meta").get("count")), 5)
        self.assertEqual(len(response.data.get("data")), limit)

        sa = response.data.get("data")
        self.assertEqual(sa[0].get("username"), "service_account-" + sa_client_ids[2])
        self.assertEqual(sa[1].get("username"), "service_account-" + sa_client_ids[3])
        self.assertEqual(sa[2].get("username"), "service_account-" + sa_client_ids[4])

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_read_principal_service_account_filtered_list_success(self, mock_request):
        """Test that we can read a filtered list of service accounts."""
        # Create 3 SA in the database
        sa_client_ids = [
            "06494bcb-1409-401b-b210-0303c810f6b3",
            "e8e388c3-eebb-4a58-a806-28bd7a1958f9",
            "355a0f5f-0aa4-4064-855f-3e6cef2fd785",
        ]
        for uuid in sa_client_ids:
            Principal.objects.create(
                username="service_account-" + uuid,
                tenant=self.tenant,
                type="service-account",
                service_account_id=uuid,
            )

        # create a return value for the mock
        mocked_sa = []
        for uuid in sa_client_ids:
            mocked_sa.append(
                {
                    "clientId": uuid,
                    "name": f"service_account_name_{uuid.split('-')[0]}",
                    "description": f"Service Account description {uuid.split('-')[0]}",
                    "owner": "jsmith",
                    "username": "service_account-" + uuid,
                    "time_created": 1706784741,
                    "type": "service-account",
                }
            )

        mock_request.return_value = mocked_sa

        # Without the 'usernames' filter we get all values
        client = APIClient()
        url = f"{reverse('v1_management:principals')}?type=service-account"
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(int(response.data.get("meta").get("count")), 3)
        self.assertEqual(len(response.data.get("data")), 3)

        # With the 'usernames' filter we get only filtered values
        sa1 = mocked_sa[0]
        url = f"{reverse('v1_management:principals')}?type=service-account&usernames={sa1['username']}"
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(int(response.data.get("meta").get("count")), 1)
        self.assertEqual(len(response.data.get("data")), 1)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.get_service_accounts")
    def test_read_principal_service_account_filtered_list_with_untrimmed_values(self, mock_request):
        """
        Test that we can read a filtered list of service accounts
        and username values are processed as trimmed values.
        """
        # Create 3 SA in the database
        sa_client_ids = [
            "06494bcb-1409-401b-b210-0303c810f6b3",
            "e8e388c3-eebb-4a58-a806-28bd7a1958f9",
            "355a0f5f-0aa4-4064-855f-3e6cef2fd785",
        ]
        for uuid in sa_client_ids:
            Principal.objects.create(
                username="service_account-" + uuid,
                tenant=self.tenant,
                type="service-account",
                service_account_id=uuid,
            )

        # create a return value for the mock
        mocked_sa = []
        for uuid in sa_client_ids[:2]:
            mocked_sa.append(
                {
                    "clientId": uuid,
                    "name": f"sa_name_{uuid.split('-')[0]}",
                    "description": f"SA description {uuid.split('-')[0]}",
                    "owner": "jsmith",
                    "username": "service_account-" + uuid,
                    "time_created": 1706784741,
                    "type": "service-account",
                }
            )

        mock_request.return_value = mocked_sa, 2

        client = APIClient()
        sa1 = mocked_sa[0]
        sa2 = mocked_sa[1]
        for gap in ("", " ", "     "):
            url = f"{reverse('v1_management:principals')}?type=service-account&usernames={sa1['username']},{gap}{sa2['username']}"
            response = client.get(url, **self.headers)
            # Regardless of the size of the gap between the values, the function is called with the same parameters
            # => the spaces are correctly removed before the function call.
            mock_request.assert_called_with(
                user=ANY,
                options={
                    "limit": 10,
                    "offset": 0,
                    "sort_order": "asc",
                    "status": "enabled",
                    "principal_type": "service-account",
                    "usernames": f"{sa1['username']},{sa2['username']}",
                    "email": None,
                    "match_criteria": None,
                    "username_only": None,
                },
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(len(response.data.get("data")), 2)

        # The function is called three times in this test.
        self.assertEqual(mock_request.call_count, 3)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.proxy.PrincipalProxy.request_principals")
    @patch("management.principal.it_service.ITService.get_service_accounts")
    def test_read_principal_all(self, mock_sa, mock_user):
        """Test that we can read both principal types in one request."""
        # Create 3 SA in the database and mock the Service Accounts return value
        sa_client_ids = [
            "06494bcb-1409-401b-b210-0303c810f6b3",
            "e8e388c3-eebb-4a58-a806-28bd7a1958f9",
            "355a0f5f-0aa4-4064-855f-3e6cef2fd785",
        ]
        for uuid in sa_client_ids:
            Principal.objects.create(
                username="service_account-" + uuid,
                tenant=self.tenant,
                type="service-account",
                service_account_id=uuid,
            )

        # create a return value for the mock
        mocked_sa = []
        for uuid in sa_client_ids:
            mocked_sa.append(
                {
                    "clientId": uuid,
                    "name": f"sa_name_{uuid.split('-')[0]}",
                    "description": f"SA description {uuid.split('-')[0]}",
                    "owner": "jsmith",
                    "username": "service_account-" + uuid,
                    "time_created": 1706784741,
                    "type": "service-account",
                }
            )

        mock_sa.return_value = mocked_sa, 3

        # Mock the User based Principals return value
        mock_user.return_value = {
            "status_code": 200,
            "data": {
                "userCount": "3",
                "users": [
                    {"username": "test_user1"},
                    {"username": "test_user2"},
                    {"username": "test_user3"},
                ],
            },
        }

        client = APIClient()
        url = f"{reverse('v1_management:principals')}?type=all"
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        for key in response.data.get("data").keys():
            self.assertIn(key, ["serviceAccounts", "users"])

        sa = response.data.get("data").get("serviceAccounts")
        users = response.data.get("data").get("users")
        self.assertEqual(len(sa), 3)
        self.assertEqual(len(users), 3)

        self.assertEqual(response.data.get("meta").get("count"), 6)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.view.PrincipalView.users_from_proxy")
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_read_principal_all_pagination(self, mock_sa, mock_user):
        """Test the pagination when we read both principal types in one request."""
        # Create 3 SA in the database and mock the Service Accounts return value
        sa_client_ids = [
            "06494bcb-1409-401b-b210-0303c810f6b3",
            "e8e388c3-eebb-4a58-a806-28bd7a1958f9",
            "355a0f5f-0aa4-4064-855f-3e6cef2fd785",
        ]
        for uuid in sa_client_ids:
            Principal.objects.create(
                username="service_account-" + uuid,
                tenant=self.tenant,
                type="service-account",
                service_account_id=uuid,
            )

        # create a return value for the mock
        mocked_sa = []
        for uuid in sa_client_ids:
            mocked_sa.append(
                {
                    "clientId": uuid,
                    "name": f"sa_name_{uuid.split('-')[0]}",
                    "description": f"SA description {uuid.split('-')[0]}",
                    "owner": "jsmith",
                    "username": "service_account-" + uuid,
                    "time_created": 1706784741,
                    "type": "service-account",
                }
            )

        mock_sa.return_value = mocked_sa

        # Mock the User based Principals return value
        mock_user.return_value = {
            "status_code": 200,
            "data": {
                "userCount": 3,
                "users": [
                    {"username": "test_user1"},
                    {"username": "test_user2"},
                ],
            },
        }, ""

        client = APIClient()

        # TEST 1 - 3 SA (service accounts) and 3 U (user based principals) -> 1 SA + 2 U in the response
        limit = 3
        offset = 2
        url = f"{reverse('v1_management:principals')}?type=all&limit={limit}&offset={offset}"
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        sa = response.data.get("data").get("serviceAccounts")
        users = response.data.get("data").get("users")
        self.assertEqual(len(sa), 1)
        self.assertEqual(len(users), 2)

        self.assertEqual(response.data.get("meta").get("count"), 6)
        self.assertEqual(response.data.get("meta").get("limit"), limit)
        self.assertEqual(response.data.get("meta").get("offset"), offset)

        # The query for user based principals was called with new limit and offset
        new_limit = 2
        new_offset = 0
        mock_user.assert_called_once_with(ANY, ANY, ANY, new_limit, new_offset)

        # TEST 2 - 3 SA (service accounts) and 3 U (user based principals) -> only 2 SA in the response
        limit = 2
        offset = 0
        url = f"{reverse('v1_management:principals')}?type=all&limit={limit}&offset={offset}"
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        sa = response.data.get("data").get("serviceAccounts")
        self.assertNotIn("users", response.data.get("data").keys())
        self.assertEqual(len(sa), 2)

        self.assertEqual(response.data.get("meta").get("count"), 6)
        self.assertEqual(response.data.get("meta").get("limit"), limit)
        self.assertEqual(response.data.get("meta").get("offset"), offset)

        # TEST 3 - 3 SA (service accounts) and 3 U (user based principals) -> only 2 U in the response
        limit = 2
        offset = 3
        url = f"{reverse('v1_management:principals')}?type=all&limit={limit}&offset={offset}"
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        users = response.data.get("data").get("users")
        self.assertEqual(len(users), 2)
        self.assertNotIn("serviceAccounts", response.data.get("data").keys())

        self.assertEqual(response.data.get("meta").get("count"), 6)
        self.assertEqual(response.data.get("meta").get("limit"), limit)
        self.assertEqual(response.data.get("meta").get("offset"), offset)
