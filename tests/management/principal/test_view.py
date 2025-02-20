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

    def test_bad_query_param(self):
        """Test handling of bad query params."""
        url = f'{reverse("v1_management:principals")}?limit=foo'
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

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
    def test_principal_service_account_filter_by_name(self, mock_request):
        """Test that we can filter service accounts by name"""
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
                    "name": f"service_account_name_b6636c60",
                    "description": f"Service Account description {uuid.split('-')[0]}",
                    "owner": "jsmith",
                    "username": "service_account-" + uuid,
                    "time_created": 1706784741,
                    "type": "service-account",
                }
            )

        mock_request.return_value = mocked_values

        url = f"{reverse('v1_management:principals')}?type=service-account&name=service_account_name_b6636c60"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)

        sa = response.data.get("data")[0]
        self.assertCountEqual(
            list(sa.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa.get("name"), f"service_account_name_{sa_client_ids[0].split('-')[0]}")
        self.assertEqual(sa.get("description"), f"Service Account description {sa_client_ids[0].split('-')[0]}")
        self.assertEqual(sa.get("owner"), "jsmith")
        self.assertEqual(sa.get("type"), "service-account")
        self.assertEqual(sa.get("username"), "service_account-" + sa_client_ids[0])

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_filter_by_owner(self, mock_request):
        """Test that we can filter service accounts by owner"""
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
                "owner": "ecasey",
                "username": sa_username,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]

        url = f"{reverse('v1_management:principals')}?type=service-account&owner=ecasey"
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
        self.assertEqual(sa.get("owner"), "ecasey")
        self.assertEqual(sa.get("type"), "service-account")
        self.assertEqual(sa.get("username"), sa_username)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_filter_by_owner_wrong_returns_empty(self, mock_request):
        """Test that we can filter service accounts by owner with wrong input returns an empty array"""
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
                "owner": "ecasey",
                "username": sa_username,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]

        url = f"{reverse('v1_management:principals')}?type=service-account&owner=wrong_owner"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 0)
        self.assertEqual(len(response.data.get("data")), 0)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_filter_by_name_wrong_returns_empty(self, mock_request):
        """Test that we can filter service accounts by name with wrong input returns an empty array"""
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
                "owner": "ecasey",
                "username": sa_username,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]

        url = f"{reverse('v1_management:principals')}?type=service-account&name=wrong_name"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 0)
        self.assertEqual(len(response.data.get("data")), 0)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_filter_by_owner_with_limit_offset(self, mock_request):
        """Test that we can filter service accounts by owner with limit and offset provided"""
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
                    "owner": "ecasey",
                    "username": "service_account-" + uuid,
                    "time_created": 1706784741,
                    "type": "service-account",
                }
            )

        mock_request.return_value = mocked_values

        url = f"{reverse('v1_management:principals')}?type=service-account&owner=ecasey&limit=2&offset=1"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 3)
        self.assertEqual(len(response.data.get("data")), 2)

        sa = response.data.get("data")[0]
        self.assertCountEqual(
            list(sa.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa.get("name"), f"service_account_name_{sa_client_ids[1].split('-')[0]}")
        self.assertEqual(sa.get("description"), f"Service Account description {sa_client_ids[1].split('-')[0]}")
        self.assertEqual(sa.get("owner"), "ecasey")
        self.assertEqual(sa.get("type"), "service-account")
        self.assertEqual(sa.get("username"), "service_account-" + sa_client_ids[1])

        sa2 = response.data.get("data")[1]
        self.assertCountEqual(
            list(sa.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[2])
        self.assertEqual(sa2.get("name"), f"service_account_name_{sa_client_ids[2].split('-')[0]}")
        self.assertEqual(sa2.get("description"), f"Service Account description {sa_client_ids[2].split('-')[0]}")
        self.assertEqual(sa2.get("owner"), "ecasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), "service_account-" + sa_client_ids[2])

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_filter_by_description(self, mock_request):
        """Test that we can filter service accounts by description"""
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
                "owner": "ecasey",
                "username": sa_username,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]

        url = f"{reverse('v1_management:principals')}?type=service-account&description=Service"
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
        self.assertEqual(sa.get("owner"), "ecasey")
        self.assertEqual(sa.get("type"), "service-account")
        self.assertEqual(sa.get("username"), sa_username)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_filter_by_owner_name_description(self, mock_request):
        """Test that we can filter service accounts by all filter options"""
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
                "owner": "ecasey",
                "username": sa_username,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]

        url = f"{reverse('v1_management:principals')}?type=service-account&owner=ecasey&name=service_account_name&description=Service"
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
        self.assertEqual(sa.get("owner"), "ecasey")
        self.assertEqual(sa.get("type"), "service-account")
        self.assertEqual(sa.get("username"), sa_username)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_sort_by_time_created_desc(self, mock_request):
        """Test that we can sort service accounts by time_created descending"""
        # Create SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        sa_username1 = "service_account-" + sa_client_ids[0]
        sa_username2 = "service_account-" + sa_client_ids[1]

        Principal.objects.create(
            username=sa_username1,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[0],
        )

        Principal.objects.create(
            username=sa_username2,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[1],
        )

        mocked_values = []

        mocked_values.append(
            {
                "clientId": sa_client_ids[0],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username1,
                "time_created": 1706784741,
                "type": "service-account",
            }
        )

        mocked_values.append(
            {
                "clientId": sa_client_ids[1],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username2,
                "time_created": 1306784741,
                "type": "service-account",
            }
        )
        mock_request.return_value = mocked_values
        url = f"{reverse('v1_management:principals')}?type=service-account&order_by=-time_created"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        sa1 = response.data.get("data")[0]
        sa2 = response.data.get("data")[1]

        self.assertCountEqual(
            list(sa1.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa1.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa1.get("name"), "service_account_name")
        self.assertEqual(sa1.get("description"), "Service Account description")
        self.assertEqual(sa1.get("owner"), "ecasey")
        self.assertEqual(sa1.get("type"), "service-account")
        self.assertEqual(sa1.get("username"), sa_username1)
        self.assertEqual(sa1.get("time_created"), 1706784741)

        self.assertCountEqual(
            list(sa2.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa2.get("name"), "service_account_name")
        self.assertEqual(sa2.get("description"), "Service Account description")
        self.assertEqual(sa2.get("owner"), "ecasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), sa_username2)
        self.assertEqual(sa2.get("time_created"), 1306784741)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_sort_by_time_created_asc(self, mock_request):
        """Test that we can sort service accounts by time_created ascending"""
        # Create SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        sa_username1 = "service_account-" + sa_client_ids[0]
        sa_username2 = "service_account-" + sa_client_ids[1]

        Principal.objects.create(
            username=sa_username1,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[0],
        )

        Principal.objects.create(
            username=sa_username2,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[1],
        )

        mocked_values = []

        mocked_values.append(
            {
                "clientId": sa_client_ids[0],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username1,
                "time_created": 1706784741,
                "type": "service-account",
            }
        )

        mocked_values.append(
            {
                "clientId": sa_client_ids[1],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username2,
                "time_created": 1306784741,
                "type": "service-account",
            }
        )
        mock_request.return_value = mocked_values
        url = f"{reverse('v1_management:principals')}?type=service-account&order_by=time_created"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        sa1 = response.data.get("data")[1]
        sa2 = response.data.get("data")[0]

        self.assertCountEqual(
            list(sa2.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa2.get("name"), "service_account_name")
        self.assertEqual(sa2.get("description"), "Service Account description")
        self.assertEqual(sa2.get("owner"), "ecasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), sa_username2)
        self.assertEqual(sa2.get("time_created"), 1306784741)

        self.assertCountEqual(
            list(sa1.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa1.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa1.get("name"), "service_account_name")
        self.assertEqual(sa1.get("description"), "Service Account description")
        self.assertEqual(sa1.get("owner"), "ecasey")
        self.assertEqual(sa1.get("type"), "service-account")
        self.assertEqual(sa1.get("username"), sa_username1)
        self.assertEqual(sa1.get("time_created"), 1706784741)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_sort_by_owner_asc(self, mock_request):
        """Test that we can sort service accounts by owner ascending"""
        # Create SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        sa_username1 = "service_account-" + sa_client_ids[0]
        sa_username2 = "service_account-" + sa_client_ids[1]

        Principal.objects.create(
            username=sa_username1,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[0],
        )

        Principal.objects.create(
            username=sa_username2,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[1],
        )

        mocked_values = []

        mocked_values.append(
            {
                "clientId": sa_client_ids[0],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "acasey",
                "username": sa_username1,
                "time_created": 1706784741,
                "type": "service-account",
            }
        )

        mocked_values.append(
            {
                "clientId": sa_client_ids[1],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username2,
                "time_created": 1306784741,
                "type": "service-account",
            }
        )
        mock_request.return_value = mocked_values
        url = f"{reverse('v1_management:principals')}?type=service-account&order_by=owner"
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        sa1 = response.data.get("data")[0]
        sa2 = response.data.get("data")[1]

        self.assertCountEqual(
            list(sa1.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa1.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa1.get("name"), "service_account_name")
        self.assertEqual(sa1.get("description"), "Service Account description")
        self.assertEqual(sa1.get("owner"), "acasey")
        self.assertEqual(sa1.get("type"), "service-account")
        self.assertEqual(sa1.get("username"), sa_username1)
        self.assertEqual(sa1.get("time_created"), 1706784741)

        self.assertCountEqual(
            list(sa2.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa2.get("name"), "service_account_name")
        self.assertEqual(sa2.get("description"), "Service Account description")
        self.assertEqual(sa2.get("owner"), "ecasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), sa_username2)
        self.assertEqual(sa2.get("time_created"), 1306784741)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_sort_by_owner_desc(self, mock_request):
        """Test that we can sort service accounts by owner descending"""
        # Create SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        sa_username1 = "service_account-" + sa_client_ids[0]
        sa_username2 = "service_account-" + sa_client_ids[1]

        Principal.objects.create(
            username=sa_username1,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[0],
        )

        Principal.objects.create(
            username=sa_username2,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[1],
        )

        mocked_values = []

        mocked_values.append(
            {
                "clientId": sa_client_ids[0],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username1,
                "time_created": 1706784741,
                "type": "service-account",
            }
        )

        mocked_values.append(
            {
                "clientId": sa_client_ids[1],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "acasey",
                "username": sa_username2,
                "time_created": 1306784741,
                "type": "service-account",
            }
        )
        mock_request.return_value = mocked_values
        url = f"{reverse('v1_management:principals')}?type=service-account&order_by=-owner"
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        sa1 = response.data.get("data")[0]
        sa2 = response.data.get("data")[1]

        self.assertCountEqual(
            list(sa1.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa1.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa1.get("name"), "service_account_name")
        self.assertEqual(sa1.get("description"), "Service Account description")
        self.assertEqual(sa1.get("owner"), "ecasey")
        self.assertEqual(sa1.get("type"), "service-account")
        self.assertEqual(sa1.get("username"), sa_username1)
        self.assertEqual(sa1.get("time_created"), 1706784741)

        self.assertCountEqual(
            list(sa2.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa2.get("name"), "service_account_name")
        self.assertEqual(sa2.get("description"), "Service Account description")
        self.assertEqual(sa2.get("owner"), "acasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), sa_username2)
        self.assertEqual(sa2.get("time_created"), 1306784741)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_sort_by_name_asc(self, mock_request):
        """Test that we can sort service accounts by name ascending"""
        # Create SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        sa_username1 = "service_account-" + sa_client_ids[0]
        sa_username2 = "service_account-" + sa_client_ids[1]

        Principal.objects.create(
            username=sa_username1,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[0],
        )

        Principal.objects.create(
            username=sa_username2,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[1],
        )

        mocked_values = []

        mocked_values.append(
            {
                "clientId": sa_client_ids[0],
                "name": "a_service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username1,
                "time_created": 1706784741,
                "type": "service-account",
            }
        )

        mocked_values.append(
            {
                "clientId": sa_client_ids[1],
                "name": "z_service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username2,
                "time_created": 1306784741,
                "type": "service-account",
            }
        )
        mock_request.return_value = mocked_values
        url = f"{reverse('v1_management:principals')}?type=service-account&order_by=name"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        sa1 = response.data.get("data")[0]
        sa2 = response.data.get("data")[1]

        self.assertCountEqual(
            list(sa1.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa1.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa1.get("name"), "a_service_account_name")
        self.assertEqual(sa1.get("description"), "Service Account description")
        self.assertEqual(sa1.get("owner"), "ecasey")
        self.assertEqual(sa1.get("type"), "service-account")
        self.assertEqual(sa1.get("username"), sa_username1)
        self.assertEqual(sa1.get("time_created"), 1706784741)

        self.assertCountEqual(
            list(sa2.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa2.get("name"), "z_service_account_name")
        self.assertEqual(sa2.get("description"), "Service Account description")
        self.assertEqual(sa2.get("owner"), "ecasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), sa_username2)
        self.assertEqual(sa2.get("time_created"), 1306784741)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_sort_by_name_desc(self, mock_request):
        """Test that we can sort service accounts by name descending"""
        # Create SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        sa_username1 = "service_account-" + sa_client_ids[0]
        sa_username2 = "service_account-" + sa_client_ids[1]

        Principal.objects.create(
            username=sa_username1,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[0],
        )

        Principal.objects.create(
            username=sa_username2,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[1],
        )

        mocked_values = []

        mocked_values.append(
            {
                "clientId": sa_client_ids[0],
                "name": "a_service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username1,
                "time_created": 1706784741,
                "type": "service-account",
            }
        )

        mocked_values.append(
            {
                "clientId": sa_client_ids[1],
                "name": "z_service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username2,
                "time_created": 1306784741,
                "type": "service-account",
            }
        )
        mock_request.return_value = mocked_values
        url = f"{reverse('v1_management:principals')}?type=service-account&order_by=-name"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        sa1 = response.data.get("data")[0]
        sa2 = response.data.get("data")[1]

        self.assertCountEqual(
            list(sa1.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa1.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa1.get("name"), "z_service_account_name")
        self.assertEqual(sa1.get("description"), "Service Account description")
        self.assertEqual(sa1.get("owner"), "ecasey")
        self.assertEqual(sa1.get("type"), "service-account")
        self.assertEqual(sa1.get("username"), sa_username2)
        self.assertEqual(sa1.get("time_created"), 1306784741)

        self.assertCountEqual(
            list(sa2.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa2.get("name"), "a_service_account_name")
        self.assertEqual(sa2.get("description"), "Service Account description")
        self.assertEqual(sa2.get("owner"), "ecasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), sa_username1)
        self.assertEqual(sa2.get("time_created"), 1706784741)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_sort_by_description_asc(self, mock_request):
        """Test that we can sort service accounts by description ascending"""
        # Create SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        sa_username1 = "service_account-" + sa_client_ids[0]
        sa_username2 = "service_account-" + sa_client_ids[1]

        Principal.objects.create(
            username=sa_username1,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[0],
        )

        Principal.objects.create(
            username=sa_username2,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[1],
        )

        mocked_values = []

        mocked_values.append(
            {
                "clientId": sa_client_ids[0],
                "name": "a_service_account_name",
                "description": "A Service Account description",
                "owner": "ecasey",
                "username": sa_username1,
                "time_created": 1706784741,
                "type": "service-account",
            }
        )

        mocked_values.append(
            {
                "clientId": sa_client_ids[1],
                "name": "z_service_account_name",
                "description": "Z Service Account description",
                "owner": "ecasey",
                "username": sa_username2,
                "time_created": 1306784741,
                "type": "service-account",
            }
        )
        mock_request.return_value = mocked_values
        url = f"{reverse('v1_management:principals')}?type=service-account&order_by=description"
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        sa1 = response.data.get("data")[0]
        sa2 = response.data.get("data")[1]

        self.assertCountEqual(
            list(sa1.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa1.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa1.get("name"), "a_service_account_name")
        self.assertEqual(sa1.get("description"), "A Service Account description")
        self.assertEqual(sa1.get("owner"), "ecasey")
        self.assertEqual(sa1.get("type"), "service-account")
        self.assertEqual(sa1.get("username"), sa_username1)
        self.assertEqual(sa1.get("time_created"), 1706784741)

        self.assertCountEqual(
            list(sa2.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa2.get("name"), "z_service_account_name")
        self.assertEqual(sa2.get("description"), "Z Service Account description")
        self.assertEqual(sa2.get("owner"), "ecasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), sa_username2)
        self.assertEqual(sa2.get("time_created"), 1306784741)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_sort_by_name_desc(self, mock_request):
        """Test that we can sort service accounts by name descending"""
        # Create SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        sa_username1 = "service_account-" + sa_client_ids[0]
        sa_username2 = "service_account-" + sa_client_ids[1]

        Principal.objects.create(
            username=sa_username1,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[0],
        )

        Principal.objects.create(
            username=sa_username2,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[1],
        )

        mocked_values = []

        mocked_values.append(
            {
                "clientId": sa_client_ids[0],
                "name": "a_service_account_name",
                "description": "A Service Account description",
                "owner": "ecasey",
                "username": sa_username1,
                "time_created": 1706784741,
                "type": "service-account",
            }
        )

        mocked_values.append(
            {
                "clientId": sa_client_ids[1],
                "name": "z_service_account_name",
                "description": "Z Service Account description",
                "owner": "ecasey",
                "username": sa_username2,
                "time_created": 1306784741,
                "type": "service-account",
            }
        )
        mock_request.return_value = mocked_values
        url = f"{reverse('v1_management:principals')}?type=service-account&order_by=-name"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        sa1 = response.data.get("data")[0]
        sa2 = response.data.get("data")[1]

        self.assertCountEqual(
            list(sa1.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa1.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa1.get("name"), "z_service_account_name")
        self.assertEqual(sa1.get("description"), "Z Service Account description")
        self.assertEqual(sa1.get("owner"), "ecasey")
        self.assertEqual(sa1.get("type"), "service-account")
        self.assertEqual(sa1.get("username"), sa_username2)
        self.assertEqual(sa1.get("time_created"), 1306784741)

        self.assertCountEqual(
            list(sa2.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa2.get("name"), "a_service_account_name")
        self.assertEqual(sa2.get("description"), "A Service Account description")
        self.assertEqual(sa2.get("owner"), "ecasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), sa_username1)
        self.assertEqual(sa2.get("time_created"), 1706784741)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_sort_by_clientid_asc(self, mock_request):
        """Test that we can sort service accounts by clientId ascending"""
        # Create SA in the database
        sa_client_ids = ["b6636c60-a31d-013c-b93d-6aa2427b506c", "69a116a0-a3d4-013c-b940-6aa2427b506c"]
        sa_username1 = "service_account-" + sa_client_ids[0]
        sa_username2 = "service_account-" + sa_client_ids[1]

        Principal.objects.create(
            username=sa_username1,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[0],
        )

        Principal.objects.create(
            username=sa_username2,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[1],
        )

        mocked_values = []

        mocked_values.append(
            {
                "clientId": sa_client_ids[0],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username1,
                "time_created": 1706784741,
                "type": "service-account",
            }
        )

        mocked_values.append(
            {
                "clientId": sa_client_ids[1],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username2,
                "time_created": 1306784741,
                "type": "service-account",
            }
        )
        mock_request.return_value = mocked_values
        url = f"{reverse('v1_management:principals')}?type=service-account&order_by=clientId"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        sa1 = response.data.get("data")[0]
        sa2 = response.data.get("data")[1]

        self.assertCountEqual(
            list(sa1.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa1.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa1.get("name"), "service_account_name")
        self.assertEqual(sa1.get("description"), "Service Account description")
        self.assertEqual(sa1.get("owner"), "ecasey")
        self.assertEqual(sa1.get("type"), "service-account")
        self.assertEqual(sa1.get("username"), sa_username2)
        self.assertEqual(sa1.get("time_created"), 1306784741)

        self.assertCountEqual(
            list(sa2.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa2.get("name"), "service_account_name")
        self.assertEqual(sa2.get("description"), "Service Account description")
        self.assertEqual(sa2.get("owner"), "ecasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), sa_username1)
        self.assertEqual(sa2.get("time_created"), 1706784741)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_principal_service_account_sort_by_clientid_desc(self, mock_request):
        """Test that we can sort service accounts by clientId descending"""
        # Create SA in the database
        sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        sa_username1 = "service_account-" + sa_client_ids[0]
        sa_username2 = "service_account-" + sa_client_ids[1]

        Principal.objects.create(
            username=sa_username1,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[0],
        )

        Principal.objects.create(
            username=sa_username2,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_client_ids[1],
        )

        mocked_values = []

        mocked_values.append(
            {
                "clientId": sa_client_ids[0],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username1,
                "time_created": 1706784741,
                "type": "service-account",
            }
        )

        mocked_values.append(
            {
                "clientId": sa_client_ids[1],
                "name": "service_account_name",
                "description": "Service Account description",
                "owner": "ecasey",
                "username": sa_username2,
                "time_created": 1306784741,
                "type": "service-account",
            }
        )
        mock_request.return_value = mocked_values
        url = f"{reverse('v1_management:principals')}?type=service-account&order_by=-clientId"

        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        sa1 = response.data.get("data")[0]
        sa2 = response.data.get("data")[1]

        self.assertCountEqual(
            list(sa1.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa1.get("clientId"), sa_client_ids[0])
        self.assertEqual(sa1.get("name"), "service_account_name")
        self.assertEqual(sa1.get("description"), "Service Account description")
        self.assertEqual(sa1.get("owner"), "ecasey")
        self.assertEqual(sa1.get("type"), "service-account")
        self.assertEqual(sa1.get("username"), sa_username1)
        self.assertEqual(sa1.get("time_created"), 1706784741)

        self.assertCountEqual(
            list(sa2.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )
        self.assertEqual(sa2.get("clientId"), sa_client_ids[1])
        self.assertEqual(sa2.get("name"), "service_account_name")
        self.assertEqual(sa2.get("description"), "Service Account description")
        self.assertEqual(sa2.get("owner"), "ecasey")
        self.assertEqual(sa2.get("type"), "service-account")
        self.assertEqual(sa2.get("username"), sa_username2)
        self.assertEqual(sa2.get("time_created"), 1306784741)

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
    @patch("management.principal.it_service.ITService.request_service_accounts", return_value=None)
    def test_read_principal_service_account_invalid_limit_offset(self, mock_request):
        """Test that 400 is returned for negative limit and offset."""
        test_values = [(-1, 1), (2, -2)]
        expected_message = "Values for limit and offset must be positive numbers."

        for limit, offset in test_values:
            url = f"{reverse('v1_management:principals')}?type=service-account&limit={limit}&offset={offset}"
            client = APIClient()
            response = client.get(url, **self.headers)
            err = response.json()["errors"][0]
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(err["detail"], expected_message)

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
