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
from django.conf import settings
from django.test.utils import override_settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APIClient

from api.models import Tenant, User
from management.models import *
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
        url = reverse("principals")
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

        url = reverse("principals")
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            account=self.customer["account_id"],
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "admin_only": "false",
                "username_only": "false",
                "principal_type": None,
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

        url = reverse("principals")
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            account=self.customer_data["account_id"],
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "admin_only": "false",
                "username_only": "false",
                "principal_type": None,
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
        url = f'{reverse("principals")}?username_only=true'
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
        url = f'{reverse("principals")}?username_only=false'
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
        url = f'{reverse("principals")}?username_only=foo'
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
        url = reverse("principals")
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            account=self.customer_data["account_id"],
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "admin_only": "false",
                "username_only": "false",
                "principal_type": None,
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

        url = f'{reverse("principals")}?usernames=test_user,cross_account_user&offset=30'
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            ["test_user", "cross_account_user"],
            account=ANY,
            org_id=ANY,
            limit=10,
            offset=30,
            options={
                "limit": 10,
                "offset": 30,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": None,
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
        url = f'{reverse("principals")}?usernames=test_user75&offset=30'
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            ["test_user75"],
            account=ANY,
            org_id=ANY,
            limit=10,
            offset=30,
            options={
                "limit": 10,
                "offset": 30,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": None,
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
        url = f'{reverse("principals")}?usernames=test_us,no_op&offset=30&match_criteria=partial'
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            account=self.customer_data["account_id"],
            input={"principalStartsWith": "test_us"},
            limit=10,
            offset=30,
            options={
                "limit": 10,
                "offset": 30,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": None,
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
        url = f'{reverse("principals")}?usernames=test_us&email=test&offset=30&match_criteria=partial'
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            account=self.customer_data["account_id"],
            input={"principalStartsWith": "test_us", "emailStartsWith": "test"},
            limit=10,
            offset=30,
            options={
                "limit": 10,
                "offset": 30,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": None,
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
        url = f'{reverse("principals")}?limit=foo'
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_bad_query_param_of_sort_order(self):
        """Test handling of bad query params."""
        url = f'{reverse("principals")}?sort_order=det'
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_principals",
        return_value={"status_code": status.HTTP_500_INTERNAL_SERVER_ERROR, "errors": [{"detail": "error"}]},
    )
    def test_read_principal_list_fail(self, mock_request):
        """Test that we can handle a failure with listing principals."""
        url = reverse("principals")
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
        url = f'{reverse("principals")}?usernames=test_user&offset=30&sort_order=desc'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            ["test_user"],
            account=ANY,
            org_id=ANY,
            limit=10,
            offset=30,
            options={
                "limit": 10,
                "offset": 30,
                "sort_order": "desc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": None,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        if settings.AUTHENTICATE_WITH_ORG_ID:
            resp = proxy._process_data(response.data.get("data"), org_id="4321", org_id_filter=True, return_id=True)
        else:
            resp = proxy._process_data(response.data.get("data"), account="1234", account_filter=True, return_id=True)
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
        url = f'{reverse("principals")}?usernames=test_user&offset=30'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        if settings.AUTHENTICATE_WITH_ORG_ID:
            resp = proxy._process_data(response.data.get("data"), org_id="4321", org_id_filter=True)
        else:
            resp = proxy._process_data(response.data.get("data"), account="1234", account_filter=True)
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
        url = f'{reverse("principals")}?usernames=test_user&offset=30'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        if settings.AUTHENTICATE_WITH_ORG_ID:
            resp = proxy._process_data(response.data.get("data"), org_id="4321", org_id_filter=False)
        else:
            resp = proxy._process_data(response.data.get("data"), account="1234", account_filter=False)
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
        url = f'{reverse("principals")}?email=test_user@example.com'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        if settings.AUTHENTICATE_WITH_ORG_ID:
            resp = proxy._process_data(response.data.get("data"), org_id="54322", org_id_filter=False)
        else:
            resp = proxy._process_data(response.data.get("data"), account="54321", account_filter=False)
        self.assertEqual(len(resp), 1)

        mock_request.assert_called_once_with(
            account=self.customer_data["account_id"],
            input={"primaryEmail": "test_user@example.com"},
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": None,
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
        url = f'{reverse("principals")}?status=disabled'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), "1")
        mock_request.assert_called_once_with(
            account=self.customer_data["account_id"],
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "disabled",
                "admin_only": "false",
                "username_only": "false",
                "principal_type": None,
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
        url = f'{reverse("principals")}'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), "1")
        mock_request.assert_called_once_with(
            account=self.customer_data["account_id"],
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "admin_only": "false",
                "status": "enabled",
                "username_only": "false",
                "principal_type": None,
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
        url = f'{reverse("principals")}?admin_only=true'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), "1")
        mock_request.assert_called_once_with(
            account=self.customer_data["account_id"],
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "admin_only": "true",
                "username_only": "false",
                "principal_type": None,
            },
            org_id=self.customer_data["org_id"],
        )

    def test_read_users_with_invalid_status_value(self):
        """Test that reading user with invalid status value returns 400"""
        url = f'{reverse("principals")}?status=invalid'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_users_with_invalid_admin_only_value(self):
        """Test that reading user with invalid status value returns 400"""
        url = f'{reverse("principals")}?admin_only=invalid'
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
        url = f'{reverse("principals")}?email=test_use&match_criteria=partial'
        client = APIClient()
        proxy = PrincipalProxy()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        if settings.AUTHENTICATE_WITH_ORG_ID:
            resp = proxy._process_data(response.data.get("data"), org_id="54322", org_id_filter=False)
        else:
            resp = proxy._process_data(response.data.get("data"), account="54321", account_filter=False)
        self.assertEqual(len(resp), 1)

        mock_request.assert_called_once_with(
            account=self.customer_data["account_id"],
            input={"emailStartsWith": "test_use"},
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "username_only": "false",
                "principal_type": None,
            },
            org_id=self.customer_data["org_id"],
        )

        self.assertEqual(resp[0]["username"], "test_user")

    def test_read_principal_invalid_type_query_params(self):
        """Test that when an invalid "principal type" query parameter is specified, a bad request response is returned"""
        url = reverse("principals")
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

        url = reverse("principals")
        client = APIClient()
        response = client.get(url, **self.headers)

        mock_request.assert_called_once_with(
            account=self.customer_data["account_id"],
            limit=10,
            offset=0,
            options={
                "limit": 10,
                "offset": 0,
                "sort_order": "asc",
                "status": "enabled",
                "admin_only": "false",
                "username_only": "false",
                "principal_type": None,
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

    def test_fetch_service_accounts(self):
        """Test fetching service accounts while not providing a token

        Test that when the user request the service accounts without an authorization token, an unauthorized response
        is returned
        """

        url = f'{reverse("principals")}?type=service-account'
        client = APIClient()
        response: Response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
