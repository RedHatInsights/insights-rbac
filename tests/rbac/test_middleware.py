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
"""Test the project middleware."""
import collections
import os
from unittest.mock import Mock
from django.conf import settings

from django.db import connection
from django.test import TestCase
from django.urls import reverse
from api.common import RH_IDENTITY_HEADER

from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant, User
from api.serializers import create_tenant_name
from tests.identity_request import IdentityRequest
from rbac.middleware import HttpResponseUnauthorizedRequest, IdentityHeaderMiddleware, TENANTS
from management.models import Access, Group, Permission, Principal, Policy, ResourceDefinition, Role


class EnvironmentVarGuard(collections.abc.MutableMapping):

    """Class to help protect the environment variable properly.  Can be used as
    a context manager."""

    def __init__(self):
        self._environ = os.environ
        self._changed = {}

    def __getitem__(self, envvar):
        return self._environ[envvar]

    def __setitem__(self, envvar, value):
        # Remember the initial value on the first access
        if envvar not in self._changed:
            self._changed[envvar] = self._environ.get(envvar)
        self._environ[envvar] = value

    def __delitem__(self, envvar):
        # Remember the initial value on the first access
        if envvar not in self._changed:
            self._changed[envvar] = self._environ.get(envvar)
        if envvar in self._environ:
            del self._environ[envvar]

    def keys(self):
        return self._environ.keys()

    def __iter__(self):
        return iter(self._environ)

    def __len__(self):
        return len(self._environ)

    def set(self, envvar, value):
        self[envvar] = value

    def unset(self, envvar):
        del self[envvar]

    def __enter__(self):
        return self

    def __exit__(self, *ignore_exc):
        for (k, v) in self._changed.items():
            if v is None:
                if k in self._environ:
                    del self._environ[k]
            else:
                self._environ[k] = v
        os.environ = self._environ


class RbacTenantMiddlewareTest(IdentityRequest):
    """Tests against the rbac tenant middleware."""

    def setUp(self):
        """Set up middleware tests."""
        super().setUp()
        self.user_data = self._create_user_data()
        self.customer = self._create_customer_data()
        self.tenant_name = create_tenant_name(self.customer["account_id"])
        self.request_context = self._create_request_context(self.customer, self.user_data, create_customer=False)
        self.request = self.request_context["request"]
        self.request.path = "/api/v1/providers/"
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        user.org_id = self.customer_data["org_id"]
        self.request.user = user

    def test_get_tenant_with_user(self):
        """Test that the customer tenant is returned."""
        mock_request = self.request
        middleware = IdentityHeaderMiddleware()
        result = middleware.get_tenant(Tenant, "localhost", mock_request)
        if settings.AUTHENTICATE_WITH_ORG_ID:
            self.assertEqual(result.org_id, mock_request.user.org_id)
        else:
            self.assertEqual(result.tenant_name, create_tenant_name(mock_request.user.account))

    def test_get_tenant_with_no_user(self):
        """Test that a 401 is returned."""
        request_context = self._create_request_context(self.customer, None, create_customer=False)
        mock_request = request_context["request"]
        mock_request.path = "/api/v1/providers/"
        middleware = IdentityHeaderMiddleware()
        result = middleware.process_request(mock_request)
        self.assertIsInstance(result, HttpResponseUnauthorizedRequest)

    def test_get_tenant_with_org_id(self):
        """Test that the customer tenant is returned containing an org_id."""
        user_data = self._create_user_data()
        customer = self._create_customer_data()
        customer["org_id"] = "45321"
        request_context = self._create_request_context(customer, user_data, create_customer=True)
        request = request_context["request"]
        request.path = "/api/v1/providers/"
        request.META["QUERY_STRING"] = ""
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer["account_id"]
        user.org_id = "45321"
        request.user = user

        middleware = IdentityHeaderMiddleware()
        middleware.process_request(request)
        self.assertEqual(Tenant.objects.filter(org_id=user.org_id).count(), 1)


class IdentityHeaderMiddlewareTest(IdentityRequest):
    """Tests against the rbac tenant middleware."""

    def setUp(self):
        """Set up middleware tests."""
        super().setUp()
        self.user_data = self._create_user_data()
        self.customer = self._create_customer_data()
        self.tenant_name = create_tenant_name(self.customer["account_id"])
        self.request_context = self._create_request_context(self.customer, self.user_data, create_customer=False)
        self.request = self.request_context["request"]
        self.request.path = "/api/v1/providers/"
        self.request.META["QUERY_STRING"] = ""

    def test_process_status(self):
        """Test that the request gets a user."""
        mock_request = Mock(path="/api/v1/status/")
        middleware = IdentityHeaderMiddleware()
        middleware.process_request(mock_request)
        self.assertTrue(hasattr(mock_request, "user"))

    def test_process_cross_account_request(self):
        """Test that the process request functions correctly for cross account request."""
        middleware = IdentityHeaderMiddleware()
        # User without redhat email will fail.
        request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, cross_account=True, is_internal=True
        )
        mock_request = request_context["request"]
        mock_request.path = "/api/v1/providers/"

        response = middleware.process_request(mock_request)
        self.assertIsInstance(response, HttpResponseUnauthorizedRequest)

        # User with is_internal equal to False will fail.
        self.user_data["email"] = "test@redhat.com"
        request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, cross_account=True
        )
        mock_request = request_context["request"]
        mock_request.path = "/api/v1/providers/"

        response = middleware.process_request(mock_request)
        self.assertIsInstance(response, HttpResponseUnauthorizedRequest)

        # Success pass if user is internal and with redhat email
        self.user_data["email"] = "test@redhat.com"
        request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, cross_account=True, is_internal=True
        )
        mock_request = request_context["request"]
        mock_request.path = "/api/v1/providers/"

        response = middleware.process_request(mock_request)
        self.assertEqual(response, None)

    def test_process_response(self):
        """Test that the process response functions correctly."""
        mock_request = Mock(path="/api/v1/status/")
        mock_response = Mock(status_code=200)
        middleware = IdentityHeaderMiddleware()
        response = middleware.process_response(mock_request, mock_response)
        self.assertEqual(response, mock_response)

    def test_process_not_status(self):
        """Test that the customer, tenant and user are created."""
        mock_request = self.request
        middleware = IdentityHeaderMiddleware()
        middleware.process_request(mock_request)
        self.assertTrue(hasattr(mock_request, "user"))
        self.assertEqual(mock_request.user.username, self.user_data["username"])
        tenant = Tenant.objects.get(tenant_name=self.tenant_name)
        self.assertIsNotNone(tenant)

    def test_process_no_customer(self):
        """Test that the customer, tenant and user are not created."""
        customer = self._create_customer_data()
        account_id = customer["account_id"]
        del customer["account_id"]
        request_context = self._create_request_context(customer, self.user_data, create_customer=False)
        mock_request = request_context["request"]
        mock_request.path = "/api/v1/providers/"
        middleware = IdentityHeaderMiddleware()
        middleware.process_request(mock_request)
        self.assertTrue(hasattr(mock_request, "user"))
        with self.assertRaises(Tenant.DoesNotExist):
            Tenant.objects.get(tenant_name=self.tenant_name)

    def test_race_condition_customer(self):
        """Test case where another request may create the tenant in a race condition."""
        mock_request = self.request
        mock_request.user = User()
        mock_request.user.username = self.user_data["username"]
        mock_request.user.account = self.customer_data["account_id"]
        orig_cust = IdentityHeaderMiddleware().get_tenant(mock_request)
        dup_cust = IdentityHeaderMiddleware().get_tenant(mock_request)
        self.assertEqual(orig_cust, dup_cust)

    def test_tenant_process_without_org_id(self):
        """Test that an existing tenant doesn't create a new one when providing an org_id."""
        tenant = Tenant.objects.create(tenant_name="test_user")

        user_data = self._create_user_data()
        customer = self._create_customer_data()
        request_context = self._create_request_context(customer, user_data, create_customer=False)
        request = request_context["request"]
        request.path = "/api/v1/providers/"
        request.META["QUERY_STRING"] = ""
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer["account_id"]
        user.org_id = "45321"
        request.user = user

        middleware = IdentityHeaderMiddleware()
        middleware.process_request(request)
        self.assertEqual(Tenant.objects.filter(tenant_name="test_user").count(), 1)
        self.assertEqual(Tenant.objects.filter(tenant_name="test_user").first().org_id, None)


class ServiceToService(IdentityRequest):
    """Tests requests without an identity header."""

    def setUp(self):
        """Setup tests."""
        self.env = EnvironmentVarGuard()
        self.env.set("SERVICE_PSKS", '{"catalog": {"secret": "abc123"}}')
        self.account_id = "1234"
        self.org_id = "4321"
        self.service_headers = {
            "HTTP_X_RH_RBAC_PSK": "abc123",
            "HTTP_X_RH_RBAC_ACCOUNT": self.account_id,
            "HTTP_X_RH_RBAC_CLIENT_ID": "catalog",
            "HTTP_X_RH_RBAC_ORG_ID": self.org_id,
        }

    def test_no_identity_or_service_headers_returns_401(self):
        url = reverse("group-list")
        client = APIClient()
        self.service_headers = {}
        response = client.get(url, {})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_identity_and_invalid_psk_returns_401(self):
        t = Tenant.objects.create(tenant_name=f"acct{self.account_id}", account_id=self.account_id, org_id=self.org_id)
        t.ready = True
        t.save()

        url = reverse("group-list")
        client = APIClient()
        self.service_headers["HTTP_X_RH_RBAC_PSK"] = "xyz"
        response = client.get(url, **self.service_headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_identity_and_invalid_account_returns_404(self):
        t = Tenant.objects.create(tenant_name=f"acct{self.account_id}", account_id=self.account_id, org_id=self.org_id)
        t.ready = True
        t.save()
        url = reverse("group-list")
        client = APIClient()
        if settings.AUTHENTICATE_WITH_ORG_ID:
            self.service_headers["HTTP_X_RH_RBAC_ORG_ID"] = "1212"
        else:
            self.service_headers["HTTP_X_RH_RBAC_ACCOUNT"] = "1212"
        response = client.get(url, **self.service_headers)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_no_identity_and_invalid_client_id_returns_401(self):
        t = Tenant.objects.create(tenant_name=f"acct{self.account_id}", account_id=self.account_id, org_id=self.org_id)
        t.ready = True
        t.save()
        url = reverse("group-list")
        client = APIClient()
        self.service_headers["HTTP_X_RH_RBAC_CLIENT_ID"] = "bad-service"
        response = client.get(url, **self.service_headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_identity_and_valid_psk_client_id_and_account_returns_200(self):
        t = Tenant.objects.create(tenant_name=f"acct{self.account_id}", account_id=self.account_id, org_id=self.org_id)
        t.ready = True
        t.save()
        url = reverse("group-list")
        client = APIClient()
        response = client.get(url, **self.service_headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)


class InternalIdentityHeaderMiddleware(IdentityRequest):
    """Tests against the internal api middleware"""

    def setUp(self):
        """Set up middleware tests."""
        super().setUp()
        self.user_data = self._create_user_data()
        self.customer = self._create_customer_data()
        self.internal_request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, is_internal=True
        )

    def test_internal_user_can_access_private_api(self):
        request = self.internal_request_context["request"]
        client = APIClient()
        response = client.get("/_private/api/tenant/unmodified/", **request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_external_user_cannot_access_private_api(self):
        request = self.request_context["request"]
        client = APIClient()
        response = client.get("/_private/api/tenant/unmodified/", **request.META)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class AccessHandlingTest(TestCase):
    """Tests against getting user access in the IdentityHeaderMiddleware."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.tenant = Tenant.objects.get(tenant_name="test")
        except:
            cls.tenant = Tenant(tenant_name="test", account_id="11111", org_id="22222", ready=True)
            cls.tenant.save()

    @classmethod
    def tearDownClass(cls):
        cls.tenant.delete()

    def test_no_principal_found(self):
        expected = {
            "group": {"read": [], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
            "principal": {"read": [], "write": []},
            "permission": {"read": [], "write": []},
        }
        access = IdentityHeaderMiddleware._get_access_for_user("test_user", self.tenant)
        self.assertEqual(expected, access)

    def test_principal_no_access(self):
        """Test access for existing principal with no access definitions."""
        Principal.objects.create(username="test_user", tenant=self.tenant)
        expected = {
            "group": {"read": [], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
            "principal": {"read": [], "write": []},
            "permission": {"read": [], "write": []},
        }
        access = IdentityHeaderMiddleware._get_access_for_user("test_user", self.tenant)
        self.assertEqual(expected, access)

    def test_principal_with_access_no_res_defs(self):
        """Test a user with defined access without any resource definitions."""
        principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        group = Group.objects.create(name="group1", tenant=self.tenant)
        group.principals.add(principal)
        group.save()
        role = Role.objects.create(name="role1", tenant=self.tenant)
        perm = Permission.objects.create(permission="rbac:group:write", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        policy = Policy.objects.create(name="policy1", group=group, tenant=self.tenant)
        policy.roles.add(role)
        policy.save()
        access = IdentityHeaderMiddleware._get_access_for_user("test_user", self.tenant)
        expected = {
            "group": {"read": ["*"], "write": ["*"]},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
            "principal": {"read": [], "write": []},
            "permission": {"read": [], "write": []},
        }
        self.assertEqual(expected, access)

    def test_principal_with_access_with_res_defs(self):
        """Test a user with defined access with any resource definitions."""
        principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        group = Group.objects.create(name="group1", tenant=self.tenant)
        group.principals.add(principal)
        group.save()
        role = Role.objects.create(name="role1", tenant=self.tenant)
        perm = Permission.objects.create(permission="rbac:group:foo:bar", tenant=self.tenant)
        Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        perm2 = Permission.objects.create(permission="rbac:group:write", tenant=self.tenant)
        access = Access.objects.create(permission=perm2, role=role, tenant=self.tenant)
        ResourceDefinition.objects.create(
            access=access, attributeFilter={"key": "group", "operation": "equal", "value": "1"}, tenant=self.tenant
        )
        ResourceDefinition.objects.create(
            access=access, attributeFilter={"key": "group", "operation": "in", "value": "3,5"}, tenant=self.tenant
        )
        ResourceDefinition.objects.create(
            access=access, attributeFilter={"key": "group", "operation": "equal", "value": "*"}, tenant=self.tenant
        )
        policy = Policy.objects.create(name="policy1", group=group, tenant=self.tenant)
        policy.roles.add(role)
        policy.save()
        access = IdentityHeaderMiddleware._get_access_for_user("test_user", self.tenant)
        expected = {
            "group": {"read": ["*"], "write": ["*"]},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
            "principal": {"read": [], "write": []},
            "permission": {"read": [], "write": []},
        }
        self.assertEqual(expected, access)

    def test_principal_with_access_with_wildcard_op(self):
        """Test a user with defined access with wildcard operation."""
        principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        group = Group.objects.create(name="group1", tenant=self.tenant)
        group.principals.add(principal)
        group.save()
        role = Role.objects.create(name="role1", tenant=self.tenant)
        perm = Permission.objects.create(permission="rbac:group:*", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        ResourceDefinition.objects.create(
            access=access, attributeFilter={"key": "group", "operation": "equal", "value": "1"}, tenant=self.tenant
        )
        ResourceDefinition.objects.create(
            access=access, attributeFilter={"key": "group", "operation": "in", "value": "3,5"}, tenant=self.tenant
        )
        ResourceDefinition.objects.create(
            access=access, attributeFilter={"key": "group", "operation": "equal", "value": "*"}, tenant=self.tenant
        )
        policy = Policy.objects.create(name="policy1", group=group, tenant=self.tenant)
        policy.roles.add(role)
        policy.save()
        access = IdentityHeaderMiddleware._get_access_for_user("test_user", self.tenant)
        expected = {
            "group": {"read": ["*"], "write": ["*"]},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
            "principal": {"read": [], "write": []},
            "permission": {"read": [], "write": []},
        }
        self.assertEqual(expected, access)

    def test_principal_with_access_with_wildcard_access(self):
        """Test a user with defined access with wildcard access."""
        principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        group = Group.objects.create(name="group1", tenant=self.tenant)
        group.principals.add(principal)
        group.save()
        role = Role.objects.create(name="role1", tenant=self.tenant)
        perm = Permission.objects.create(permission="rbac:*:*", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        policy = Policy.objects.create(name="policy1", group=group, tenant=self.tenant)
        policy.roles.add(role)
        policy.save()
        access = IdentityHeaderMiddleware._get_access_for_user("test_user", self.tenant)
        expected = {
            "group": {"read": ["*"], "write": ["*"]},
            "role": {"read": ["*"], "write": ["*"]},
            "policy": {"read": ["*"], "write": ["*"]},
            "principal": {"read": ["*"], "write": ["*"]},
            "permission": {"read": ["*"], "write": ["*"]},
        }
        self.assertEqual(expected, access)
