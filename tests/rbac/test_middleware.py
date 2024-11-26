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
from functools import partial
import json
import os
from unittest import mock
from unittest.mock import Mock, patch
from django.conf import settings
from django.http import QueryDict
from django.test.utils import override_settings
from importlib import reload

from django.test import TestCase, RequestFactory
from django.urls import reverse

from rest_framework import status
from rest_framework.test import APIClient
from django.urls import clear_url_caches, get_resolver

from api.models import Tenant, User
from api.serializers import create_tenant_name
from management.cache import TenantCache
from management.group.definer import seed_group
from management.tenant_mapping.model import TenantMapping
from management.workspace.model import Workspace
from migration_tool.in_memory_tuples import (
    InMemoryRelationReplicator,
    InMemoryTuples,
    all_of,
    relation,
    resource,
    subject,
)
from tests.identity_request import IdentityRequest
from rbac import urls
from rbac.middleware import HttpResponseUnauthorizedRequest, IdentityHeaderMiddleware, ReadOnlyApiMiddleware
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
        for k, v in self._changed.items():
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
        self.org_id = self.customer["org_id"]
        self.request_context = self._create_request_context(self.customer, self.user_data)
        self.request = self.request_context["request"]
        self.request.path = "/api/v1/providers/"
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        user.org_id = self.customer_data["org_id"]
        user.user_id = self.user_data["user_id"]
        self.request.user = user

    def test_get_tenant_with_user(self):
        """Test that the customer tenant is returned."""
        mock_request = self.request
        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.get_tenant)
        result = middleware.get_tenant(Tenant, "localhost", mock_request)
        self.assertEqual(result.org_id, mock_request.user.org_id)

    def test_get_tenant_with_no_user(self):
        """Test that a 401 is returned."""
        request_context = self._create_request_context(self.customer, None)
        mock_request = request_context["request"]
        mock_request.path = "/api/v1/providers/"
        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_request)
        result = middleware.process_request(mock_request)
        self.assertIsInstance(result, HttpResponseUnauthorizedRequest)

    def test_get_tenant_with_org_id(self):
        """Test that the customer tenant is returned containing an org_id."""
        user_data = self._create_user_data()
        customer = self._create_customer_data()
        customer["org_id"] = "45321"
        request_context = self._create_request_context(customer, user_data)
        request = request_context["request"]
        request.path = "/api/v1/providers/"
        request.META["QUERY_STRING"] = ""
        user = User()
        user.username = user_data["username"]
        user.account = customer["account_id"]
        user.org_id = "45321"
        request.user = user

        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_request)
        middleware.process_request(request)
        self.assertEqual(request.tenant.org_id, user.org_id)


class IdentityHeaderMiddlewareTest(IdentityRequest):
    """Tests against the rbac tenant middleware."""

    def setUp(self):
        """Set up middleware tests."""
        super().setUp()
        self.user_data = self._create_user_data()
        self.customer = self._create_customer_data()
        self.tenant_name = create_tenant_name(self.customer["account_id"])
        self.org_id = self.customer["org_id"]
        self.request_context = self._create_request_context(self.customer, self.user_data)
        self.request = self.request_context["request"]
        self.request.path = "/api/v1/providers/"
        self.request.META["QUERY_STRING"] = ""

    def test_process_status(self):
        """Test that the request gets a user."""
        mock_request = Mock(path="/api/v1/status/")
        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_request)
        middleware.process_request(mock_request)
        self.assertTrue(hasattr(mock_request, "user"))

    def test_process_cross_account_request(self):
        """Test that the process request functions correctly for cross account request."""
        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_request)
        # User without redhat email will fail.
        request_context = self._create_request_context(
            self.customer, self.user_data, cross_account=True, is_internal=True
        )
        mock_request = request_context["request"]
        mock_request.path = "/api/v1/providers/"

        response = middleware.process_request(mock_request)
        self.assertIsInstance(response, HttpResponseUnauthorizedRequest)

        # User with is_internal equal to False will fail.
        self.user_data["email"] = "test@redhat.com"
        request_context = self._create_request_context(self.customer, self.user_data, cross_account=True)
        mock_request = request_context["request"]
        mock_request.path = "/api/v1/providers/"

        response = middleware.process_request(mock_request)
        self.assertIsInstance(response, HttpResponseUnauthorizedRequest)

        # Success pass if user is internal and with redhat email
        self.user_data["email"] = "test@redhat.com"
        request_context = self._create_request_context(
            self.customer, self.user_data, cross_account=True, is_internal=True
        )
        mock_request = request_context["request"]
        mock_request.path = "/api/v1/providers/"

        response = middleware.process_request(mock_request)
        self.assertEqual(response, None)

    def test_process_response(self):
        """Test that the process response functions correctly."""
        mock_request = Mock(path="/api/rbac/v1/status/")
        mock_response = Mock(status_code=200)
        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_response)
        response = middleware.process_response(mock_request, mock_response)
        self.assertEqual(response, mock_response)

    def test_process_not_status(self):
        """Test that the customer, tenant and user are created."""
        mock_request = self.request
        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_request)
        middleware.process_request(mock_request)
        self.assertTrue(hasattr(mock_request, "user"))
        self.assertEqual(mock_request.user.username, self.user_data["username"])
        tenant = Tenant.objects.get(org_id=self.org_id)
        self.assertIsNotNone(tenant)
        self.assertTrue(tenant.ready)

    def test_process_existing_tenant_unchanged(self):
        mock_request = self.request
        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_request)
        middleware.process_request(mock_request)
        self.assertTrue(hasattr(mock_request, "user"))
        self.assertEqual(mock_request.user.username, self.user_data["username"])
        tenant = Tenant.objects.get(org_id=self.org_id)
        self.assertIsNotNone(tenant)
        self.assertTrue(tenant.ready)

        # Process a second request
        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_request)
        middleware.process_request(mock_request)

        tenant = Tenant.objects.get(org_id=self.org_id)
        self.assertTrue(tenant.ready)

    def test_process_readies_tenant(self):
        """If a tenant exists but is not ready, it is readied by the middleware."""
        tenant = Tenant.objects.create(
            tenant_name="test_user", org_id=self.org_id, account_id=self.customer["account_id"]
        )
        tenant.ready = False
        tenant.save()

        mock_request = self.request
        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_request)
        middleware.process_request(mock_request)

        tenant = Tenant.objects.get(org_id=self.org_id)
        self.assertTrue(tenant.ready)

    def test_process_no_customer(self):
        """Test that the customer, tenant and user are not created."""
        customer = self._create_customer_data()
        account_id = customer["account_id"]
        del customer["account_id"]
        request_context = self._create_request_context(customer, self.user_data)
        mock_request = request_context["request"]
        mock_request.path = "/api/v1/providers/"
        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_request)
        middleware.process_request(mock_request)
        self.assertTrue(hasattr(mock_request, "user"))
        with self.assertRaises(Tenant.DoesNotExist):
            Tenant.objects.get(org_id=self.org_id)

    def test_race_condition_customer(self):
        """Test case where another request may create the tenant in a race condition."""
        mock_request = self.request
        mock_request.user = User()
        mock_request.user.username = self.user_data["username"]
        mock_request.user.account = self.customer_data["account_id"]
        orig_cust = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.get_tenant).get_tenant(
            model=None, hostname=None, request=mock_request
        )
        dup_cust = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.get_tenant).get_tenant(
            model=None, hostname=None, request=mock_request
        )
        self.assertEqual(orig_cust, dup_cust)

    def test_tenant_process_without_org_id(self):
        """Test that an existing tenant doesn't create a new one when providing an org_id."""
        tenant = Tenant.objects.create(tenant_name="test_user")

        user_data = self._create_user_data()
        customer = self._create_customer_data()
        request_context = self._create_request_context(customer, user_data)
        request = request_context["request"]
        request.path = "/api/v1/providers/"
        request.META["QUERY_STRING"] = ""
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer["account_id"]
        user.org_id = "45321"
        request.user = user

        middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.process_request)
        middleware.process_request(request)
        self.assertEqual(Tenant.objects.filter(tenant_name="test_user").count(), 1)
        self.assertEqual(Tenant.objects.filter(tenant_name="test_user").first().org_id, None)

    def test_should_load_user_permissions_org_admin(self):
        """Tests that the function that determines if user permissions should be loaded returns False for org admins."""
        user = User()
        user.admin = True

        middleware = IdentityHeaderMiddleware(get_response=Mock())
        self.assertEqual(middleware.should_load_user_permissions(Mock(), user), False)

    def test_should_load_user_permissions_regular_user_non_access_endpoint(self):
        """Tests that the function under test returns True for regular users who have requested a path which isn't the access path"""
        user = User()
        user.admin = False

        request = Mock()
        request.path = "/principals/"

        middleware = IdentityHeaderMiddleware(get_response=Mock())
        self.assertEqual(middleware.should_load_user_permissions(request, user), True)

    def test_should_load_user_permissions_regular_user_access_non_get_request(self):
        """Tests that the function under test returns True for regular users who have requested the access path but with a different HTTP verb than GET"""
        user = User()
        user.admin = False

        request = Mock()
        request.path = "/access/"

        middleware = IdentityHeaderMiddleware(get_response=Mock())

        http_verbs = ["DELETE", "PATCH", "POST"]
        for verb in http_verbs:
            request.method = verb
            self.assertEqual(middleware.should_load_user_permissions(request, user), True)

    def test_should_load_user_permissions_regular_user_access(self):
        """Tests that the function under test returns True for regular users who have requested the access path with the expected query parameters"""
        user = User()
        user.admin = False

        request = Mock()
        request.path = "/access/"
        request.method = "GET"
        request.GET = QueryDict("application=rbac&username=foo")
        middleware = IdentityHeaderMiddleware(get_response=Mock())
        self.assertEqual(middleware.should_load_user_permissions(request, user), True)

    def test_should_load_user_permissions_regular_user_access_missing_query_params(self):
        """Tests that the function under test returns False for regular users who have requested the access path without the expected query parameters"""
        user = User()
        user.admin = False

        request = Mock()
        request.path = "/access/"
        request.method = "GET"

        test_cases: list[QueryDict] = [
            QueryDict("application=rbac"),
            QueryDict("username=foo"),
            QueryDict("applications=rbac&username=foo"),
            QueryDict("application=rbac&usernames=foo"),
        ]

        middleware = IdentityHeaderMiddleware(get_response=Mock())
        for test_case in test_cases:
            request.GET = test_case

            self.assertEqual(middleware.should_load_user_permissions(request, user), False)


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
        url = reverse("v1_management:group-list")
        client = APIClient()
        self.service_headers = {}
        response = client.get(url, {})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_identity_and_invalid_psk_returns_401(self):
        t = Tenant.objects.create(tenant_name=f"acct{self.account_id}", account_id=self.account_id, org_id=self.org_id)
        t.ready = True
        t.save()

        url = reverse("v1_management:group-list")
        client = APIClient()
        self.service_headers["HTTP_X_RH_RBAC_PSK"] = "xyz"
        response = client.get(url, **self.service_headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_identity_and_invalid_account_returns_404(self):
        t = Tenant.objects.create(tenant_name=f"acct{self.account_id}", account_id=self.account_id, org_id=self.org_id)
        t.ready = True
        t.save()
        url = reverse("v1_management:group-list")
        client = APIClient()
        self.service_headers["HTTP_X_RH_RBAC_ORG_ID"] = "1212"
        response = client.get(url, **self.service_headers)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_no_identity_and_invalid_client_id_returns_401(self):
        t = Tenant.objects.create(tenant_name=f"acct{self.account_id}", account_id=self.account_id, org_id=self.org_id)
        t.ready = True
        t.save()
        url = reverse("v1_management:group-list")
        client = APIClient()
        self.service_headers["HTTP_X_RH_RBAC_CLIENT_ID"] = "bad-service"
        response = client.get(url, **self.service_headers)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_identity_and_valid_psk_client_id_and_account_returns_200(self):
        t = Tenant.objects.create(tenant_name=f"acct{self.account_id}", account_id=self.account_id, org_id=self.org_id)
        t.ready = True
        t.save()
        url = reverse("v1_management:group-list")
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
        self.internal_request_context = self._create_request_context(self.customer, self.user_data, is_internal=True)

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


class RBACReadOnlyApiMiddleware(IdentityRequest):
    """Tests against the read-only API middleware."""

    def setUp(self):
        """Set up middleware tests."""
        super().setUp()
        self.factory = RequestFactory()
        self.request = self.factory.get("/api/rbac/v1/roles/")
        self.write_methods = ["POST", "PUT", "PATCH", "DELETE"]

    def assertReadOnlyFailure(self, resp):
        resp_body_str = resp.content.decode("utf-8")
        self.assertEqual(
            json.loads(resp_body_str)["error"], "This API is currently in read-only mode. Please try again later."
        )
        self.assertEqual(resp.status_code, 405)

    @override_settings(READ_ONLY_API_MODE=True)
    def test_get_read_only_true(self):
        """Test GET and READ_ONLY_API_MODE=True."""
        self.request.method = "GET"
        middleware = ReadOnlyApiMiddleware(get_response=Mock())
        resp = middleware.process_request(self.request)
        self.assertEqual(resp, None)

    @override_settings(READ_ONLY_API_MODE=True)
    def test_write_methods_read_only_true(self):
        """Test write methods and READ_ONLY_API_MODE=True."""
        for method in self.write_methods:
            self.request.method = method
            middleware = ReadOnlyApiMiddleware(get_response=Mock())
            resp = middleware.process_request(self.request)
            self.assertReadOnlyFailure(resp)

    def test_get_read_only_false(self):
        """Test GET and READ_ONLY_API_MODE=False."""
        self.request.method = "GET"
        middleware = ReadOnlyApiMiddleware(get_response=Mock())
        resp = middleware.process_request(self.request)
        self.assertEqual(resp, None)

    def test_write_methods_read_only_false(self):
        """Test write methods and READ_ONLY_API_MODE=False."""
        for method in self.write_methods:
            self.request.method = method
            middleware = ReadOnlyApiMiddleware(get_response=Mock())
            resp = middleware.process_request(self.request)
            self.assertEqual(resp, None)


@override_settings(V2_BOOTSTRAP_TENANT=True)
class V2RbacTenantMiddlewareTest(RbacTenantMiddlewareTest):
    """Run all the same tests with v2 tenant bootstrap enabled."""

    _tuples: InMemoryTuples

    def setUp(self):
        """Set up middleware tests."""
        super().setUp()
        self._tuples = InMemoryTuples()
        seed_group()

    def test_bootstraps_tenants_if_not_existing(self):
        with patch("rbac.middleware.OutboxReplicator", new=partial(InMemoryRelationReplicator, self._tuples)):
            # Change the user's org so we create a new tenant
            self.request.user.org_id = "12345"
            self.org_id = "12345"
            mock_request = self.request
            tenant_cache = TenantCache()
            tenant_cache.delete_tenant(self.org_id)
            middleware = IdentityHeaderMiddleware(get_response=IdentityHeaderMiddleware.get_tenant)
            result = middleware.get_tenant(Tenant, "localhost", mock_request)
            self.assertEqual(result.org_id, mock_request.user.org_id)
            tenant = Tenant.objects.get(org_id=self.org_id)
            self.assertIsNotNone(tenant)
            mapping = TenantMapping.objects.get(tenant=tenant)
            self.assertIsNotNone(mapping)
            workspaces = list(Workspace.objects.filter(tenant=tenant))
            self.assertEqual(len(workspaces), 2)
            default = Workspace.objects.get(type=Workspace.Types.DEFAULT, tenant=tenant)
            self.assertIsNotNone(default)
            root = Workspace.objects.get(type=Workspace.Types.ROOT, tenant=tenant)
            self.assertIsNotNone(root)

            platform_default_policy = Policy.objects.get(group=Group.objects.get(platform_default=True))
            admin_default_policy = Policy.objects.get(group=Group.objects.get(admin_default=True))

            self.assertEqual(
                1,
                self._tuples.count_tuples(
                    all_of(
                        resource("rbac", "workspace", default.id),
                        relation("binding"),
                        subject("rbac", "role_binding", mapping.default_role_binding_uuid),
                    )
                ),
            )
            self.assertEqual(
                1,
                self._tuples.count_tuples(
                    all_of(
                        resource("rbac", "role_binding", mapping.default_role_binding_uuid),
                        relation("subject"),
                        subject("rbac", "group", mapping.default_group_uuid, "member"),
                    )
                ),
            )
            self.assertEqual(
                1,
                self._tuples.count_tuples(
                    all_of(
                        resource("rbac", "role_binding", mapping.default_role_binding_uuid),
                        relation("role"),
                        subject("rbac", "role", platform_default_policy.uuid),
                    )
                ),
            )

            self.assertEqual(
                1,
                self._tuples.count_tuples(
                    all_of(
                        resource("rbac", "workspace", default.id),
                        relation("binding"),
                        subject("rbac", "role_binding", mapping.default_admin_role_binding_uuid),
                    )
                ),
            )
            self.assertEqual(
                1,
                self._tuples.count_tuples(
                    all_of(
                        resource("rbac", "role_binding", mapping.default_admin_role_binding_uuid),
                        relation("subject"),
                        subject("rbac", "group", mapping.default_admin_group_uuid, "member"),
                    )
                ),
            )
            self.assertEqual(
                1,
                self._tuples.count_tuples(
                    all_of(
                        resource("rbac", "role_binding", mapping.default_admin_role_binding_uuid),
                        relation("role"),
                        subject("rbac", "role", admin_default_policy.uuid),
                    )
                ),
            )


@override_settings(V2_BOOTSTRAP_TENANT=True)
class V2IdentityHeaderMiddlewareTest(IdentityHeaderMiddlewareTest):
    """Run all the same tests with v2 tenant bootstrap enabled plus additional."""

    pass


@override_settings(V2_APIS_ENABLED=True)
class RBACReadOnlyApiMiddlewareV2(RBACReadOnlyApiMiddleware):
    """Tests against the read-only API middleware for v2."""

    def setUp(self):
        """Set up middleware tests."""
        reload(urls)
        clear_url_caches()
        super().setUp()
        self.request = self.factory.get("/api/rbac/v2/workspaces/")

    @override_settings(V2_READ_ONLY_API_MODE=True)
    def test_get_read_only_v2_true(self):
        """Test GET and V2_READ_ONLY_API_MODE=True."""
        self.request.method = "GET"
        middleware = ReadOnlyApiMiddleware(get_response=Mock())
        resp = middleware.process_request(self.request)
        self.assertEqual(resp, None)

    @override_settings(V2_READ_ONLY_API_MODE=True)
    def test_write_methods_read_only_v2_true(self):
        """Test write methods and V2_READ_ONLY_API_MODE=True."""
        for method in self.write_methods:
            self.request.method = method
            middleware = ReadOnlyApiMiddleware(get_response=Mock())
            resp = middleware.process_request(self.request)
            self.assertReadOnlyFailure(resp)

    def test_get_read_only_v2_false(self):
        """Test GET and V2_READ_ONLY_API_MODE=False."""
        self.request.method = "GET"
        middleware = ReadOnlyApiMiddleware(get_response=Mock())
        resp = middleware.process_request(self.request)
        self.assertEqual(resp, None)

    def test_write_methods_read_only_v2_false(self):
        """Test write methods and V2_READ_ONLY_API_MODE=False."""
        for method in self.write_methods:
            self.request.method = method
            middleware = ReadOnlyApiMiddleware(get_response=Mock())
            resp = middleware.process_request(self.request)
            self.assertEqual(resp, None)

    @override_settings(V2_READ_ONLY_API_MODE=True)
    def test_write_methods_read_only_v2_true_v1_path(self):
        """Test write methods and V2_READ_ONLY_API_MODE=False with a v1 API path succeeds."""
        for method in self.write_methods:
            self.request.method = method
            self.request.path = "/api/rbac/v1/roles/"
            middleware = ReadOnlyApiMiddleware(get_response=Mock())
            resp = middleware.process_request(self.request)
            self.assertEqual(resp, None)
