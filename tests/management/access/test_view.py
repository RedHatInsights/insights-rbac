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
"""Test the access view."""
import json
import random
from decimal import Decimal
from uuid import uuid4
from unittest.mock import patch

from api.models import CrossAccountRequest, Tenant
from collections import OrderedDict
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant, User
from datetime import timedelta
from management.cache import AccessCache
from management.models import Group, Permission, Principal, Policy, Role, Access
from tests.identity_request import IdentityRequest


class AccessViewTests(IdentityRequest):
    """Test the access view."""

    def setUp(self):
        """Set up the access view tests."""
        super().setUp()
        request = self.request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        user.org_id = self.customer_data["org_id"]
        request.user = user
        public_tenant = Tenant.objects.get(tenant_name="public")

        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [{"attributeFilter": {"key": "key1", "operation": "equal", "value": "value1"}}],
        }
        self.test_tenant = Tenant(tenant_name="acct1111111", account_id="1111111", org_id="100001", ready=True)
        self.test_tenant.save()
        self.test_principal = Principal(username="test_user", tenant=self.test_tenant)
        self.test_principal.save()
        self.test_group = Group(name="test_groupA", tenant=self.test_tenant)
        self.test_group.save()
        self.test_group.principals.add(self.test_principal)
        self.test_group.save()
        self.test_permission = Permission.objects.create(permission="app:test_*:test_*", tenant=self.test_tenant)
        Permission.objects.create(permission="app:test_foo:test_bar", tenant=self.test_tenant)

        self.principal = Principal(username=user.username, tenant=self.tenant)
        self.principal.save()
        self.admin_principal = Principal(username="user_admin", tenant=self.tenant)
        self.admin_principal.save()
        self.group = Group(name="groupA", tenant=self.tenant)
        self.group.save()
        self.group.principals.add(self.principal)
        self.group.save()
        self.permission = Permission.objects.create(permission="app:*:*", tenant=self.tenant)
        Permission.objects.create(permission="app:foo:bar", tenant=self.tenant)

    def tearDown(self):
        """Tear down access view tests."""
        Group.objects.all().delete()
        Principal.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()

    def create_role(self, role_name, headers, in_access_data=None):
        """Create a role."""
        access_data = self.access_data
        if in_access_data:
            access_data = in_access_data
        test_data = {"name": role_name, "access": [access_data]}

        # create a role
        url = reverse("role-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        return response

    def create_policy(self, policy_name, group, roles, headers, status=status.HTTP_201_CREATED):
        """Create a policy."""
        # create a policy
        test_data = {"name": policy_name, "group": group, "roles": roles}
        url = reverse("policy-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **headers)
        self.assertEqual(response.status_code, status)
        return response

    def create_platform_default_resource(self):
        """Setup default group and role."""
        default_permission = Permission.objects.create(permission="default:*:*", tenant=self.tenant)
        default_role = Role.objects.create(name="default role", platform_default=True, system=True, tenant=self.tenant)
        default_access = Access.objects.create(permission=default_permission, role=default_role, tenant=self.tenant)
        default_policy = Policy.objects.create(name="default policy", system=True, tenant=self.tenant)
        default_policy.roles.add(default_role)
        default_group = Group.objects.create(
            name="default group", system=True, platform_default=True, tenant=self.tenant
        )
        default_group.policies.add(default_policy)

    def create_role_and_permission(self, role_name, permission):
        role = Role.objects.create(name=role_name, tenant=self.tenant)
        assigned_permission = Permission.objects.create(permission=permission, tenant=self.tenant)
        access = Access.objects.create(role=role, permission=assigned_permission, tenant=self.tenant)
        return role

    def test_get_access_success(self):
        """Test that we can obtain the expected access without pagination."""
        role_name = "roleA"
        response = self.create_role(role_name, headers=self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)
        access = Access.objects.create(role=role, permission=self.permission, tenant=self.tenant)
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid], headers=self.headers)
        # Create platform default group, and add roles to it.
        self.create_platform_default_resource()

        # Test that we can retrieve the principal access
        url = "{}?application={}".format(reverse("access"), "app")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("data"))
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 2)
        self.assertEqual(response.data.get("meta").get("limit"), 2)
        self.assertEqual(self.access_data, response.data.get("data")[0])

        # the platform default permission could also be retrieved
        url = "{}?application={}".format(reverse("access"), "default")
        response = client.get(url, **self.headers)
        self.assertEqual({"permission": "default:*:*", "resourceDefinitions": []}, response.data.get("data")[0])

    def test_access_for_cross_account_principal_return_permissions_based_on_assigned_role(self):
        """Test that the expected access for cross account principal return permissions based on assigned role."""
        # setup default group/role
        self.create_platform_default_resource()
        client = APIClient()
        url = "{}?application=".format(reverse("access"))
        account_id = self.customer_data["account_id"]
        org_id = self.customer_data["org_id"]
        user_id = "123456"
        user_name = f"{account_id}-{user_id}"

        # setup cross account request, role and permission in public schema
        ## This CAR will provide permission: "test:assigned:permission"
        role = self.create_role_and_permission("Test Role one", "test:assigned:permission1")
        cross_account_request = CrossAccountRequest.objects.create(
            target_account=account_id,
            user_id=user_id,
            target_org=org_id,
            end_date=timezone.now() + timedelta(10),
            status="approved",
        )
        cross_account_request.roles.add(role)
        ## CAR below will provide permission: "app:*:*"
        role = self.create_role_and_permission("Test Role two", "test:assigned:permission2")
        cross_account_request = CrossAccountRequest.objects.create(
            target_account=account_id,
            user_id=user_id,
            target_org=org_id,
            end_date=timezone.now() + timedelta(20),
            status="approved",
        )
        cross_account_request.roles.add(role)

        # Create cross_account principal and role, permission in the account
        user_data = {"username": user_name, "email": "test@gmail.com"}
        request_context = self._create_request_context(self.customer_data, user_data, is_org_admin=False)
        request = request_context["request"]
        headers = request.META
        Principal.objects.create(username=user_name, cross_account=True, tenant=self.tenant)

        response = client.get(url, **headers)

        # only assigned role permissions without platform default permission
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        permissions = [access["permission"] for access in response.data.get("data")]
        self.assertListEqual(permissions, ["test:assigned:permission1", "test:assigned:permission2"])

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": True,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "test_user",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_get_access_no_app_supplied(self, mock_request):
        """Test that we return all permissions when no app supplied."""
        user_data = {"username": "test_user", "email": "test@gmail.com"}
        request_context = self._create_request_context(
            {"account_id": "1111111", "tenant_name": "acct1111111", "org_id": "100001"}, user_data, is_org_admin=True
        )
        request = request_context["request"]
        headers = request.META
        role_name = "roleA"
        policy_name = "policyA"
        access_data = {
            "permission": "app:test_foo:test_bar",
            "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
        }
        response = self.create_role(role_name, headers, access_data)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)
        access = Access.objects.create(role=role, permission=self.test_permission, tenant=self.test_tenant)
        self.create_policy(policy_name, self.test_group.uuid, [role_uuid], headers)

        url = "{}?application=&username={}".format(reverse("access"), self.test_principal.username)
        client = APIClient()
        response = client.get(url, **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("data"))
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 2)
        self.assertEqual(response.data.get("meta").get("limit"), 2)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": True,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "test_user",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_get_access_multiple_apps_supplied(self, mock_request):
        """Test that we return all permissions for multiple apps when supplied."""
        user_data = {"username": "test_user", "email": "test@gmail.com"}
        request_context = self._create_request_context(
            {"account_id": "1111111", "tenant_name": "acct1111111", "org_id": "100001"}, user_data, is_org_admin=True
        )
        request = request_context["request"]
        headers = request.META
        role_name = "roleA"
        policy_name = "policyA"
        access_data = {
            "permission": "app:test_foo:test_bar",
            "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
        }
        response = self.create_role(role_name, headers, access_data)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)
        access = Access.objects.create(role=role, permission=self.test_permission, tenant=self.test_tenant)
        self.create_policy(policy_name, self.test_group.uuid, [role_uuid], headers)

        url = "{}?application={}&username={}".format(reverse("access"), "app,app2", "test_user")
        client = APIClient()
        response = client.get(url, **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 2)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": True,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "test_user",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_get_access_no_partial_match(self, mock_request):
        """Test that we can have a partial match on app/permission."""
        user_data = {"username": "test_user", "email": "test@gmail.com"}
        request_context = self._create_request_context(
            {"account_id": "1111111", "tenant_name": "acct1111111", "org_id": "100001"}, user_data, is_org_admin=True
        )
        request = request_context["request"]
        headers = request.META
        role_name = "roleA"
        policy_name = "policyA"
        access_data = {
            "permission": "app:test_foo:test_bar",
            "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
        }
        response = self.create_role(role_name, headers, access_data)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)
        access = Access.objects.create(role=role, permission=self.test_permission, tenant=self.test_tenant)
        self.create_policy(policy_name, self.test_group.uuid, [role_uuid], headers)

        url = "{}?application={}&username={}".format(reverse("access"), "ap", self.test_principal.username)
        client = APIClient()
        response = client.get(url, **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("data"))
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 0)
        self.assertEqual(response.data.get("meta").get("limit"), 0)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": True,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "test_user",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_get_access_no_subset_match(self, mock_request):
        """Test that we cannot have a subset match on app/permission."""
        user_data = {"username": "test_user", "email": "test@gmail.com"}
        request_context = self._create_request_context(
            {"account_id": "1111111", "tenant_name": "acct1111111", "org_id": "100001"}, user_data, is_org_admin=True
        )
        request = request_context["request"]
        headers = request.META
        role_name = "roleA"
        policy_name = "policyA"
        access_data = {
            "permission": "app:test_foo:test_bar",
            "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
        }
        response = self.create_role(role_name, headers, access_data)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)
        access = Access.objects.create(role=role, permission=self.test_permission, tenant=self.test_tenant)
        self.create_policy(policy_name, self.test_group.uuid, [role_uuid], headers)

        url = "{}?application={}&username={}".format(reverse("access"), "appfoo", self.test_principal.username)
        client = APIClient()
        response = client.get(url, **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("data"))
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 0)
        self.assertEqual(response.data.get("meta").get("limit"), 0)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": True,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "test_user",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_get_access_no_match(self, mock_request):
        """Test that we only match on the application name of the permission data."""
        user_data = {"username": "test_user", "email": "test@gmail.com"}
        request_context = self._create_request_context(
            {"account_id": "1111111", "tenant_name": "acct1111111", "org_id": "100001"}, user_data, is_org_admin=True
        )
        request = request_context["request"]
        headers = request.META
        role_name = "roleA"
        policy_name = "policyA"
        access_data = {
            "permission": "app:test_foo:test_bar",
            "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
        }
        response = self.create_role(role_name, headers, access_data)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)
        access = Access.objects.create(role=role, permission=self.test_permission, tenant=self.test_tenant)
        self.create_policy(policy_name, self.test_group.uuid, [role_uuid], headers)

        url = "{}?application={}&username={}".format(reverse("access"), "test_foo", self.test_principal.username)
        client = APIClient()
        response = client.get(url, **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("data"))
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 0)
        self.assertEqual(response.data.get("meta").get("limit"), 0)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": True,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "test_user",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_get_access_with_limit(self, mock_request):
        """Test that we can obtain the expected access with pagination."""
        user_data = {"username": "test_user", "email": "test@gmail.com"}
        request_context = self._create_request_context(
            {"account_id": "1111111", "tenant_name": "acct1111111", "org_id": "100001"}, user_data, is_org_admin=True
        )
        request = request_context["request"]
        headers = request.META
        role_name = "roleA"
        response = self.create_role(role_name, headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.test_group.uuid, [role_uuid], headers)

        # test that we can retrieve the principal access
        url = "{}?application={}&username={}&limit=1".format(reverse("access"), "app", self.test_principal.username)
        client = APIClient()
        response = client.get(url, **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("data"))
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        self.assertEqual(response.data.get("meta").get("limit"), 1)
        self.assertEqual(self.access_data, response.data.get("data")[0])

    def test_missing_query_params(self):
        """Test that we get expected failure when missing required query params."""
        url = "{}?page={}".format(reverse("access"), "3")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_missing_invalid_username(self, mock_request):
        """Test that we get expected failure when missing required query params."""
        url = "{}?application={}&username={}".format(reverse("access"), "app", "test_user")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("management.cache.AccessCache.get_policy", return_value=None)
    @patch("management.cache.AccessCache.save_policy", return_value=None)
    def test_get_access_with_pagination_and_cache(self, save_policy, get_policy):
        """Test that we can obtain the expected access with pagination and cache."""
        role_name = "roleA"
        response = self.create_role(role_name, self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        test_role = self.create_role_and_permission("Test Role one", "test:assigned:permission1")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid, test_role.uuid], self.headers)

        tenant_name = self.tenant.tenant_name
        principal_id = self.principal.uuid
        key = f"rbac::policy::tenant={tenant_name}::user={principal_id}"
        client = APIClient()

        ######## access_policy are cached with desired sub_key ############
        url = "{}?application={}&username={}&offset=1&limit=1".format(
            reverse("access"), "app", self.principal.username
        )
        response = client.get(url, **self.headers)

        get_policy.assert_called_with(principal_id, "app")
        called_with_para = save_policy.mock_calls[0][1]  # save_policy params
        self.assertEqual(principal_id, called_with_para[0])
        self.assertEqual("app", called_with_para[1])
        self.assertEqual([self.access_data], called_with_para[2])  # it catches all the policies for app
        self.assertEqual(response.data["meta"]["count"], 1)
        self.assertEqual(
            response.data["data"], []
        )  # after pagination, it is empty becase totoal is one, and offset is one
        ###################################################################

        #### access_policy are cached properly when application is empty ####
        url = "{}?application=&username={}&limit=1".format(reverse("access"), self.principal.username)
        response = client.get(url, **self.headers)

        # Cache is called saved with sub_key ""
        get_policy.assert_called_with(principal_id, "")
        called_with_para = save_policy.mock_calls[1][1]
        self.assertEqual(principal_id, called_with_para[0])
        self.assertEqual("", called_with_para[1])
        self.assertEqual(2, len(called_with_para[2]))  # it catches all the policies for app
        self.assertEqual(response.data["meta"]["count"], 2)
        self.assertEqual(len(response.data["data"]), 1)  # returns one policy because limit is 1

    @patch("management.cache.AccessCache.get_policy", return_value=None)
    @patch("management.cache.AccessCache.save_policy", return_value=None)
    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": True,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "test_user",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_get_access_with_ordering_and_cache(self, save_policy, get_policy, mock_request):
        """Test that we can obtain the expected access with ordering and cache."""
        user_data = {"username": "test_user", "email": "test@gmail.com"}
        request_context = self._create_request_context(
            {"account_id": "1111111", "tenant_name": "acct1111111", "org_id": "100001"}, user_data, is_org_admin=True
        )
        request = request_context["request"]
        headers = request.META
        role_name = "roleA"
        response = self.create_role(role_name, headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        test_role = self.create_role_and_permission("Test Role one", "test:assigned:permission1")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.test_group.uuid, [role_uuid, test_role.uuid], headers)

        tenant_name = self.test_tenant.tenant_name
        principal_id = self.test_principal.uuid
        principal_username = self.test_principal.username
        key = f"rbac::policy::tenant={tenant_name}::user={principal_id}"
        client = APIClient()

        #### Sort by application ####
        url = "{}?application=&username={}&order_by={}".format(
            reverse("access"), self.test_principal.username, "application"
        )
        response = client.get(url, **headers)

        # Cache is called saved with sub_key ""
        get_policy.assert_called_with(
            principal_id,
            "&order:application",
            [
                OrderedDict(
                    [
                        (
                            "resourceDefinitions",
                            [
                                OrderedDict(
                                    [("attributeFilter", {"key": "key1", "value": "value1", "operation": "equal"})]
                                )
                            ],
                        ),
                        ("permission", "app:*:*"),
                    ]
                ),
                OrderedDict([("resourceDefinitions", []), ("permission", "test:assigned:permission1")]),
            ],
        )
        called_with_para = save_policy.mock_calls[0][1]
        self.assertEqual([principal_username], called_with_para[0])
        self.assertEqual("&order:application", called_with_para[1])
        self.assertEqual(2, len(called_with_para[2]))  # it catches all the policies
        self.assertEqual(response.data["meta"]["count"], 2)
        self.assertEqual(response.data["data"][0]["permission"], "app:*:*")  # check order

        url = "{}?application=&username={}&order_by={}".format(
            reverse("access"), self.test_principal.username, "-application"
        )
        response = client.get(url, headers)
        get_policy.assert_called_with(principal_id, "&order:-application")
        called_with_para = save_policy.mock_calls[1][1]
        self.assertEqual(principal_username, called_with_para[0])
        self.assertEqual("&order:-application", called_with_para[1])
        self.assertEqual(2, len(called_with_para[2]))  # it catches all the policies
        self.assertEqual(response.data["meta"]["count"], 2)
        # Response data is in reverse order
        self.assertEqual(response.data["data"][0]["permission"], "test:assigned:permission1")  # check order

        #### Sort by resource_type ####
        url = "{}?application=&username={}&order_by={}".format(
            reverse("access"), self.test_principal.username, "resource_type"
        )
        response = client.get(url, **headers)

        # Cache is called saved with sub_key ""
        get_policy.assert_called_with(principal_id, "&order:resource_type")
        called_with_para = save_policy.mock_calls[2][1]
        self.assertEqual(principal_username, called_with_para[0])
        self.assertEqual("&order:resource_type", called_with_para[1])
        self.assertEqual(2, len(called_with_para[2]))  # it catches all the policies
        self.assertEqual(response.data["meta"]["count"], 2)
        self.assertEqual(response.data["data"][0]["permission"], "app:*:*")  # check order

        url = "{}?application=&username={}&order_by={}".format(
            reverse("access"), self.test_principal.username, "-resource_type"
        )
        response = client.get(url, **headers)
        get_policy.assert_called_with(principal_id, "&order:-resource_type")
        called_with_para = save_policy.mock_calls[3][1]
        self.assertEqual(principal_username, called_with_para[0])
        self.assertEqual("&order:-resource_type", called_with_para[1])
        self.assertEqual(2, len(called_with_para[2]))  # it catches all the policies
        self.assertEqual(response.data["meta"]["count"], 2)
        # Response data is in reverse order
        self.assertEqual(response.data["data"][0]["permission"], "test:assigned:permission1")  # check order

        #### Sort by verb ####
        url = "{}?application=&username={}&order_by={}".format(reverse("access"), self.test_principal.username, "verb")
        response = client.get(url, **headers)

        # Cache is called saved with sub_key ""
        get_policy.assert_called_with(principal_id, "&order:verb")
        called_with_para = save_policy.mock_calls[4][1]
        self.assertEqual(principal_username, called_with_para[0])
        self.assertEqual("&order:verb", called_with_para[1])
        self.assertEqual(2, len(called_with_para[2]))  # it catches all the policies
        self.assertEqual(response.data["meta"]["count"], 2)
        self.assertEqual(response.data["data"][0]["permission"], "app:*:*")  # check order

        url = "{}?application=&username={}&order_by={}".format(
            reverse("access"), self.test_principal.username, "-verb"
        )
        response = client.get(url, **headers)
        # Cache is called saved with sub_key ""
        get_policy.assert_called_with(principal_id, "&order:-verb")
        called_with_para = save_policy.mock_calls[5][1]
        self.assertEqual(principal_username, called_with_para[0])
        self.assertEqual("&order:-verb", called_with_para[1])
        self.assertEqual(2, len(called_with_para[2]))  # it catches all the policies
        self.assertEqual(response.data["meta"]["count"], 2)
        # Response data is in reverse order
        self.assertEqual(response.data["data"][0]["permission"], "test:assigned:permission1")  # check order

        #### Sort by nothing still works ####
        url = "{}?application=&username={}&order_by=".format(reverse("access"), self.test_principal.username)
        response = client.get(url, **headers)
        # Cache is called saved with sub_key ""
        get_policy.assert_called_with(principal_id, "")
        called_with_para = save_policy.mock_calls[6][1]
        self.assertEqual(principal_username, called_with_para[0])
        self.assertEqual("", called_with_para[1])
        self.assertEqual(2, len(called_with_para[2]))  # it catches all the policies
        self.assertEqual(response.data["meta"]["count"], 2)

    def test_get_access_with_invalid_ordering_value(self):
        """Test that get access with invalid ordering value raises 401."""
        client = APIClient()
        url = "{}?application={}&username={}&order_by={}".format(
            reverse("access"), "app", self.principal.username, "invalid_value"
        )
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
