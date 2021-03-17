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

import random
from decimal import Decimal
from uuid import uuid4
from unittest.mock import patch

from api.models import CrossAccountRequest, Tenant
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient
from tenant_schemas.utils import tenant_context

from api.models import User
from datetime import timedelta
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
        request.user = user

        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [{"attributeFilter": {"key": "key1", "operation": "equal", "value": "value1"}}],
        }
        with tenant_context(self.tenant):
            self.principal = Principal(username=self.user_data["username"])
            self.principal.save()
            self.admin_principal = Principal(username="user_admin")
            self.admin_principal.save()
            self.group = Group(name="groupA")
            self.group.save()
            self.group.principals.add(self.principal)
            self.group.save()
            self.permission = Permission.objects.create(permission="app:*:*")
            Permission.objects.create(permission="app:foo:bar")

    def tearDown(self):
        """Tear down access view tests."""
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Principal.objects.all().delete()
            Role.objects.all().delete()
            Policy.objects.all().delete()

    def create_role(self, role_name, in_access_data=None):
        """Create a role."""
        access_data = self.access_data
        if in_access_data:
            access_data = in_access_data
        test_data = {"name": role_name, "access": [access_data]}

        # create a role
        url = reverse("role-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        return response

    def create_policy(self, policy_name, group, roles, status=status.HTTP_201_CREATED):
        """Create a policy."""
        # create a policy
        test_data = {"name": policy_name, "group": group, "roles": roles}
        url = reverse("policy-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status)
        return response

    def create_platform_default_resource(self):
        """Setup default group and role."""
        with tenant_context(self.tenant):
            default_permission = Permission.objects.create(permission="default:*:*")
            default_role = Role.objects.create(name="default role", platform_default=True, system=True)
            default_access = Access.objects.create(permission=default_permission, role=default_role)
            default_policy = Policy.objects.create(name="default policy", system=True)
            default_policy.roles.add(default_role)
            default_group = Group.objects.create(name="default group", system=True, platform_default=True)
            default_group.policies.add(default_policy)

    def create_role_and_permission(self, role_name, permission):
        role = Role.objects.create(name=role_name)
        assigned_permission = Permission.objects.create(permission=permission)
        access = Access.objects.create(role=role, permission=assigned_permission)
        return role

    def test_get_access_success(self):
        """Test that we can obtain the expected access without pagination."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)
        access = Access.objects.create(role=role, permission=self.permission)
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])
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
        self.assertEqual(response.data.get("meta").get("limit"), 1000)
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
        user_id = "123456"
        user_name = f"{account_id}-{user_id}"

        # setup cross account request, role and permission in public schema
        ## This CAR will provide permission: "test:assigned:permission"
        role = self.create_role_and_permission("Test Role one", "test:assigned:permission1")
        cross_account_request = CrossAccountRequest.objects.create(
            target_account=account_id, user_id=user_id, end_date=timezone.now() + timedelta(10), status="approved"
        )
        cross_account_request.roles.add(role)
        ## CAR below will provide permission: "app:*:*"
        role = self.create_role_and_permission("Test Role two", "test:assigned:permission2")
        cross_account_request = CrossAccountRequest.objects.create(
            target_account=account_id, user_id=user_id, end_date=timezone.now() + timedelta(20), status="approved"
        )
        cross_account_request.roles.add(role)

        # Create cross_account principal and role, permission in the account
        user_data = {"username": user_name, "email": "test@gmail.com"}
        request_context = self._create_request_context(self.customer_data, user_data, is_org_admin=False)
        request = request_context["request"]
        headers = request.META

        with tenant_context(self.tenant):
            Principal.objects.create(username=user_name, cross_account=True)
            self.create_role_and_permission("Test Role one", "test:assigned:permission1")
            self.create_role_and_permission("Test Role two", "test:assigned:permission2")
        response = client.get(url, **headers)

        # only assigned role permissions without platform default permission
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        permissions = [access["permission"] for access in response.data.get("data")]
        self.assertListEqual(permissions, ["test:assigned:permission1", "test:assigned:permission2"])

    def test_get_access_no_app_supplied(self):
        """Test that we return all permissions when no app supplied."""
        role_name = "roleA"
        policy_name = "policyA"
        access_data = {
            "permission": "app:foo:bar",
            "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
        }
        response = self.create_role(role_name, access_data)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)
        access = Access.objects.create(role=role, permission=self.permission)
        self.create_policy(policy_name, self.group.uuid, [role_uuid])

        url = "{}?application=&username={}".format(reverse("access"), self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("data"))
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 2)
        self.assertEqual(response.data.get("meta").get("limit"), 1000)

    def test_get_access_multiple_apps_supplied(self):
        """Test that we return all permissions for multiple apps when supplied."""
        role_name = "roleA"
        policy_name = "policyA"
        access_data = {
            "permission": "app:foo:bar",
            "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
        }
        response = self.create_role(role_name, access_data)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)
        access = Access.objects.create(role=role, permission=self.permission)
        self.create_policy(policy_name, self.group.uuid, [role_uuid])

        url = "{}?application={}&username={}".format(reverse("access"), "app,app2", self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 2)

    def test_get_access_no_partial_match(self):
        """Test that we can have a partial match on app/permission."""
        role_name = "roleA"
        policy_name = "policyA"
        access_data = {
            "permission": "app:foo:bar",
            "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
        }
        response = self.create_role(role_name, access_data)
        role_uuid = response.data.get("uuid")
        self.create_policy(policy_name, self.group.uuid, [role_uuid])

        url = "{}?application={}&username={}".format(reverse("access"), "ap", self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("data"))
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 0)
        self.assertEqual(response.data.get("meta").get("limit"), 1000)

    def test_get_access_no_match(self):
        """Test that we only match on the application name of the permission data."""
        role_name = "roleA"
        policy_name = "policyA"
        access_data = {
            "permission": "app:foo:bar",
            "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
        }
        response = self.create_role(role_name, access_data)
        role_uuid = response.data.get("uuid")
        self.create_policy(policy_name, self.group.uuid, [role_uuid])

        url = "{}?application={}&username={}".format(reverse("access"), "foo", self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("data"))
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 0)
        self.assertEqual(response.data.get("meta").get("limit"), 1000)

    def test_get_access_with_limit(self):
        """Test that we can obtain the expected access with pagination."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])

        # test that we can retrieve the principal access
        url = "{}?application={}&username={}&limit=1".format(reverse("access"), "app", self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)
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
        url = "{}?application={}&username={}".format(reverse("access"), "app", uuid4())
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
