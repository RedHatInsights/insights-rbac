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

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from tenant_schemas.utils import tenant_context

from api.models import User
from management.models import Group, Principal, Policy, Role, Access
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

    def test_get_access_success(self):
        """Test that we can obtain the expected access without pagination."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=role_uuid)
        access = Access.objects.create(role=role, permission="app2:foo:bar")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])

        # test that we can retrieve the principal access
        url = "{}?application={}&username={}".format(reverse("access"), "app", self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("data"))
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("meta").get("limit"), 1000)
        self.assertEqual(self.access_data, response.data.get("data")[0])

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
        access = Access.objects.create(role=role, permission="app2:foo:bar")
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
        access = Access.objects.create(role=role, permission="app2:foo:bar")
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
