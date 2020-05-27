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
"""Test the policy viewset."""

import random
from decimal import Decimal
from uuid import uuid4

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from tenant_schemas.utils import tenant_context

from api.models import User
from management.models import Group, Principal, Policy, Role
from tests.identity_request import IdentityRequest


class PolicyViewsetTests(IdentityRequest):
    """Test the policy viewset."""

    def setUp(self):
        """Set up the policy viewset tests."""
        super().setUp()
        request = self.request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        request.user = user

        with tenant_context(self.tenant):
            self.principal = Principal(username=self.user_data["username"])
            self.principal.save()
            self.group = Group(name="groupA")
            self.group.save()
            self.group.principals.add(self.principal)
            self.group.save()

    def tearDown(self):
        """Tear down policy viewset tests."""
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Principal.objects.all().delete()
            Role.objects.all().delete()
            Policy.objects.all().delete()

    def create_role(self, role_name, in_access_data=None):
        """Create a role."""
        access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [{"attributeFilter": {"key": "key1", "operation": "equal", "value": "value1"}}],
        }
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

    def test_create_policy_success(self):
        """Test that we can create a policy."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])

        # test that we can retrieve the policy
        url = reverse("policy-detail", kwargs={"uuid": response.data.get("uuid")})
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertIsNotNone(response.data.get("uuid"))
        self.assertIsNotNone(response.data.get("name"))
        self.assertEqual(policy_name, response.data.get("name"))
        self.assertEqual(str(self.group.uuid), response.data.get("group").get("uuid"))

    def test_create_policy_invalid_group(self):
        """Test that we cannot create a policy with invalid group."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, uuid4(), [role_uuid], status.HTTP_400_BAD_REQUEST)

    def test_create_policy_invalid_role(self):
        """Test that we cannot create a policy with an invalid role."""
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [uuid4()], status.HTTP_400_BAD_REQUEST)

    def test_create_policy_no_role(self):
        """Test that we cannot create a policy without roles."""
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [], status.HTTP_400_BAD_REQUEST)

    def test_create_policy_invalid(self):
        """Test that creating an invalid policy returns an error."""
        test_data = {}
        url = reverse("policy-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_policy_invalid(self):
        """Test that reading an invalid policy returns an error."""
        url = reverse("policy-detail", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_read_policy_list_success(self):
        """Test that we can read a list of policies."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])

        # list a policies
        url = reverse("policy-list")
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 1)

        policy = response.data.get("data")[0]
        self.assertIsNotNone(policy.get("name"))
        self.assertEqual(policy.get("name"), policy_name)

    def test_update_policy_success(self):
        """Test that we can update an existing policy."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])
        updated_name = policy_name + "_update"
        policy_uuid = response.data.get("uuid")
        test_data = response.data
        test_data["name"] = updated_name
        test_data["group"] = self.group.uuid
        test_data["roles"] = [role_uuid]
        del test_data["uuid"]
        url = reverse("policy-detail", kwargs={"uuid": policy_uuid})
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIsNotNone(response.data.get("uuid"))
        self.assertEqual(updated_name, response.data.get("name"))

    def test_update_policy_bad_group(self):
        """Test that we cannot update an existing policy with a bad group."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])
        updated_name = policy_name + "_update"
        policy_uuid = response.data.get("uuid")
        test_data = response.data
        test_data["name"] = updated_name
        test_data["group"] = uuid4()
        test_data["roles"] = [role_uuid]
        del test_data["uuid"]
        url = reverse("policy-detail", kwargs={"uuid": policy_uuid})
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_policy_bad_role(self):
        """Test that we cannot update an existing policy with a bad role."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])
        updated_name = policy_name + "_update"
        policy_uuid = response.data.get("uuid")
        test_data = response.data
        test_data["name"] = updated_name
        test_data["group"] = self.group.uuid
        test_data["roles"] = [uuid4()]
        del test_data["uuid"]
        url = reverse("policy-detail", kwargs={"uuid": policy_uuid})
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_policy_no_role(self):
        """Test that we can update an existing policy to have no roles."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])
        updated_name = policy_name + "_update"
        policy_uuid = response.data.get("uuid")
        test_data = response.data
        test_data["name"] = updated_name
        test_data["group"] = self.group.uuid
        test_data["roles"] = []
        del test_data["uuid"]
        url = reverse("policy-detail", kwargs={"uuid": policy_uuid})
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_policy_invalid(self):
        """Test that updating an invalid policy returns an error."""
        url = reverse("policy-detail", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.put(url, {}, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_role_success(self):
        """Test that we can delete an existing role."""
        role_name = "roleA"
        response = self.create_role(role_name)
        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])
        policy_uuid = response.data.get("uuid")
        url = reverse("policy-detail", kwargs={"uuid": policy_uuid})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # verify the policy no longer exists
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_policy_invalid(self):
        """Test that deleting an invalid policy returns an error."""
        url = reverse("policy-detail", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_policy_removed_on_group_deletion(self):
        """Test that we can an existing policy is cleaned up when the group is deleted."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])
        policy_uuid = response.data.get("uuid")

        url = reverse("group-detail", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        response = client.delete(url, **self.headers)

        url = reverse("policy-detail", kwargs={"uuid": policy_uuid})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_policy_removed_on_all_role_deletion(self):
        """Test that we can an existing policy is cleaned up when the all roles are deleted."""
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        role_uuid = response.data.get("uuid")
        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])
        policy_uuid = response.data.get("uuid")

        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        response = client.delete(url, **self.headers)

        url = reverse("policy-detail", kwargs={"uuid": policy_uuid})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_policy_removed_on_one_role_deletion(self):
        """Test that we can an existing policy remains when not all roles are deleted."""
        roles = []
        role_name = "roleA"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        roles.append(response.data.get("uuid"))

        role_name = "roleB"
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        roles.append(response.data.get("uuid"))

        policy_name = "policyA"
        response = self.create_policy(policy_name, self.group.uuid, roles)
        policy_uuid = response.data.get("uuid")

        url = reverse("role-detail", kwargs={"uuid": roles[0]})
        client = APIClient()
        response = client.delete(url, **self.headers)

        url = reverse("policy-detail", kwargs={"uuid": policy_uuid})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
