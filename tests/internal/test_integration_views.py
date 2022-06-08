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
"""Test the internal viewset."""
import uuid
from rest_framework import status
from rest_framework.test import APIClient
from unittest.mock import patch

from api.models import User
from management.models import Group, Policy, Principal, Role
from tests.identity_request import IdentityRequest


class IntegrationViewsTests(IdentityRequest):
    """Test the integration views."""

    def setUp(self):
        """Set up the integration view tests."""
        test_roles = ["Role Admin", "Role A", "Role B"]
        test_principals = ["user_admin", "user_a", "user_b"]

        super().setUp()
        self.client = APIClient()
        self.customer = self.customer_data
        self.internal_request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, is_internal=True, create_tenant=False
        )

        self.request = self.internal_request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        self.request.user = user

        for username in test_principals:
            principal = Principal.objects.create(username=username, tenant=self.tenant)
            principal.save()

        for role_name in test_roles:
            role = Role.objects.create(
                name=role_name, description="A role for a group.", system=True, tenant=self.tenant
            )
            role.save()

        group = Group(name="Group Admin", system=True, tenant=self.tenant)
        group.save()
        group.principals.add(Principal.objects.get(username="user_admin"))
        policy = Policy.objects.create(name="Admin Policy", group=group, tenant=self.tenant)
        policy.roles.add(Role.objects.get(name="Role Admin"))
        policy.save()
        group.policies.add(policy)
        group.save()

        group = Group(name="Group All", system=True, tenant=self.tenant)
        group.save()
        for principal in test_principals:
            group.principals.add(Principal.objects.get(username=principal))
        policy = Policy.objects.create(name="All Policy", group=group, tenant=self.tenant)
        for role in test_roles:
            policy.roles.add(Role.objects.get(name=role))
        group.policies.add(policy)
        group.save()

        group = Group(name="Group A", system=True, tenant=self.tenant)
        group.save()
        group.principals.add(Principal.objects.get(username="user_admin"))
        group.principals.add(Principal.objects.get(username="user_a"))
        policy = Policy.objects.create(name="A Policy", group=group, tenant=self.tenant)
        policy.roles.add(Role.objects.get(name="Role A"))
        group.policies.add(policy)
        group.save

    def tearDown(self):
        """Tear down internal viewset tests."""
        Group.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "user_admin",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_groups_valid_account(self, mock_request):
        """Test that a request to /tenant/<id>/groups/?username= from an internal account works."""
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/groups/?username=user_admin",
            **self.request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Expecting ["Group All", "Group A", "Group Admin"]
        self.assertEqual(response.data.get("meta").get("count"), 3)

    def test_groups_invalid_account(self):
        """Test that a /tenant/<id>/groups/?username= request from an external account fails."""
        external_request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, is_internal=False, create_tenant=False
        )
        request = external_request_context["request"]
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/groups/?username=user_a", **request.META, follow=True
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "user_a",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_groups_user_filter(self, mock_request):
        """Test that only the groups a user is a member of are returned for a /tenant/<id>/groups/?username= request."""
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/groups/?username=user_a", **self.request.META, follow=True
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Expecting ["Group All", "Group A"]
        expected = []
        expected.append(Group.objects.get(name="Group A"))
        expected.append(Group.objects.get(name="Group All"))
        self.assertEqual(response.data.get("meta").get("count"), 2)
        self.assertTrue(expected, response.data)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_groups_nonexistent_user(self, mock_request):
        """Test that a request for groups of a nonexistent user returns 0."""
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/groups/?username=user_x", **self.request.META, follow=True
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_groups_for_principal_valid_account(self):
        """Test that a request to /tenant/<id>/principal/<username>/groups/ from an internal account works."""
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/principal/user_admin/groups/",
            **self.request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Expecting ["Group All", "Group A", "Group Admin"]
        self.assertEqual(response.data.get("meta").get("count"), 3)

    def test_groups_for_principal_invalid_account(self):
        """Test that a /tenant/<id>/principal/<username>groups/ request from an external account fails."""
        external_request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, is_internal=False, create_tenant=False
        )
        request = external_request_context["request"]
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/principal/user_a/groups/", **request.META, follow=True
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "user_a",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_groups_for_principal_filter(self, mock_request):
        """Test that only the groups a user is a member of are returned for a /tenant/<id>/groups/?username= request."""
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/groups/?username=user_a", **self.request.META, follow=True
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Expecting ["Group All", "Group A"]
        self.assertEqual(response.data.get("meta").get("count"), 2)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_groups_for_principal_nonexistant_user(self, mock_request):
        """Test that an error is return for nonexistant ."""
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/groups/?username=user_x", **self.request.META, follow=True
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_roles_from_group_valid(self):
        """Test that a valid request to /tenant/<id>/groups/<uuid>/roles/ from an internal account works."""
        group_all_uuid = Group.objects.get(name="Group All").uuid
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/groups/{group_all_uuid}/roles/",
            **self.request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Expecting ["Role Admin", "Role A", "Role B"]
        self.assertEqual(response.data.get("meta").get("count"), 3)

    def test_roles_from_group_invalid_uuid(self):
        """Test that a request to /tenant/<id>/groups/<uuid>/roles/ with an invalid uuid fails."""
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/groups/{uuid.uuid4}/roles/",
            **self.request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_roles_from_group_invalid_account(self):
        """Test that a /tenant/<id>/groups/<uuid>/roles/ request from an external account fails."""
        group_all_uuid = Group.objects.get(name="Group All").uuid
        external_request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, is_internal=False, create_tenant=False
        )
        request = external_request_context["request"]
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/groups/{group_all_uuid}/roles/",
            **request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_roles_from_group_filter(self):
        """Test that a valid request to /tenant/<id>/groups/<uuid>/roles/ from an internal properly filters groups."""
        group_a_uuid = Group.objects.get(name="Group A").uuid
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/groups/{group_a_uuid}/roles/",
            **self.request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Expecting ["Role A"]
        self.assertEqual(response.data.get("meta").get("count"), 1)

    def test_roles_for_group_principal_valid(self):
        """Test that a valid request to /tenant/<id>/principal/user_admin/groups/<uuid>/roles/ from an internal account works."""
        group_all_uuid = Group.objects.get(name="Group All").uuid
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/principal/user_admin/groups/{group_all_uuid}/roles/",
            **self.request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Expecting ["Role Admin", "Role A", "Role B"]
        self.assertEqual(response.data.get("meta").get("count"), 3)

    def test_roles_for_group_principal_invalid_account(self):
        """Test that a valid request to /tenant/<id>/principal/user_admin/groups/<uuid>/roles/ from an external account fails."""
        group_all_uuid = Group.objects.get(name="Group All").uuid
        external_request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, is_internal=False, create_tenant=False
        )
        request = external_request_context["request"]
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/principal/user_admin/groups/{group_all_uuid}/roles/",
            **request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_roles_for_group_principal_invalid_uuid(self):
        """Test that a request to /tenant/<id>/principal/user_admin/groups/<uuid>/roles/ with an invalid uuid fails."""
        group_all_uuid = Group.objects.get(name="Group All").uuid
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/principal/user_admin/groups/{uuid.uuid4}/roles/",
            **self.request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_roles_for_group_principal_filter(self):
        """Test that a valid request to /tenant/<id>/principal/user_admin/groups/<uuid>/roles/ filters properly."""
        # user_a in Group A
        group_a_uuid = Group.objects.get(name="Group A").uuid
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/principal/user_a/groups/{group_a_uuid}/roles/",
            **self.request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Expecting ["Role A"]
        self.assertEqual(response.data.get("meta").get("count"), 1)

        # user_b not in Group A
        group_a_uuid = Group.objects.get(name="Group A").uuid
        response = self.client.get(
            f"/_private/api/tenant/{self.tenant.org_id}/principal/user_b/groups/{group_a_uuid}/roles/",
            **self.request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
