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
"""Test the role viewset."""

from uuid import uuid4

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from api.models import User
from management.models import Group, Permission, Principal, Role, Access, Policy, ResourceDefinition
from tests.identity_request import IdentityRequest
from unittest.mock import patch


URL = reverse("role-list")


class RoleViewsetTests(IdentityRequest):
    """Test the role viewset."""

    def setUp(self):
        """Set up the role viewset tests."""
        super().setUp()
        request = self.request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        request.user = user

        sys_role_config = {"name": "system_role", "display_name": "system_display", "system": True}

        def_role_config = {"name": "default_role", "display_name": "default_display", "platform_default": True}

        admin_def_role_config = {
            "name": "admin_default_role",
            "display_name": "admin_default_display",
            "system": True,
            "admin_default": True,
        }

        self.display_fields = {
            "applications",
            "description",
            "uuid",
            "name",
            "display_name",
            "system",
            "created",
            "policyCount",
            "accessCount",
            "modified",
            "platform_default",
            "admin_default",
        }

        self.principal = Principal(username=self.user_data["username"], tenant=self.tenant)
        self.principal.save()
        self.policy = Policy.objects.create(name="policyA", tenant=self.tenant)
        self.group = Group(name="groupA", description="groupA description", tenant=self.tenant)
        self.group.save()
        self.group.principals.add(self.principal)
        self.group.policies.add(self.policy)
        self.group.save()

        self.adminRole = Role(**admin_def_role_config, tenant=self.tenant)
        self.adminRole.save()

        self.sysRole = Role(**sys_role_config, tenant=self.tenant)
        self.sysRole.save()

        self.defRole = Role(**def_role_config, tenant=self.tenant)
        self.defRole.save()
        self.defRole.save()

        self.policy.roles.add(self.defRole, self.sysRole, self.adminRole)
        self.policy.save()

        self.permission = Permission.objects.create(permission="app:*:*", tenant=self.tenant)
        self.permission2 = Permission.objects.create(permission="app2:*:*", tenant=self.tenant)
        self.permission3 = Permission.objects.create(permission="app:*:read", tenant=self.tenant)
        self.permission.permissions.add(self.permission3)
        self.access = Access.objects.create(permission=self.permission, role=self.defRole, tenant=self.tenant)
        self.access2 = Access.objects.create(permission=self.permission2, role=self.defRole, tenant=self.tenant)

        self.access3 = Access.objects.create(permission=self.permission2, role=self.sysRole, tenant=self.tenant)
        Permission.objects.create(permission="cost-management:*:*", tenant=self.tenant)

    def create_role(self, role_name, role_display="", in_access_data=None):
        """Create a role."""
        access_data = [
            {
                "permission": "app:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "key1", "operation": "equal", "value": "value1"}}],
            },
            {"permission": "app:*:read", "resourceDefinitions": []},
        ]
        if in_access_data:
            access_data = in_access_data
        test_data = {"name": role_name, "display_name": role_display, "access": access_data}

        # create a role
        client = APIClient()
        response = client.post(URL, test_data, format="json", **self.headers)
        return response

    def test_create_role_success(self):
        """Test that we can create a role."""
        role_name = "roleA"
        access_data = [
            {
                "permission": "app:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
            },
            {"permission": "app:*:read", "resourceDefinitions": []},
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # test that we can retrieve the role
        url = reverse("role-detail", kwargs={"uuid": response.data.get("uuid")})
        client = APIClient()
        response = client.get(url, **self.headers)
        uuid = response.data.get("uuid")
        role = Role.objects.get(uuid=uuid)

        self.assertIsNotNone(uuid)
        self.assertIsNotNone(response.data.get("name"))
        self.assertEqual(role_name, response.data.get("name"))
        self.assertIsNotNone(response.data.get("display_name"))
        self.assertEqual(role_name, response.data.get("display_name"))
        self.assertIsInstance(response.data.get("access"), list)
        self.assertEqual(access_data, response.data.get("access"))
        self.assertEqual(role.tenant, self.tenant)
        for access in role.access.all():
            self.assertEqual(access.tenant, self.tenant)
            for rd in ResourceDefinition.objects.filter(access=access):
                self.assertEqual(rd.tenant, self.tenant)

    def test_create_role_with_display_success(self):
        """Test that we can create a role."""
        role_name = "roleD"
        role_display = "display name for roleD"
        access_data = [
            {
                "permission": "app:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
            },
            {"permission": "app:*:read", "resourceDefinitions": []},
        ]
        response = self.create_role(role_name, role_display=role_display, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # test that we can retrieve the role
        url = reverse("role-detail", kwargs={"uuid": response.data.get("uuid")})
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertIsNotNone(response.data.get("uuid"))
        self.assertIsNotNone(response.data.get("name"))
        self.assertEqual(role_name, response.data.get("name"))
        self.assertIsNotNone(response.data.get("display_name"))
        self.assertEqual(role_display, response.data.get("display_name"))
        self.assertIsInstance(response.data.get("access"), list)
        self.assertEqual(access_data, response.data.get("access"))

    def test_create_role_without_required_permission(self):
        """Test that creating a role with dependent permissions not supplied, fails."""
        role_name = "roleWithDependentPermissions"
        access_data = [
            {
                "permission": self.permission.permission,
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("errors")[0].get("detail"),
            f"Permission '{self.permission.permission}' requires: '['{self.permission3.permission}']'",
        )

    def test_create_role_invalid(self):
        """Test that creating an invalid role returns an error."""
        test_data = {}
        client = APIClient()
        response = client.post(URL, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_role_invalid_permission(self):
        """Test that creating a role with invalid access permission returns an error."""
        test_data = {"name": "role1", "access": [{"permission": "foo:bar", "resourceDefinitions": []}]}
        client = APIClient()
        response = client.post(URL, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_role_empty_application_in_permission(self):
        """Test that creating a role with empty application in access permission returns an error."""
        test_data = {"name": "role1", "access": [{"permission": ":foo:bar", "resourceDefinitions": []}]}
        client = APIClient()
        response = client.post(URL, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_role_allow_list(self):
        """Test that we can create a role in an allow_listed application via API."""
        role_name = "C-MRole"
        access_data = [
            {
                "permission": "cost-management:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # test that we can retrieve the role
        url = reverse("role-detail", kwargs={"uuid": response.data.get("uuid")})
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertIsNotNone(response.data.get("uuid"))
        self.assertIsNotNone(response.data.get("name"))
        self.assertEqual(role_name, response.data.get("name"))
        self.assertIsInstance(response.data.get("access"), list)
        self.assertEqual(access_data, response.data.get("access"))

    def test_create_role_allow_list_fail(self):
        """Test that we cannot create a role for a non-allow_listed app."""
        role_name = "roleFail"
        access_data = [
            {
                "permission": "someApp:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_role_appfilter_structure_fail(self):
        """Test that we cannot create a role with invalid structure of resource definition."""
        role_name = "operationFail"
        access_data = [
            {
                "permission": "cost-management:*:*",
                "resourceDefinitions": {"attributeFilter": {"key": "keyA", "operation": "in", "foo": "valueA"}},
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["errors"][0]["detail"].code, "not_a_list")

    def test_create_role_appfilter_fields_fail(self):
        """Test that we cannot create a role with an invalid key in the attributeFilter object."""
        role_name = "operationFail"
        access_data = [
            {
                "permission": "cost-management:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "in", "foo": "valueA"}}],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_role_appfilter_operation_fail(self):
        """Test that we cannot create a role with an invalid operation."""
        role_name = "operationFail"
        access_data = [
            {
                "permission": "cost-management:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "boop", "value": "valueA"}}],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_role_permission_does_not_exist_fail(self):
        """Test that we cannot create a role with a permission that doesn't exist."""
        role_name = "roleFailPermission"
        permission = "cost-management:foo:bar"
        access_data = [
            {
                "permission": permission,
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), f"Permission does not exist: {permission}")

    def test_create_role_fail_with_access_not_list(self):
        """Test that we cannot create a role for a non-allow_listed app."""
        role_name = "AccessNotList"
        access_data = "some data"
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_role_fail_with_invalid_access(self):
        """Test that we cannot create a role for invalid access data."""
        role_name = "AccessInvalid"
        access_data = [{"per": "some data"}]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_role_invalid(self):
        """Test that reading an invalid role returns an error."""
        url = reverse("role-detail", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_read_role_valid(self):
        """Test that reading a valid role returns expected fields/values."""
        url = reverse("role-detail", kwargs={"uuid": self.defRole.uuid})
        client = APIClient()
        response = client.get(url, **self.headers)
        response_data = response.data
        expected_fields = self.display_fields
        expected_fields.add("access")
        self.assertEqual(expected_fields, set(response_data.keys()))
        self.assertEqual(response_data.get("uuid"), str(self.defRole.uuid))
        self.assertEqual(response_data.get("name"), self.defRole.name)
        self.assertEqual(response_data.get("display_name"), self.defRole.display_name)
        self.assertEqual(response_data.get("description"), self.defRole.description)
        self.assertCountEqual(response_data.get("applications"), ["app", "app2"])
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_read_role_access_success(self):
        """Test that reading a valid role returns access."""
        url = reverse("role-access", kwargs={"uuid": self.defRole.uuid})
        client = APIClient()
        response = client.get(url, **self.headers)

        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 2)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_read_role_access_invalid_uuid(self):
        """Test that reading a non-existent role uuid returns an error."""
        url = reverse("role-access", kwargs={"uuid": "abc-123"})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_role_access_not_found_uuid(self):
        """Test that reading an invalid role uuid returns an error."""
        url = reverse("role-access", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_read_role_list_success(self):
        """Test that we can read a list of roles."""
        role_name = "roleA"
        role_display = "Display name for roleA"
        response = self.create_role(role_name, role_display=role_display)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")

        # list a role
        client = APIClient()
        response = client.get(URL, **self.headers)

        # three parts in response: meta, links and data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 4)

        role = None

        for iterRole in response.data.get("data"):
            self.assertIsNotNone(iterRole.get("name"))
            # fields displayed are same as defined
            self.assertEqual(self.display_fields, set(iterRole.keys()))
            if iterRole.get("name") == role_name:
                self.assertEqual(iterRole.get("accessCount"), 2)
                role = iterRole
        self.assertEqual(role.get("name"), role_name)
        self.assertEqual(role.get("display_name"), role_display)

    def test_get_role_by_application_single(self):
        """Test that getting roles by application returns roles based on permissions."""
        url = "{}?application={}".format(URL, "app")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        self.assertEqual(response.data.get("data")[0].get("name"), self.defRole.name)

    def test_get_role_by_application_multiple(self):
        """Test that getting roles by multiple applications returns roles based on permissions."""
        url = "{}?application={}".format(URL, "app2")
        client = APIClient()
        response = client.get(url, **self.headers)
        role_names = [role.get("name") for role in response.data.get("data")]
        self.assertEqual(response.data.get("meta").get("count"), 2)
        self.assertCountEqual(role_names, [self.defRole.name, self.sysRole.name])

    def test_get_role_by_application_duplicate_role(self):
        """Test that getting roles by application with permissions in the same role only returns the roles once."""
        url = "{}?application={}".format(URL, "app,app2")
        client = APIClient()
        response = client.get(url, **self.headers)
        role_names = [role.get("name") for role in response.data.get("data")]
        self.assertEqual(response.data.get("meta").get("count"), 2)
        self.assertCountEqual(role_names, [self.defRole.name, self.sysRole.name])

    def test_get_role_by_application_does_not_exist(self):
        """Test that getting roles by application returns nothing when there is no match."""
        url = "{}?application={}".format(URL, "foo")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 0)

    def test_get_role_by_permission_single(self):
        """Test that getting roles by permission returns roles based on permissions."""
        url = "{}?permission={}".format(URL, "app:*:*")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        self.assertEqual(response.data.get("data")[0].get("name"), self.defRole.name)

    def test_get_role_by_duplicate_permission(self):
        """Test that getting roles by duplicate permissions in the same role only returns the roles once."""
        url = "{}?permission={}".format(URL, "app2:*:*")
        client = APIClient()
        response = client.get(url, **self.headers)
        role_names = [role.get("name") for role in response.data.get("data")]
        self.assertEqual(response.data.get("meta").get("count"), 2)
        self.assertCountEqual(role_names, [self.defRole.name, self.sysRole.name])

    def test_get_role_by_permission_multiple(self):
        """Test that getting roles by permissions ."""
        url = "{}?permission={}".format(URL, "app:*:*,app2:*:*")
        client = APIClient()
        response = client.get(url, **self.headers)
        role_names = [role.get("name") for role in response.data.get("data")]
        self.assertEqual(response.data.get("meta").get("count"), 2)
        self.assertCountEqual(role_names, [self.defRole.name, self.sysRole.name])

    def test_get_role_by_permission_does_not_exist(self):
        """Test that getting roles by permission returns nothing when there is no match."""
        url = "{}?permission={}".format(URL, "foo:foo:foo")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 0)

    def test_get_role_by_partial_name_by_default(self):
        """Test that getting roles by name returns partial match by default."""
        url = "{}?name={}".format(URL, "role")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 3)

    def test_get_role_by_partial_name_explicit(self):
        """Test that getting roles by name returns partial match when specified."""
        url = "{}?name={}&name_match={}".format(URL, "role", "partial")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 3)

    def test_get_role_by_name_invalid_criteria(self):
        """Test that getting roles by name fails with invalid name_match."""
        url = "{}?name={}&name_match={}".format(URL, "role", "bad_criteria")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_role_by_exact_name_match(self):
        """Test that getting roles by name returns exact match."""
        url = "{}?name={}&name_match={}".format(URL, self.sysRole.name, "exact")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        role = response.data.get("data")[0]
        self.assertEqual(role.get("name"), self.sysRole.name)

    def test_get_role_by_exact_name_no_match(self):
        """Test that getting roles by name returns no results with exact match."""
        url = "{}?name={}&name_match={}".format(URL, "role", "exact")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 0)

    def test_get_role_by_partial_display_name_by_default(self):
        """Test that getting roles by display_name returns partial match by default."""
        url = "{}?display_name={}".format(URL, "display")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 3)

    def test_get_role_by_partial_display_name_explicit(self):
        """Test that getting roles by display_name returns partial match when specified."""
        url = "{}?display_name={}&name_match={}".format(URL, "display", "partial")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 3)

    def test_get_role_by_display_name_invalid_criteria(self):
        """Test that getting roles by display_name fails with invalid name_match."""
        url = "{}?display_name={}&name_match={}".format(URL, "display", "bad_criteria")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_role_by_exact_display_name_match(self):
        """Test that getting roles by display_name returns exact match."""
        url = "{}?display_name={}&name_match={}".format(URL, self.sysRole.display_name, "exact")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        role = response.data.get("data")[0]
        self.assertEqual(role.get("display_name"), self.sysRole.display_name)

    def test_get_role_by_exact_display_name_no_match(self):
        """Test that getting roles by display_name returns no results with exact match."""
        url = "{}?display_name={}&name_match={}".format(URL, "display", "exact")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 0)

    def test_list_role_with_additional_fields_success(self):
        """Test that we can read a list of roles and add fields."""
        role_name = "roleA"
        field_1 = "groups_in_count"
        field_2 = "groups_in"
        new_diaplay_fields = self.display_fields
        new_diaplay_fields.add(field_1)
        new_diaplay_fields.add(field_2)

        # list a role
        url = "{}?add_fields={},{}".format(URL, field_1, field_2)
        client = APIClient()
        response = client.get(url, **self.headers)

        # three parts in response: meta, links and data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)

        role = None

        for iterRole in response.data.get("data"):
            # fields displayed are same as defined, groupsInCount is added
            self.assertEqual(new_diaplay_fields, set(iterRole.keys()))
            if iterRole.get("name") == role_name:
                self.assertEqual(iterRole.get("accessCount"), 1)
                role = iterRole

            self.assertIsNotNone(iterRole.get("groups_in")[0]["name"])
            self.assertIsNotNone(iterRole.get("groups_in")[0]["uuid"])
            self.assertIsNotNone(iterRole.get("groups_in")[0]["description"])

    def test_list_role_with_username_forbidden_to_nonadmin(self):
        """Test that non admin can not read a list of roles for username."""
        # Setup non admin request
        non_admin_request_context = self._create_request_context(
            self.customer_data, self.user_data, create_customer=False, is_org_admin=False
        )
        non_admin_request = non_admin_request_context["request"]

        url = "{}?username={}".format(URL, self.user_data["username"])
        client = APIClient()
        response = client.get(url, **non_admin_request.META)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_list_role_fail_with_invalid_username(self, mock_request):
        """Test that non admin can not read a list of roles for username."""
        url = "{}?username={}".format(URL, "foo")
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_list_role_with_additional_fields_username_success(self):
        """Test that we can read a list of roles and add fields for username."""
        field_1 = "groups_in_count"
        field_2 = "groups_in"
        new_diaplay_fields = self.display_fields
        new_diaplay_fields.add(field_1)
        new_diaplay_fields.add(field_2)

        url = "{}?add_fields={},{}&username={}".format(URL, field_1, field_2, self.user_data["username"])
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 3)

        role = response.data.get("data")[0]
        self.assertEqual(new_diaplay_fields, set(role.keys()))
        self.assertEqual(role["groups_in_count"], 1)

    def test_list_role_with_additional_fields_principal_success(self):
        """Test that we can read a list of roles and add fields for principal."""
        field_1 = "groups_in_count"
        field_2 = "groups_in"
        new_diaplay_fields = self.display_fields
        new_diaplay_fields.add(field_1)
        new_diaplay_fields.add(field_2)

        url = "{}?add_fields={},{}&scope=principal".format(URL, field_1, field_2)
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 3)

        role = response.data.get("data")[0]
        self.assertEqual(new_diaplay_fields, set(role.keys()))
        self.assertEqual(role["groups_in_count"], 1)

    def test_list_role_with_invalid_additional_fields(self):
        """Test that invalid additional fields will raise exception."""
        add_field = "invalid_field"

        # list a role
        url = "{}?add_fields={}".format(URL, add_field)
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_list_role_with_invalid_sort_order(self):
        """Test that an invalid sort order is ignored."""
        url = "{}?sort_field=zombie".format(URL)
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_patch_role_success(self):
        """Test that we can patch an existing role."""
        role_name = "role"
        response = self.create_role(role_name)
        updated_name = role_name + "_update"
        updated_description = role_name + "This is a test"
        role_uuid = response.data.get("uuid")
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        response = client.patch(
            url,
            {"name": updated_name, "display_name": updated_name, "description": updated_description},
            format="json",
            **self.headers,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIsNotNone(response.data.get("uuid"))
        self.assertEqual(updated_name, response.data.get("name"))
        self.assertEqual(updated_name, response.data.get("display_name"))
        self.assertEqual(updated_description, response.data.get("description"))

    def test_patch_role_failure(self):
        """Test that we return a 400 with invalid fields in the patch."""
        role_name = "role"
        response = self.create_role(role_name)
        updated_name = role_name + "_update"
        updated_description = role_name + "This is a test"
        role_uuid = response.data.get("uuid")
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        response = client.patch(
            url,
            {"name": updated_name, "display_name": updated_name, "description": updated_description, "foo": "bar"},
            format="json",
            **self.headers,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_role_success(self):
        """Test that we can update an existing role."""
        role_name = "roleA"
        response = self.create_role(role_name)
        updated_name = role_name + "_update"
        role_uuid = response.data.get("uuid")
        test_data = response.data
        test_data["name"] = updated_name
        test_data["access"][0]["permission"] = "cost-management:*:*"
        del test_data["uuid"]
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIsNotNone(response.data.get("uuid"))
        self.assertEqual(updated_name, response.data.get("name"))
        self.assertEqual("cost-management:*:*", response.data.get("access")[0]["permission"])

    def test_update_role_invalid(self):
        """Test that updating an invalid role returns an error."""
        url = reverse("role-detail", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.put(
            url,
            {"name": "updated_name", "display_name": "updated_name", "description": "updated_description"},
            format="json",
            **self.headers,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_role_invalid_permission(self):
        """Test that updating a role with an invalid permission returns an error."""
        # Set up
        role_name = "permRole"
        access_data = [
            {
                "permission": "cost-management:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        test_data = response.data
        test_data.get("access")[0]["permission"] = "foo:*:read"
        test_data["applications"] = ["foo"]

        # Test update failure
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_role_invalid_resource_defs_structure(self):
        """Test that updating a role with an invalid resource definitions returns an error."""
        # Set up
        role_name = "permRole"
        access_data = [
            {
                "permission": "cost-management:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        test_data = response.data
        test_data.get("access")[0]["resourceDefinitions"] = {
            "attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}
        }

        # Test update failure
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["errors"][0]["detail"].code, "not_a_list")

    def test_update_role_appfilter_operation_fail(self):
        # Set up
        role_name = "permRole"
        access_data = [
            {
                "permission": "cost-management:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        test_data = response.data
        test_data.get("access")[0]["resourceDefinitions"][0].get("attributeFilter")["operation"] = "foo"

        # Test update failure
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data["errors"][0]["detail"]), "attributeFilter operation must be one of ['in', 'equal']"
        )

    def test_update_role_permission_does_not_exist_fail(self):
        """Test that we cannot update a role with a permission that doesn't exist."""
        # Set up
        role_name = "permRole"
        permission = "cost-management:foo:bar"
        access_data = [
            {
                "permission": "cost-management:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA", "operation": "equal", "value": "valueA"}}],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        test_data = response.data
        test_data.get("access")[0]["permission"] = permission
        test_data["applications"] = ["foo"]

        # Test update failure
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), f"Permission does not exist: {permission}")

    def test_delete_role_success(self):
        """Test that we can delete an existing role."""
        role_name = "roleA"
        response = self.create_role(role_name)

        role_uuid = response.data.get("uuid")
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # verify the role no longer exists
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_system_role(self):
        """Test that system roles are protected from deletion"""
        url = reverse("role-detail", kwargs={"uuid": self.sysRole.uuid})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # verify the role still exists
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_admin_default_role(self):
        """Test that admin default roles are protected from deletion"""
        url = reverse("role-detail", kwargs={"uuid": self.adminRole.uuid})
        client = APIClient()
        access_data = [
            {
                "admin_default": True,
                "permission": "app:*:*",
                "resourceDefinitions": [{"attributeFilter": {"key": "key1", "operation": "equal", "value": "value1"}}],
            },
            {"permission": "app:*:read", "resourceDefinitions": []},
        ]

        test_data = {"name": "role_name", "display_name": "role_display", "access": access_data}
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_default_role(self):
        """Test that default roles are protected from deletion"""
        url = reverse("role-detail", kwargs={"uuid": self.defRole.uuid})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # verify the role still exists
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_role_invalid(self):
        """Test that deleting an invalid role returns an error."""
        url = reverse("role-detail", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_system_flag_filter(self):
        """Test that we can filter roles based on system flag."""
        client = APIClient()
        response = client.get(URL, **self.headers)

        self.assertEqual(len(response.data.get("data")), 3)

        url = f"{URL}?system=true"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 2)
        role = response.data.get("data")[0]
        self.assertEqual(role.get("system"), True)

        url = f"{URL}?system=false"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 1)
        role = response.data.get("data")[0]
        self.assertEqual(role.get("system"), False)
