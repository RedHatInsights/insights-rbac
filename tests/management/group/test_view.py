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
"""Test the group viewset."""
import random
from unittest.mock import call, patch, ANY, Mock
from uuid import uuid4

from django.db import transaction
from django.conf import settings
from django.urls import reverse, resolve
from django.test.utils import override_settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APIClient

from api.models import Tenant, User
from management.cache import TenantCache
from management.group.serializer import GroupInputSerializer
from management.models import (
    Access,
    BindingMapping,
    Group,
    Permission,
    Principal,
    Policy,
    Role,
    ExtRoleRelation,
    ExtTenant,
)
from tests.core.test_kafka import copy_call_args
from tests.identity_request import IdentityRequest
from tests.management.role.test_view import find_in_list, relation_api_tuple


def generate_relation_entry(group_uuid, principal_uuid):
    relation_entry = {"resource": {}}

    relation_entry["resource"]["type"] = {}
    relation_entry["resource"]["type"]["namespace"] = "rbac"
    relation_entry["resource"]["type"]["name"] = "group"
    relation_entry["resource"]["id"] = group_uuid

    relation_entry["relation"] = "member"

    relation_entry["subject"] = {}
    relation_entry["subject"]["subject"] = {}
    relation_entry["subject"]["subject"]["type"] = {}
    relation_entry["subject"]["subject"]["type"]["namespace"] = "rbac"
    relation_entry["subject"]["subject"]["type"]["name"] = "principal"
    relation_entry["subject"]["subject"]["id"] = principal_uuid

    return relation_entry


def replication_event(relations_to_add, relations_to_remove):
    """Create a replication event for a v1 role."""
    return {
        "relations_to_add": relations_to_add,
        "relations_to_remove": relations_to_remove,
    }


def generate_replication_event_to_add_principals(group_uuid, principal_uuid):
    return {"relations_to_add": [generate_relation_entry(group_uuid, principal_uuid)], "relations_to_remove": []}


def generate_replication_event_to_remove_principals(group_uuid, principal_uuid):
    return {"relations_to_add": [], "relations_to_remove": [generate_relation_entry(group_uuid, principal_uuid)]}


def find_relation_in_list(relation_list, relation_tuple):
    return find_in_list(
        relation_list,
        lambda r: r["resource"]["type"]["name"] == relation_tuple["resource"]["type"]["name"]
        and r["resource"]["id"] == relation_tuple["resource"]["id"]
        and r["relation"] == relation_tuple["relation"]
        and r["subject"]["subject"]["type"]["name"] == relation_tuple["subject"]["subject"]["type"]["name"]
        and r["subject"]["subject"]["id"] == relation_tuple["subject"]["subject"]["id"],
    )


class GroupViewsetTests(IdentityRequest):
    """Test the group viewset."""

    def setUp(self):
        """Set up the group viewset tests."""
        super().setUp()
        request = self.request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        user.org_id = self.customer_data["org_id"]
        user.admin = True
        request.user = user

        self.dummy_role_id = uuid4()

        test_tenant_org_id = "100001"

        # we need to delete old test_tenant's that may exist in cache
        TENANTS = TenantCache()
        TENANTS.delete_tenant(test_tenant_org_id)

        self.test_tenant = Tenant(
            tenant_name="acct1111111", account_id="1111111", org_id=test_tenant_org_id, ready=True
        )
        self.test_tenant.save()
        self.test_principal = Principal(username="test_user", tenant=self.test_tenant)
        self.test_principal.save()
        self.test_principalB = Principal(username="mock_user", tenant=self.test_tenant)
        self.test_principalB.save()
        self.test_principalC = Principal(username="user_not_attached_to_group_explicitly", tenant=self.test_tenant)
        self.test_principalC.save()
        user_data = {"username": "test_user", "email": "test@gmail.com"}
        test_request_context = self._create_request_context(
            {"account_id": "1111111", "tenant_name": "acct1111111", "org_id": test_tenant_org_id},
            user_data,
            is_org_admin=True,
        )
        test_request = test_request_context["request"]
        self.test_headers = test_request.META

        self.public_tenant = Tenant.objects.get(tenant_name="public")
        self.principal = Principal(username=self.user_data["username"], tenant=self.tenant)
        self.principal.save()
        self.principalB = Principal(username="mock_user", tenant=self.tenant)
        self.principalB.save()
        self.principalC = Principal(username="user_not_attached_to_group_explicitly", tenant=self.tenant)
        self.principalC.save()
        self.group = Group(name="groupA", tenant=self.tenant)
        self.group.save()
        self.role = Role.objects.create(
            name="roleA", description="A role for a group.", system=True, tenant=self.tenant
        )
        self.ext_tenant = ExtTenant.objects.create(name="foo")
        self.ext_role_relation = ExtRoleRelation.objects.create(role=self.role, ext_tenant=self.ext_tenant)
        self.policy = Policy.objects.create(name="policyA", group=self.group, tenant=self.tenant)
        self.policy.roles.add(self.role)
        self.policy.save()
        self.group.policies.add(self.policy)
        self.group.principals.add(self.principal, self.principalB)
        self.group.save()

        self.defGroup = Group(name="groupDef", platform_default=True, system=True, tenant=self.public_tenant)
        self.defGroup.save()
        self.defGroup.principals.add(self.principal, self.test_principal)
        self.defGroup.save()
        self.defPolicy = Policy(name="defPolicy", system=True, tenant=self.public_tenant, group=self.defGroup)
        self.defPolicy.save()

        self.adminGroup = Group(name="groupAdmin", admin_default=True, tenant=self.public_tenant, system=True)
        self.adminGroup.save()
        self.adminGroup.principals.add(self.principal, self.test_principal)
        self.adminGroup.save()
        self.adminPolicy = Policy(name="adminPolicy", tenant=self.public_tenant, group=self.adminGroup)
        self.adminPolicy.save()

        self.emptyGroup = Group(name="groupE", tenant=self.tenant)
        self.emptyGroup.save()

        self.groupB = Group.objects.create(name="groupB", tenant=self.tenant)
        self.groupB.principals.add(self.principal, self.principal)
        self.policyB = Policy.objects.create(name="policyB", group=self.groupB, tenant=self.tenant)
        self.roleB = Role.objects.create(name="roleB", system=False, tenant=self.tenant)
        self.policyB.roles.add(self.roleB)
        self.policyB.save()

        # role that's not assigned to principal
        self.roleOrphan = Role.objects.create(name="roleOrphan", tenant=self.tenant)

        # group that associates with multiple roles
        self.groupMultiRole = Group.objects.create(name="groupMultiRole", tenant=self.tenant)
        self.policyMultiRole = Policy.objects.create(name="policyMultiRole", tenant=self.tenant)
        self.policyMultiRole.roles.add(self.role)
        self.policyMultiRole.roles.add(self.roleB)
        self.groupMultiRole.policies.add(self.policyMultiRole)

        # fixtures for Service Accounts
        self.sa_client_ids = [
            "b6636c60-a31d-013c-b93d-6aa2427b506c",
            "69a116a0-a3d4-013c-b940-6aa2427b506c",
            "6f3c2700-a3d4-013c-b941-6aa2427b506c",
        ]
        self.service_accounts = []
        for uuid in self.sa_client_ids:
            principal = Principal(
                username="service-account-" + uuid,
                tenant=self.tenant,
                type="service-account",
                service_account_id=uuid,
            )
            self.service_accounts.append(principal)
            principal.save()

        self.group.principals.add(*self.service_accounts)
        self.group.save()

    def tearDown(self):
        """Tear down group viewset tests."""
        Group.objects.all().delete()
        Principal.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_create_group_success(self, send_kafka_message, mock_request):
        """Test that we can create a group."""
        with self.settings(NOTIFICATIONS_ENABLED=True):
            group_name = "groupC"
            test_data = {"name": group_name}

            org_id = self.customer_data["org_id"]

            # create a group
            url = reverse("group-list")
            client = APIClient()
            response = client.post(url, test_data, format="json", **self.headers)
            uuid = response.data.get("uuid")
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

            # test that we can retrieve the group
            url = reverse("group-detail", kwargs={"uuid": response.data.get("uuid")})
            response = client.get(url, **self.headers)
            group = Group.objects.get(uuid=uuid)

            # test whether newly created group is added correctly within audit log database
            al_url = "/api/v1/auditlogs/"
            al_client = APIClient()
            al_response = al_client.get(al_url, **self.headers)
            retrieve_data = al_response.data.get("data")
            al_list = retrieve_data
            al_dict = al_list[0]

            al_dict_principal_username = al_dict["principal_username"]
            al_dict_description = al_dict["description"]
            al_dict_resource = al_dict["resource_type"]
            al_dict_action = al_dict["action"]

            self.assertEqual(self.user_data["username"], al_dict_principal_username)
            self.assertIsNotNone(al_dict_description)
            self.assertEqual(al_dict_resource, "group")
            self.assertEqual(al_dict_action, "create")

            # test that we can retrieve the role
            url = reverse("role-detail", kwargs={"uuid": response.data.get("uuid")})
            client = APIClient()
            self.assertIsNotNone(uuid)
            self.assertIsNotNone(response.data.get("name"))
            self.assertEqual(group_name, response.data.get("name"))
            self.assertEqual(group.tenant, self.tenant)
            send_kafka_message.assert_called_with(
                settings.NOTIFICATIONS_TOPIC,
                {
                    "bundle": "console",
                    "application": "rbac",
                    "event_type": "group-created",
                    "timestamp": ANY,
                    "events": [
                        {
                            "metadata": {},
                            "payload": {
                                "name": group_name,
                                "username": self.user_data["username"],
                                "uuid": str(group.uuid),
                            },
                        }
                    ],
                    "org_id": org_id,
                },
                ANY,
            )

    def test_create_default_group(self):
        """Test that system groups can be created."""
        group_name = "groupDef"

        # test group retrieval
        client = APIClient()
        url = reverse("group-detail", kwargs={"uuid": self.defGroup.uuid})
        response = client.get(url, **self.headers)

        self.assertIsNotNone(response.data.get("uuid"))
        self.assertIsNotNone(response.data.get("name"))
        self.assertTrue(response.data.get("platform_default"))
        self.assertEqual(group_name, response.data.get("name"))

    def test_create_group_invalid(self):
        """Test that creating an invalid group returns an error."""
        test_data = {}
        url = reverse("group-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_duplicate_group(self):
        """Test that creating a duplicate group is not allowed."""
        group_name = "groupC"
        test_data = {"name": group_name}

        # create a group
        with transaction.atomic():
            url = reverse("group-list")
            client = APIClient()
            response = client.post(url, test_data, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

            response = client.post(url, test_data, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_group_with_reserved_name(self):
        """Test that creating a group with reserved name is not allowed."""

        # create a group
        url = reverse("group-list")
        client = APIClient()

        test_data = {"name": "Custom default access"}
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        test_data = {"name": "default access"}
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_group_filter_by_any_role_name_in_a_list_success(self):
        """Test default behaviour that filter groups by any role name in a list success."""
        url = "{}?role_names={},{}".format(reverse("group-list"), "RoleA", "RoleB")
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertTrue(response.data.get("meta").get("count") == 3)

        expected_groups = [self.group.name, self.groupB.name, self.groupMultiRole.name]
        self.assertEqual(expected_groups, [group.get("name") for group in response.data.get("data")])

    def test_group_filter_by_all_role_name_in_a_list_success(self):
        """Test that filter groups by all role names in a list success."""
        url = "{}?role_names={},{}&role_discriminator=all".format(reverse("group-list"), "RoleA", "roleB")
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertTrue(response.data.get("meta").get("count") == 1)

        expected_groups = [self.groupMultiRole.name]
        self.assertEqual(expected_groups, [group.get("name") for group in response.data.get("data")])

    def test_group_filter_with_invalid_discriminator_failure(self):
        """Test that filter groups with invalid discriminator returns failed validation."""
        url = "{}?role_names={},{}&role_discriminator=invalid".format(reverse("group-list"), "roleA", "ROLEb")
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_group_filter_by_guids_with_invalid_guid(self):
        """Test that an invalid guid in a list of guids returns an error."""
        url = "{}?uuids=invalid"
        client = APIClient()
        response = client.get(url, **self.headers)
        # FIXME: This seems inconsistent with GUID validation we added elsewhere
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_read_group_success(self, mock_request):
        """Test that we can read a group."""
        url = reverse("group-detail", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get("name"))
        self.assertEqual(self.group.name, response.data.get("name"))
        self.assertEqual(len(response.data.get("roles")), 1)
        self.assertEqual(response.data.get("roles")[0]["uuid"], str(self.role.uuid))

    def test_read_group_invalid(self):
        """Test that reading an invalid group returns an error."""
        url = reverse("group-detail", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_read_group_nonguid(self):
        """Test that reading a group with an invalid UUID returns an error."""
        url = reverse("group-detail", kwargs={"uuid": "potato"})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_group_list_success(self):
        """Test that we can read a list of groups."""
        url = reverse("group-list")
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 6)

        group = response.data.get("data")[0]
        self.assertIsNotNone(group.get("name"))
        self.assertEqual(group.get("name"), self.group.name)

        # check that all fields from GroupInputSerializer are present
        for key in GroupInputSerializer().fields.keys():
            self.assertIn(key, group.keys())

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
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
                    "username": "user_based_principal",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    @patch(
        "management.principal.it_service.ITService.request_service_accounts",
        return_value=[
            {
                "clientId": "b7a82f30-bcef-013c-2452-6aa2427b506c",
                "name": f"service_account_name",
                "description": f"Service Account description",
                "owner": "jsmith",
                "username": "service_account-b7a82f30-bcef-013c-2452-6aa2427b506c",
                "time_created": 1706784741,
                "type": "service-account",
            }
        ],
    )
    def test_read_group_list_principalCount(self, mock_request, sa_mock_request):
        """Test that correct number is returned for principalCount."""
        # Create a test data - group with 1 user based and 1 service account principal
        group_name = "TestGroup"
        group = Group(name=group_name, tenant=self.tenant)
        group.save()

        user_based_principal = Principal(username="user_based_principal", tenant=self.test_tenant)
        user_based_principal.save()

        sa_uuid = "b7a82f30-bcef-013c-2452-6aa2427b506c"
        sa_based_principal = Principal(
            username="service_account-" + sa_uuid,
            tenant=self.tenant,
            type="service-account",
            service_account_id=sa_uuid,
        )
        sa_based_principal.save()

        group.principals.add(user_based_principal, sa_based_principal)
        self.group.save()

        # Test that /groups/{uuid}/principals/ returns correct count of user based principals
        url = f"{reverse('group-principals', kwargs={'uuid': group.uuid})}"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(int(response.data.get("meta").get("count")), 1)
        self.assertEqual(len(response.data.get("data")), 1)
        principal_out = response.data.get("data")[0]
        self.assertEqual(principal_out["username"], user_based_principal.username)

        # Test that /groups/{uuid}/principals/?principal_type=service-account returns
        # correct count of service account based principals
        url = f"{reverse('group-principals', kwargs={'uuid': group.uuid})}?principal_type=service-account"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(int(response.data.get("meta").get("count")), 1)
        self.assertEqual(len(response.data.get("data")), 1)
        sa_out = response.data.get("data")[0]
        self.assertEqual(sa_out["username"], sa_based_principal.username)

        # Test that /groups/?name=<group_name> returns 1 group with principalCount for only user based principals
        url = f"{reverse('group-list')}?name={group_name}"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

        group = response.data.get("data")[0]
        self.assertEqual(group["principalCount"], 1)

    def test_get_group_by_partial_name_by_default(self):
        """Test that getting groups by name returns partial match by default."""
        url = reverse("group-list")
        url = "{}?name={}".format(url, "group")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 6)

    def test_get_group_by_partial_name_explicit(self):
        """Test that getting groups by name returns partial match when specified."""
        url = reverse("group-list")
        url = "{}?name={}&name_match={}".format(url, "group", "partial")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 6)

    def test_get_group_by_name_invalid_criteria(self):
        """Test that getting groups by name fails with invalid name_match."""
        url = reverse("group-list")
        url = "{}?name={}&name_match={}".format(url, "group", "bad_criteria")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_group_by_exact_name_match(self):
        """Test that getting groups by name returns exact match."""
        url = reverse("group-list")
        url = "{}?name={}&name_match={}".format(url, self.group.name, "exact")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 1)
        group = response.data.get("data")[0]
        self.assertEqual(group.get("name"), self.group.name)

    def test_get_group_by_exact_name_no_match(self):
        """Test that getting groups by name returns no results with exact match."""
        url = reverse("group-list")
        url = "{}?name={}&name_match={}".format(url, "group", "exact")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 0)

    def test_get_group_invalid_sort_order_ignored(self):
        """Test that an invalid sort order value is ignored when getting groups."""
        url = reverse("group-list")
        url = "{}?order_by=potato".format(url)
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_filter_group_list_by_uuid_success(self):
        """Test that we can filter a list of groups by uuid."""
        url = f"{reverse('group-list')}?uuid={self.group.uuid}"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 1)

        group = response.data.get("data")[0]
        self.assertIsNotNone(group.get("name"))
        self.assertEqual(group.get("name"), self.group.name)

    def test_filter_group_list_by_uuid_multiple(self):
        """Test that we can filter a list of groups by uuid."""
        url = f"{reverse('group-list')}?uuid={self.group.uuid},{self.groupB.uuid}"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 2)

        group = response.data.get("data")[0]
        self.assertIsNotNone(group.get("name"))
        self.assertEqual(group.get("name"), self.group.name)
        group = response.data.get("data")[1]
        self.assertIsNotNone(group.get("name"))
        self.assertEqual(group.get("name"), self.groupB.name)

    def test_filter_group_list_by_uuid_fail(self):
        """Test that filtering by a nonexistent uuid returns nothing."""
        url = f"{reverse('group-list')}?uuid={uuid4()}"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertEqual(response.data.get("data"), [])
        self.assertEqual(len(response.data.get("data")), 0)

    def test_filter_group_list_by_system_true(self):
        """Test that we can filter a list of groups by system flag true."""
        system_group = Group.objects.create(system=True, tenant=self.tenant)
        url = f"{reverse('group-list')}?system=true"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_group_uuids = [group["uuid"] for group in response.data.get("data")]
        self.assertCountEqual(
            response_group_uuids, [str(self.defGroup.uuid), str(system_group.uuid), str(self.adminGroup.uuid)]
        )

    def test_filter_group_list_by_system_false(self):
        """Test that we can filter a list of groups by system flag false."""
        url = f"{reverse('group-list')}?system=false"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 4)
        response_group_uuids = [group["uuid"] for group in response.data.get("data")]
        self.assertCountEqual(
            response_group_uuids,
            [
                str(self.group.uuid),
                str(self.groupB.uuid),
                str(self.emptyGroup.uuid),
                str(self.groupMultiRole.uuid),
            ],
        )

    def test_filter_group_list_by_platform_default_true(self):
        """Test that we can filter a list of groups by platform_default flag true."""
        default_group = Group.objects.create(
            name="Platform Default", platform_default=True, system=False, tenant=self.tenant
        )

        url = f"{reverse('group-list')}?platform_default=true"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_group_uuids = [group["uuid"] for group in response.data.get("data")]
        # Tenant default group will be returned instead of the public one
        self.assertCountEqual(response_group_uuids, [str(default_group.uuid)])

    def test_filter_group_list_by_platform_default_false(self):
        """Test that we can filter a list of groups by platform_default flag false."""
        url = f"{reverse('group-list')}?platform_default=false"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 5)
        response_group_uuids = [group["uuid"] for group in response.data.get("data")]
        self.assertCountEqual(
            response_group_uuids,
            [
                str(self.group.uuid),
                str(self.groupB.uuid),
                str(self.emptyGroup.uuid),
                str(self.groupMultiRole.uuid),
                str(self.adminGroup.uuid),
            ],
        )

    def test_filter_group_list_by_admin_default_true(self):
        """Test that we can filter a list of groups by admin default flag true."""
        default_group = Group.objects.create(
            name="Default admin access", admin_default=True, system=False, tenant=self.tenant
        )

        url = f"{reverse('group-list')}?admin_default=true"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_group_uuids = [group["uuid"] for group in response.data.get("data")]
        # Tenant default group will be returned instead of the public one
        self.assertCountEqual(response_group_uuids, [str(default_group.uuid)])

    def test_filter_group_list_by_admin_default_false(self):
        """Test that we can filter a list of groups by admin_default flag false."""
        url = f"{reverse('group-list')}?admin_default=false"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 5)
        response_group_uuids = [group["uuid"] for group in response.data.get("data")]
        self.assertCountEqual(
            response_group_uuids,
            [
                str(self.group.uuid),
                str(self.groupB.uuid),
                str(self.emptyGroup.uuid),
                str(self.groupMultiRole.uuid),
                str(self.defGroup.uuid),
            ],
        )

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_update_group_success(self, send_kafka_message, mock_request):
        """Test that we can update an existing group."""
        with self.settings(NOTIFICATIONS_ENABLED=True):
            updated_name = self.group.name + "_update"
            test_data = {"name": updated_name}

            org_id = self.customer_data["org_id"]

            url = reverse("group-detail", kwargs={"uuid": self.group.uuid})
            client = APIClient()
            response = client.put(url, test_data, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_200_OK)

            self.assertIsNotNone(response.data.get("uuid"))
            self.assertEqual(updated_name, response.data.get("name"))

            # test whether newly edited (POST) group is added correctly within audit log database
            al_url = "/api/v1/auditlogs/"
            al_client = APIClient()
            al_response = al_client.get(al_url, **self.headers)
            retrieve_data = al_response.data.get("data")
            al_list = retrieve_data
            al_dict = al_list[0]

            al_dict_principal_username = al_dict["principal_username"]
            al_dict_description = al_dict["description"]
            al_dict_resource = al_dict["resource_type"]
            al_dict_action = al_dict["action"]

            self.assertEqual(self.user_data["username"], al_dict_principal_username)
            self.assertIsNotNone(al_dict_description)
            self.assertEqual(al_dict_resource, "group")
            self.assertEqual(al_dict_action, "edit")

            send_kafka_message.assert_called_with(
                settings.NOTIFICATIONS_TOPIC,
                {
                    "bundle": "console",
                    "application": "rbac",
                    "event_type": "group-updated",
                    "timestamp": ANY,
                    "events": [
                        {
                            "metadata": {},
                            "payload": {
                                "name": updated_name,
                                "username": self.user_data["username"],
                                "uuid": str(self.group.uuid),
                            },
                        }
                    ],
                    "org_id": org_id,
                },
                ANY,
            )

    def test_update_default_group(self):
        """Test that platform_default groups are protected from updates"""
        url = reverse("group-detail", kwargs={"uuid": self.defGroup.uuid})
        test_data = {"name": self.defGroup.name + "_updated"}
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_admin_default_group(self):
        """Test that admin_default groups are protected from updates"""
        url = reverse("group-detail", kwargs={"uuid": self.adminGroup.uuid})
        test_data = {"name": self.adminGroup.name + "_updated"}
        client = APIClient()
        response = client.put(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_admin_default_group_roles(self):
        """Test that admin_default groups' roles are protected from updates"""
        url = reverse("group-roles", kwargs={"uuid": self.adminGroup.uuid})
        test_data = {"roles": [self.roleB.uuid]}
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_failure_adding_principals_to_admin_default(self, mock_request):
        """Test that adding a principal to a admin default group will fail."""
        url = reverse("group-principals", kwargs={"uuid": self.adminGroup.uuid})
        client = APIClient()
        username = "test_user"
        test_data = {"principals": [{"username": username}]}
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_group_invalid(self):
        """Test that updating an invalid group returns an error."""
        url = reverse("group-detail", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.put(url, {}, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_group_invalid_guid(self):
        """Test that an invalid GUID on update causes a 400."""
        url = reverse("group-detail", kwargs={"uuid": "invalid_guid"})
        client = APIClient()
        response = client.put(url, {}, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("management.role.relation_api_dual_write_handler.OutboxReplicator._save_replication_event")
    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_delete_group_success(self, send_kafka_message, mock_method):
        """Test that we can delete an existing group."""
        with (self.settings(NOTIFICATIONS_ENABLED=True)):
            url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
            request_body = {"roles": [self.role.uuid]}

            client = APIClient()
            response = client.post(url, request_body, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_200_OK)

            role_binding_id = (
                BindingMapping.objects.filter(role=self.role, resource_id=self.role.tenant.org_id).get().mappings["id"]
            )

            url = reverse("group-detail", kwargs={"uuid": self.group.uuid})
            client = APIClient()
            principals_uuids = self.group.principals.values_list("uuid", flat=True)
            group_uuid = self.group.uuid
            response = client.delete(url, **self.headers)

            actual_call_arg = mock_method.call_args[0][0]
            to_remove = actual_call_arg["relations_to_remove"]
            print(to_remove)
            self.assertEqual(8, len(to_remove))

            def assert_group_tuples(tuples_to_replicate):
                for principal_uuid in principals_uuids:
                    relation_tuple = relation_api_tuple(
                        "group",
                        group_uuid,
                        "member",
                        "principal",
                        str(principal_uuid),
                    )

                    self.assertIsNotNone(find_relation_in_list(tuples_to_replicate, relation_tuple))

                relation_tuple = relation_api_tuple(
                    "role_binding",
                    role_binding_id,
                    "subject",
                    "group",
                    str(group_uuid),
                    "member",
                )
                self.assertIsNotNone(find_relation_in_list(tuples_to_replicate, relation_tuple))

                relation_tuple = relation_api_tuple(
                    "role_binding",
                    role_binding_id,
                    "role",
                    "role",
                    str(self.role.uuid),
                )
                self.assertIsNotNone(find_relation_in_list(tuples_to_replicate, relation_tuple))

                relation_tuple = relation_api_tuple(
                    "workspace",
                    self.group.tenant.org_id,
                    "binding",
                    "role_binding",
                    str(role_binding_id),
                )
                self.assertIsNotNone(find_relation_in_list(tuples_to_replicate, relation_tuple))

            assert_group_tuples(to_remove)

            self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

            org_id = self.customer_data["org_id"]

            # test whether correctly added to audit logs
            al_url = "/api/v1/auditlogs/"
            al_client = APIClient()
            al_response = al_client.get(al_url, **self.headers)
            retrieve_data = al_response.data.get("data")
            al_list = retrieve_data
            al_dict = al_list[0]

            al_dict_principal_username = al_dict["principal_username"]
            al_dict_description = al_dict["description"]
            al_dict_resource = al_dict["resource_type"]
            al_dict_action = al_dict["action"]

            self.assertEqual(self.user_data["username"], al_dict_principal_username)
            self.assertIsNotNone(al_dict_description)
            self.assertEqual(al_dict_resource, "group")
            self.assertEqual(al_dict_action, "delete")

            # verify the group no longer exists
            response = client.get(url, **self.headers)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

            send_kafka_message.assert_called_with(
                settings.NOTIFICATIONS_TOPIC,
                {
                    "bundle": "console",
                    "application": "rbac",
                    "event_type": "group-deleted",
                    "timestamp": ANY,
                    "events": [
                        {
                            "metadata": {},
                            "payload": {
                                "name": self.group.name,
                                "username": self.user_data["username"],
                                "uuid": str(self.group.uuid),
                            },
                        }
                    ],
                    "org_id": org_id,
                },
                ANY,
            )

    def test_delete_default_group(self):
        """Test that platform_default groups are protected from deletion"""
        url = reverse("group-detail", kwargs={"uuid": self.defGroup.uuid})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_custom_default_group(self):
        """
        Test that custom platform_default groups can be deleted and the public default group
        becomes default for the tenant
        """
        client = APIClient()
        customDefGroup = Group(name="customDefGroup", platform_default=True, system=False, tenant=self.tenant)
        customDefGroup.save()
        customDefGroup.principals.add(self.test_principal)
        customDefGroup.save()
        customDefPolicy = Policy(name="customDefPolicy", system=True, tenant=self.tenant, group=customDefGroup)
        customDefPolicy.save()

        url = f"{reverse('group-list')}?platform_default=true"
        response = client.get(url, **self.headers)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0]["uuid"], str(customDefGroup.uuid))

        url = reverse("group-detail", kwargs={"uuid": customDefGroup.uuid})
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        url = f"{reverse('group-list')}?platform_default=true"
        response = client.get(url, **self.headers)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0]["uuid"], str(self.defGroup.uuid))

    def test_delete_group_invalid(self):
        """Test that deleting an invalid group returns an error."""
        url = reverse("group-detail", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_group_invalid_guid(self):
        """Test that deleting group with an invalid GUID returns an error."""
        url = reverse("group-detail", kwargs={"uuid": "invalid_guid"})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_group_principals_invalid_method(self):
        """Test that using an unsupported REST method returns an error."""
        url = reverse("group-principals", kwargs={"uuid": uuid4()})
        client = APIClient()
        response = client.put(url, {}, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
            "errors": [
                {
                    "detail": "Unexpected error.",
                    "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "source": "principals",
                }
            ],
        },
    )
    def test_add_group_principals_failure(self, mock_request):
        """Test that adding a principal to a group returns the proper response on failure."""
        url = reverse("group-principals", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        new_username = uuid4()
        test_data = {"principals": [{"username": self.principal.username}, {"username": new_username}]}
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data[0]["detail"], "Unexpected error.")
        self.assertEqual(response.data[0]["status"], 500)
        self.assertEqual(response.data[0]["source"], "principals")

    def test_add_group_principal_invalid_guid(self):
        """Test that adding a principal to a group with an invalid GUID causes a 400."""
        url = reverse("group-principals", kwargs={"uuid": "invalid_guid"})
        client = APIClient()
        test_data = {"principals": [{"username": self.principal.username}]}
        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("management.role.relation_api_dual_write_handler.OutboxReplicator._save_replication_event")
    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_add_group_principal_not_exists(self, mock_request, mock_method):
        """Test that adding a non-existing principal into existing group causes a 404"""
        url = reverse("group-principals", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        test_data = {"principals": [{"username": "not_existing_username"}]}

        response = client.post(url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIsNone(mock_method.call_args)

    @patch("management.role.relation_api_dual_write_handler.OutboxReplicator._save_replication_event")
    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"username": "test_add_user", "user_id": -448717}]},
    )
    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_add_group_principals_success(self, send_kafka_message, mock_request, mock_method):
        """Test that adding a principal to a group returns successfully."""
        # Create a group and a cross account user.
        with self.settings(NOTIFICATIONS_ENABLED=True):
            test_group = Group.objects.create(name="test", tenant=self.tenant)
            cross_account_user = Principal.objects.create(
                username="cross_account_user", cross_account=True, tenant=self.tenant
            )

            org_id = self.customer_data["org_id"]

            url = reverse("group-principals", kwargs={"uuid": test_group.uuid})
            client = APIClient()
            username = "test_add_user"
            test_data = {"principals": [{"username": username}, {"username": cross_account_user.username}]}

            response = client.post(url, test_data, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            principal = Principal.objects.get(username=username)

            # Only the user exists in IT will be created and added to the group
            # cross account users won't be added
            self.assertEqual(len(response.data.get("principals")), 1)
            self.assertEqual(
                response.data.get("principals")[0], {"username": username, "user_id": int(principal.user_id)}
            )
            self.assertEqual(principal.tenant, self.tenant)

            actual_call_arg = mock_method.call_args[0][0]
            self.assertEqual(
                generate_replication_event_to_add_principals(str(test_group.uuid), str(principal.uuid)),
                actual_call_arg,
            )

            send_kafka_message.assert_called_with(
                settings.NOTIFICATIONS_TOPIC,
                {
                    "bundle": "console",
                    "application": "rbac",
                    "event_type": "group-updated",
                    "timestamp": ANY,
                    "events": [
                        {
                            "metadata": {},
                            "payload": {
                                "name": test_group.name,
                                "username": self.user_data["username"],
                                "uuid": str(test_group.uuid),
                                "operation": "added",
                                "principal": username,
                            },
                        }
                    ],
                    "org_id": org_id,
                },
                ANY,
            )

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_get_group_principals_empty(self, mock_request):
        """Test that getting principals from an empty group returns successfully."""
        client = APIClient()
        url = reverse("group-principals", kwargs={"uuid": self.emptyGroup.uuid})
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("meta").get("count"), 0)
        self.assertEqual(response.data.get("data"), [])

    def test_get_group_principals_invalid_guid(self):
        client = APIClient()
        url = reverse("group-principals", kwargs={"uuid": "invalid"})
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_group_principals_invalid_sort_order(self):
        """Test that an invalid value for sort order is rejected."""
        client = APIClient()
        url = reverse("group-principals", kwargs={"uuid": self.emptyGroup.uuid})
        url += "?order_by=themis"
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_get_group_principals_nonempty(self, mock_request):
        """Test that getting principals from a nonempty group returns successfully."""
        mock_request.return_value["data"] = [
            {"username": self.principal.username},
            {"username": self.principalB.username},
        ]

        client = APIClient()
        url = reverse("group-principals", kwargs={"uuid": self.group.uuid})

        response = client.get(url, **self.headers)

        call_args, kwargs = mock_request.call_args_list[0]
        username_arg = call_args[0]

        for username in [self.principal.username, self.principalB.username]:
            self.assertTrue(username in username_arg)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("meta").get("count"), 2)
        self.assertEqual(response.data.get("data")[0].get("username"), self.principal.username)
        self.assertEqual(response.data.get("data")[1].get("username"), self.principalB.username)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_get_group_principals_nonempty_admin_only(self, mock_request):
        """Test that getting principals from a nonempty group returns successfully."""

        client = APIClient()
        url = reverse("group-principals", kwargs={"uuid": self.group.uuid}) + f"?admin_only=true"

        response = client.get(url, **self.headers)

        call_args, kwargs = mock_request.call_args_list[0]
        username_arg = call_args[0]

        mock_request.assert_called_with(
            ANY,
            org_id=ANY,
            options={"sort_order": None, "username_only": "false", "admin_only": True, "principal_type": None},
        )

        self.assertTrue(self.principal.username in username_arg)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0].get("username"), "test_user")

    @patch("management.role.relation_api_dual_write_handler.OutboxReplicator._save_replication_event")
    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_remove_group_principals_success(self, send_kafka_message, mock_request, mock_method):
        """Test that removing a principal to a group returns successfully."""
        with self.settings(NOTIFICATIONS_ENABLED=True):
            test_user = Principal.objects.create(username="test_user", tenant=self.tenant)
            self.group.principals.add(test_user)

            url = reverse("group-principals", kwargs={"uuid": self.group.uuid})
            client = APIClient()

            org_id = self.customer_data["org_id"]

            url = "{}?usernames={}".format(url, "test_user")
            response = client.delete(url, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

            send_kafka_message.assert_called_with(
                settings.NOTIFICATIONS_TOPIC,
                {
                    "bundle": "console",
                    "application": "rbac",
                    "event_type": "group-updated",
                    "timestamp": ANY,
                    "events": [
                        {
                            "metadata": {},
                            "payload": {
                                "name": self.group.name,
                                "username": self.user_data["username"],
                                "uuid": str(self.group.uuid),
                                "operation": "removed",
                                "principal": test_user.username,
                            },
                        }
                    ],
                    "org_id": org_id,
                },
                ANY,
            )

            actual_call_arg = mock_method.call_args[0][0]
            self.assertEqual(
                generate_replication_event_to_remove_principals(str(self.group.uuid), str(test_user.uuid)),
                actual_call_arg,
            )

    def test_remove_group_principals_invalid(self):
        """Test that removing a principal returns an error with invalid data format."""
        url = reverse("group-principals", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        response = client.delete(url, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            str(response.data.get("errors")[0].get("detail")),
            "Query parameter service-accounts or usernames is required.",
        )

    def test_remove_group_principals_invalid_guid(self):
        """Test that removing a principal returns an error when GUID is invalid."""
        invalid_uuid = "invalid"
        url = reverse("group-principals", kwargs={"uuid": invalid_uuid})
        client = APIClient()
        response = client.delete(url, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(str(response.data.get("errors")[0].get("detail")), f"{invalid_uuid} is not a valid UUID.")

    def test_remove_group_principals_invalid_username(self):
        """Test that removing a principal returns an error for invalid username."""
        invalid_username = "invalid_3098408"
        url = reverse("group-principals", kwargs={"uuid": self.group.uuid}) + f"?usernames={invalid_username}"
        client = APIClient()
        response = client.delete(url, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        err_message = f"User(s) {{'{invalid_username}'}} not found in the group '{self.group.name}'."
        self.assertEqual(str(response.data.get("errors")[0].get("detail")), err_message)

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
    def test_get_group_by_username(self, mock_request):
        """Test that getting groups for a principal returns successfully."""
        url = reverse("group-list")
        url = "{}?username={}".format(url, self.test_principal.username)
        client = APIClient()
        response = client.get(url, **self.test_headers)
        self.assertEqual(response.data.get("meta").get("count"), 4)

        # Return bad request when user does not exist
        url = reverse("group-list")
        url = "{}?username={}".format(url, uuid4())
        client = APIClient()
        response = client.get(url, **self.test_headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

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
                    "username": "user_not_attached_to_group_explicitly",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_get_group_by_username_no_assigned_group(self, mock_request):
        """Test that getting groups for a principal not assigned to a group returns successfully."""
        # User who is not added to a group explicitly will return platform default group
        url = reverse("group-list")
        url = "{}?username={}".format(url, self.principalC.username)
        client = APIClient()
        response = client.get(url, **self.test_headers)
        self.assertEqual(response.data.get("meta").get("count"), 2)

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
                    "username": "user_not_attached_to_group_explicitly",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_get_group_by_username_for_cross_account_principal(self, mock_request):
        """Test that getting groups for a cross account principal won't have platform default group."""
        self.test_principalC.cross_account = True
        self.test_principalC.save()
        url = reverse("group-list")
        url = "{}?username={}".format(url, self.test_principalC.username)
        client = APIClient()

        # User who is not added to a group explicitly will not return platform default group
        # if he is cross account principal.
        response = client.get(url, **self.test_headers)
        self.assertEqual(response.data.get("meta").get("count"), 1)

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
    def test_get_group_by_username_with_capitalization(self, mock_request):
        """Test that getting groups for a username with capitalization returns successfully."""
        url = reverse("group-list")
        username = "".join(random.choice([k.upper(), k]) for k in self.test_principal.username)
        url = "{}?username={}".format(url, username)
        client = APIClient()
        response = client.get(url, **self.test_headers)
        self.assertEqual(response.data.get("meta").get("count"), 4)

    def test_get_group_roles_success(self):
        """Test that getting roles for a group returns successfully."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get("uuid"), str(self.role.uuid))
        self.assertEqual(roles[0].get("name"), self.role.name)
        self.assertEqual(roles[0].get("description"), self.role.description)

    def test_get_group_roles_with_exclude_false_success(self):
        """Test that getting roles with 'exclude=false' for a group works as default."""
        url = "%s?exclude=FALSE" % (reverse("group-roles", kwargs={"uuid": self.group.uuid}))
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get("uuid"), str(self.role.uuid))
        self.assertEqual(roles[0].get("name"), self.role.name)
        self.assertEqual(roles[0].get("description"), self.role.description)

    def test_get_group_roles_with_exclude_success(self):
        """Test that getting roles with 'exclude=True' for a group returns successfully."""
        url = "%s?exclude=True" % (reverse("group-roles", kwargs={"uuid": self.group.uuid}))
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 2)
        self.assertTrue(role.uuid in [self.roleB.uuid, self.roleOrphan.uuid] for role in roles)

    def test_get_group_roles_with_exclude_in_principal_scope_success(self):
        """Test that getting roles with 'exclude=True' for a group in principal scope."""
        url = "%s?exclude=True&scope=principal" % (reverse("group-roles", kwargs={"uuid": self.group.uuid}))
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get("uuid"), str(self.roleB.uuid))
        self.assertEqual(roles[0].get("name"), self.roleB.name)
        self.assertEqual(roles[0].get("description"), self.roleB.description)

    def test_get_group_roles_ordered(self):
        """Test getting roles with 'order_by=' returns properly."""
        url = f"{reverse('group-roles', kwargs={'uuid': self.group.uuid})}?order_by=-name"
        client = APIClient()

        test_data = {"roles": [self.roleB.uuid]}
        response = client.post(url, test_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = client.get(url, **self.headers)
        roles = response.data.get("data")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 2)
        self.assertEqual(roles[0].get("name"), self.roleB.name)
        self.assertEqual(roles[1].get("name"), self.role.name)

    def test_get_group_roles_ordered_bad_input(self):
        url = f"{reverse('group-roles', kwargs={'uuid': self.group.uuid})}?order_by=-themis"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_group_roles_bad_group_guid(self):
        url = f"{reverse('group-roles', kwargs={'uuid': 'kielbasa'})}"
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_group_roles_nonexistent_group(self):
        url = f"{reverse('group-roles', kwargs={'uuid': uuid4()})}"
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_exclude_input_invalid(self):
        """Test that getting roles with 'exclude=' for a group returns failed validation."""
        url = "%s?exclude=sth" % (reverse("group-roles", kwargs={"uuid": self.group.uuid}))
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_role_name_filter_for_group_roles_no_match(self):
        """Test role_name filter for getting roles for a group."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        url = "{}?role_name=test".format(url)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 0)

    def test_role_name_filter_for_group_roles_match(self):
        """Test role_name filter for getting roles for a group."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        url = "{}?role_name={}".format(url, self.role.name)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get("uuid"), str(self.role.uuid))

    def test_role_display_name_filter_for_group_roles_no_match(self):
        """Test role_display_name filter for getting roles for a group."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        url = "{}?role_display_name=test".format(url)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 0)

    def test_role_display_name_filter_for_group_roles_match(self):
        """Test role_display_name filter for getting roles for a group."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        url = "{}?role_display_name={}".format(url, self.role.name)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get("uuid"), str(self.role.uuid))

    def test_role_description_filter_for_group_roles_no_match(self):
        """Test role_description filter for getting roles for a group."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        url = "{}?role_description=test".format(url)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 0)

    def test_role_description_filter_for_group_roles_match(self):
        """Test role_description filter for getting roles for a group."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        url = "{}?role_description={}".format(url, self.role.description)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get("uuid"), str(self.role.uuid))

    def test_all_role_filters_for_group_roles_no_match(self):
        """Test role filters for getting roles for a group."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        url = "{}?role_description=test&role_name=test".format(url)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 0)

    def test_all_role_filters_for_group_roles_match(self):
        """Test role filters for getting roles for a group."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        url = "{}?role_description={}&role_name={}".format(url, self.role.description, self.role.name)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get("uuid"), str(self.role.uuid))

    def test_group_filter_by_role_external_tenant(self):
        """Test that filtering groups by role_external_tenant succeeds."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        url = "{}?role_external_tenant={}".format(url, "foo")
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get("uuid"), str(self.role.uuid))

    def test_role_system_filter_for_group_roles(self):
        """Test role_system filter for getting roles for a group."""
        base_url = reverse("group-roles", kwargs={"uuid": self.groupMultiRole.uuid})
        client = APIClient()
        response = client.get(base_url, **self.headers)
        self.assertEqual(len(response.data.get("data")), 2)

        url = f"{base_url}?role_system=true"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 1)
        role = response.data.get("data")[0]
        self.assertEqual(role.get("system"), True)

        url = f"{base_url}?role_system=false"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 1)
        role = response.data.get("data")[0]
        self.assertEqual(role.get("system"), False)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_principal_username_filter_for_group_roles_no_match(self, mock_request):
        """Test principal_username filter for getting principals for a group."""
        url = reverse("group-principals", kwargs={"uuid": self.group.uuid})
        url = "{}?principal_username=test".format(url)
        client = APIClient()
        response = client.get(url, **self.headers)
        principals = response.data.get("data")

        mock_request.assert_called_with(
            [],
            options={"sort_order": None, "username_only": "false", "principal_type": None},
            org_id=self.customer_data["org_id"],
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(principals), 0)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_principal_username_filter_for_group_roles_match(self, mock_request):
        """Test principal_username filter for getting principals for a group."""
        url = reverse("group-principals", kwargs={"uuid": self.group.uuid})
        url = "{}?principal_username={}".format(url, self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)
        principals = response.data.get("data")

        mock_request.assert_called_with(
            [self.principal.username],
            options={"sort_order": None, "username_only": "false", "principal_type": None},
            org_id=self.customer_data["org_id"],
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(principals), 1)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_principal_get_ordering_username_success(self, mock_request):
        """Test that passing a username order_by parameter calls the proxy correctly."""
        url = f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}?order_by=username"
        client = APIClient()
        response = client.get(url, **self.headers)
        principals = response.data.get("data")
        expected_principals = sorted([self.principal.username, self.principalB.username])

        mock_request.assert_called_with(
            expected_principals,
            options={"sort_order": "asc", "username_only": "false", "principal_type": None},
            org_id=self.customer_data["org_id"],
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(principals), 1)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": [{"username": "test_user"}]},
    )
    def test_principal_get_ordering_nonusername_fail(self, mock_request):
        """Test that passing a username order_by parameter calls the proxy correctly."""
        url = f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}?order_by=best_joke"
        client = APIClient()
        response = client.get(url, **self.headers)
        principals = response.data.get("data")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(principals, None)

    @patch("management.group.relation_api_dual_write_group_handler.OutboxReplicator._save_replication_event")
    def test_add_group_roles_system_policy_create_success(self, mock_method):
        """Test that adding a role to a group without a system policy returns successfully."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        test_data = {"roles": [self.roleB.uuid, self.dummy_role_id]}

        self.assertCountEqual([self.role], list(self.group.roles()))
        self.assertCountEqual([self.policy], list(self.group.policies.all()))

        response = client.post(url, test_data, format="json", **self.headers)

        roles = response.data.get("data")
        system_policies = Policy.objects.filter(system=True)
        system_policy = system_policies.get(group=self.group)

        self.assertEqual(len(system_policies), 2)
        self.assertCountEqual([system_policy, self.policy], list(self.group.policies.all()))
        self.assertCountEqual([self.roleB], list(system_policy.roles.all()))
        self.assertCountEqual([self.role], list(self.policy.roles.all()))
        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))
        self.assertEqual(len(roles), 2)
        self.assertEqual(roles[0].get("uuid"), str(self.role.uuid))
        self.assertEqual(roles[0].get("name"), self.role.name)
        self.assertEqual(roles[0].get("description"), self.role.description)
        self.assertEqual(system_policy.tenant, self.tenant)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_system_flag_update_on_add(self, send_kafka_message):
        """Test that adding a role to a platform_default group flips the system flag."""
        kafka_mock = copy_call_args(send_kafka_message)
        with self.settings(NOTIFICATIONS_ENABLED=True):
            url = reverse("group-roles", kwargs={"uuid": self.defGroup.uuid})
            client = APIClient()
            test_data = {"roles": [self.roleB.uuid, self.dummy_role_id]}

            org_id = self.customer_data["org_id"]

            default_role = Role.objects.create(
                name="default_role",
                description="A default role for a group.",
                platform_default=True,
                system=True,
                tenant=self.public_tenant,
            )
            self.defGroup.policies.first().roles.add(default_role)
            self.assertTrue(self.defGroup.system)
            self.assertEqual(self.defGroup.roles().count(), 1)
            response = client.post(url, test_data, format="json", **self.headers)

            # Original platform default role does not change
            self.defGroup.refresh_from_db()
            self.assertEqual(self.defGroup.roles().count(), 1)
            self.assertTrue(self.defGroup.system)
            self.assertEqual(self.defGroup.tenant, self.public_tenant)
            self.assertEqual(response.status_code, status.HTTP_200_OK)

            # New platform default role for tenant created
            custom_default_group = Group.objects.get(platform_default=True, tenant=self.tenant)
            self.assertEqual(custom_default_group.name, "Custom default access")
            self.assertFalse(custom_default_group.system)
            self.assertEqual(custom_default_group.tenant, self.tenant)
            self.assertEqual(custom_default_group.roles().count(), 2)

            notification_messages = [
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "platform-default-group-turned-into-custom",
                        "timestamp": ANY,
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "name": custom_default_group.name,
                                    "username": self.user_data["username"],
                                    "uuid": str(custom_default_group.uuid),
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "custom-default-access-updated",
                        "timestamp": ANY,
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "name": custom_default_group.name,
                                    "username": self.user_data["username"],
                                    "uuid": str(custom_default_group.uuid),
                                    "operation": "added",
                                    "role": {"uuid": str(self.roleB.uuid), "name": self.roleB.name},
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
            ]
            kafka_mock.assert_has_calls(notification_messages, any_order=True)

    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_system_flag_update_on_remove(self, send_kafka_message):
        """Test that removing a role from a platform_default group flips the system flag."""
        kafka_mock = copy_call_args(send_kafka_message)
        with self.settings(NOTIFICATIONS_ENABLED=True):
            default_role = Role.objects.create(
                name="default_role",
                description="A default role for a group.",
                platform_default=True,
                system=True,
                tenant=self.public_tenant,
            )
            self.defGroup.policies.first().roles.add(default_role)
            self.assertTrue(self.defGroup.system)

            org_id = self.customer_data["org_id"]

            url = reverse("group-roles", kwargs={"uuid": self.defGroup.uuid})
            client = APIClient()
            url = "{}?roles={}".format(url, default_role.uuid)
            response = client.delete(url, format="json", **self.headers)
            self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
            self.defGroup.refresh_from_db()
            self.assertEqual(self.defGroup.name, "groupDef")
            self.assertTrue(self.defGroup.system)
            self.assertTrue(self.defGroup.tenant, self.tenant)
            self.assertTrue(self.defGroup.roles(), 1)

            # New platform default role for tenant created
            custom_default_group = Group.objects.get(platform_default=True, tenant=self.tenant)
            self.assertEqual(custom_default_group.name, "Custom default access")
            self.assertFalse(custom_default_group.system)
            self.assertEqual(custom_default_group.tenant, self.tenant)
            self.assertEqual(custom_default_group.roles().count(), 0)

            notification_messages = [
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "platform-default-group-turned-into-custom",
                        "timestamp": ANY,
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "name": custom_default_group.name,
                                    "username": self.user_data["username"],
                                    "uuid": str(custom_default_group.uuid),
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "custom-default-access-updated",
                        "timestamp": ANY,
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "name": custom_default_group.name,
                                    "username": self.user_data["username"],
                                    "uuid": str(custom_default_group.uuid),
                                    "operation": "removed",
                                    "role": {"uuid": str(default_role.uuid), "name": default_role.name},
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
            ]
            kafka_mock.assert_has_calls(notification_messages, any_order=True)

    def test_add_group_roles_bad_group_guid(self):
        group_url = reverse("group-roles", kwargs={"uuid": "master_exploder"})
        client = APIClient()
        test_data = {"roles": [self.roleB.uuid]}
        response = client.post(group_url, test_data, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_add_group_roles_system_policy_create_new_group_success(self):
        """Test that adding a role to a group without a system policy returns successfully."""
        group_url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        groupB_url = reverse("group-roles", kwargs={"uuid": self.groupB.uuid})
        client = APIClient()
        test_data = {"roles": [self.roleB.uuid]}

        response = client.post(group_url, test_data, format="json", **self.headers)
        responseB = client.post(groupB_url, test_data, format="json", **self.headers)

        system_policies = Policy.objects.filter(system=True)
        system_policy = system_policies.get(group=self.group)
        system_policyB = system_policies.get(group=self.groupB)

        self.assertEqual(len(system_policies), 3)
        self.assertCountEqual([self.roleB], list(system_policy.roles.all()))
        self.assertCountEqual([self.roleB], list(system_policyB.roles.all()))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(responseB.status_code, status.HTTP_200_OK)

    def test_add_group_roles_system_policy_get_success(self):
        """Test that adding a role to a group with existing system policy returns successfully."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        test_data = {"roles": [self.roleB.uuid, self.dummy_role_id]}
        system_policy_name = "System Policy for Group {}".format(self.group.uuid)
        system_policy = Policy.objects.create(
            system=True, tenant=self.tenant, group=self.group, name=system_policy_name
        )
        self.assertCountEqual([self.role], list(self.group.roles()))
        self.assertCountEqual([system_policy, self.policy], list(self.group.policies.all()))

        response = client.post(url, test_data, format="json", **self.headers)

        roles = response.data.get("data")
        self.assertCountEqual([system_policy, self.policy], list(self.group.policies.all()))
        self.assertCountEqual([self.roleB], list(system_policy.roles.all()))
        self.assertCountEqual([self.role], list(self.policy.roles.all()))
        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))
        self.assertEqual(len(roles), 2)
        self.assertEqual(roles[0].get("uuid"), str(self.role.uuid))
        self.assertEqual(roles[0].get("name"), self.role.name)
        self.assertEqual(roles[0].get("description"), self.role.description)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_add_group_multiple_roles_success(self, send_kafka_message):
        """Test that adding multiple roles to a group returns successfully."""
        kafka_mock = copy_call_args(send_kafka_message)
        with self.settings(NOTIFICATIONS_ENABLED=True):
            groupC = Group.objects.create(name="groupC", tenant=self.tenant)
            url = reverse("group-roles", kwargs={"uuid": groupC.uuid})
            client = APIClient()
            test_data = {"roles": [self.role.uuid, self.roleB.uuid]}

            org_id = self.customer_data["org_id"]

            self.assertCountEqual([], list(groupC.roles()))

            response = client.post(url, test_data, format="json", **self.headers)

            self.assertCountEqual([self.role, self.roleB], list(groupC.roles()))
            self.assertEqual(response.status_code, status.HTTP_200_OK)

            notification_messages = [
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "group-updated",
                        "timestamp": ANY,
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "name": groupC.name,
                                    "username": self.user_data["username"],
                                    "uuid": str(groupC.uuid),
                                    "operation": "added",
                                    "role": {"uuid": str(self.role.uuid), "name": self.role.name},
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "group-updated",
                        "timestamp": ANY,
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "name": groupC.name,
                                    "username": self.user_data["username"],
                                    "uuid": str(groupC.uuid),
                                    "operation": "added",
                                    "role": {"uuid": str(self.roleB.uuid), "name": self.roleB.name},
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
            ]
            kafka_mock.assert_has_calls(notification_messages, any_order=True)

    def test_add_group_multiple_roles_invalid(self):
        """Test that adding invalid roles to a group fails the request and does not add any."""
        groupC = Group.objects.create(name="groupC", tenant=self.tenant)
        url = reverse("group-roles", kwargs={"uuid": groupC.uuid})
        client = APIClient()
        test_data = {"roles": ["abc123", self.roleB.uuid]}

        self.assertCountEqual([], list(groupC.roles()))

        response = client.post(url, test_data, format="json", **self.headers)

        self.assertCountEqual([], list(groupC.roles()))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_add_group_multiple_roles_not_found_success(self):
        """Test that adding roles to a group skips ids not found, and returns success."""
        groupC = Group.objects.create(name="groupC", tenant=self.tenant)
        url = reverse("group-roles", kwargs={"uuid": groupC.uuid})
        client = APIClient()
        test_data = {"roles": [self.dummy_role_id, self.roleB.uuid]}

        self.assertCountEqual([], list(groupC.roles()))

        response = client.post(url, test_data, format="json", **self.headers)

        self.assertCountEqual([self.roleB], list(groupC.roles()))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_remove_group_roles_success(self):
        """Test that removing a role from a group returns successfully."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        url = "{}?roles={}".format(url, self.role.uuid)

        self.policyB.roles.add(self.role)
        self.policyB.save()
        self.assertCountEqual([self.role], list(self.group.roles()))

        response = client.delete(url, format="json", **self.headers)

        self.assertCountEqual([], list(self.group.roles()))
        self.assertCountEqual([self.role, self.roleB], list(self.groupB.roles()))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_admin_default_group_roles(self):
        """Test that admin_default groups' roles are protected from removal"""
        url = reverse("group-roles", kwargs={"uuid": self.adminGroup.uuid})
        client = APIClient()
        url = "{}?roles={}".format(url, self.role.uuid)

        response = client.delete(url, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_remove_group_multiple_roles_success(self, send_kafka_message):
        """Test that removing multiple roles from a group returns successfully."""
        kafka_mock = copy_call_args(send_kafka_message)
        with self.settings(NOTIFICATIONS_ENABLED=True):
            url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
            client = APIClient()
            url = "{}?roles={},{}".format(url, self.role.uuid, self.roleB.uuid)

            org_id = self.customer_data["org_id"]

            self.policy.roles.add(self.roleB)
            self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))

            response = client.delete(url, format="json", **self.headers)

            self.assertCountEqual([], list(self.group.roles()))
            self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

            notification_messages = [
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "group-updated",
                        "timestamp": ANY,
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "name": self.group.name,
                                    "username": self.user_data["username"],
                                    "uuid": str(self.group.uuid),
                                    "operation": "removed",
                                    "role": {"uuid": str(self.role.uuid), "name": self.role.name},
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "group-updated",
                        "timestamp": ANY,
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "name": self.group.name,
                                    "username": self.user_data["username"],
                                    "uuid": str(self.group.uuid),
                                    "operation": "removed",
                                    "role": {"uuid": str(self.roleB.uuid), "name": self.roleB.name},
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
            ]
            kafka_mock.assert_has_calls(notification_messages, any_order=True)

    def test_remove_group_multiple_roles_invalid(self):
        """Test that removing invalid roles from a group fails the request and does not remove any."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        url = "{}?roles={},{}".format(url, "abc123", self.roleB.uuid)

        self.policy.roles.add(self.roleB)
        self.policy.save()
        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))

        response = client.delete(url, format="json", **self.headers)

        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_remove_group_multiple_roles_not_found_success(self):
        """Test that removing roles from a group skips ids not found, and returns success."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        url = "{}?roles={},{},{}".format(url, self.role.uuid, self.roleB.uuid, self.dummy_role_id)

        self.policy.roles.add(self.roleB)
        self.policy.save()
        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))

        response = client.delete(url, format="json", **self.headers)

        self.assertCountEqual([], list(self.group.roles()))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_group_roles_invalid(self):
        """Test that removing a role returns an error with invalid data format."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        client = APIClient()

        response = client.delete(url, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_remove_group_roles_bad_guid(self):
        url = reverse("group-roles", kwargs={"uuid": "invalid"})
        client = APIClient()
        response = client.delete(url, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_remove_group_roles_nonexistent_role(self):
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        url = "{}?roles={}".format(url, self.dummy_role_id)
        client = APIClient()
        response = client.delete(url, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_admin_RonR(self):
        """Test that an admin user can group RBAC resources"""
        url = "{}?application={}".format(reverse("group-list"), "rbac")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_get_group_user_principals_nonempty(self, mock_request):
        """Test that getting the "user" type principals from a nonempty group returns successfully."""
        mock_request.return_value["data"] = [
            {"username": self.principal.username},
            {"username": self.principalB.username},
        ]

        client = APIClient()
        url = reverse("group-principals", kwargs={"uuid": self.group.uuid})

        response = client.get(url, {"principal_type": "user"}, **self.headers)

        call_args, kwargs = mock_request.call_args_list[0]
        username_arg = call_args[0]

        for username in [self.principal.username, self.principalB.username]:
            self.assertTrue(username in username_arg)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("meta").get("count"), 2)
        self.assertEqual(response.data.get("data")[0].get("username"), self.principal.username)
        self.assertEqual(response.data.get("data")[1].get("username"), self.principalB.username)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_get_group_user_principals_nonempty_limit_offset(self, mock_request):
        """
        Test that getting the user based principals from a group returns successfully
        according to the given limit and offset.
        """
        # Create a group with 3 user based principals
        group_name = "TestGroup"
        group = Group(name=group_name, tenant=self.tenant)
        group.save()

        principals_list = []
        for i in range(3):
            principal = Principal(username=f"user_based_principal_{i}", tenant=self.test_tenant)
            principal.save()
            principals_list.append(principal)
            group.principals.add(principal)
        group.save()

        # Set the return value for the mock
        mock_request.return_value["data"] = [
            {"username": principals_list[0].username},
            {"username": principals_list[1].username},
            {"username": principals_list[2].username},
        ]

        # Test that /groups/{uuid}/principals/ returns correct data with default limit and offset
        url = f"{reverse('group-principals', kwargs={'uuid': group.uuid})}"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(int(response.data.get("meta").get("count")), 3)
        self.assertEqual(int(response.data.get("meta").get("limit")), 10)
        self.assertEqual(int(response.data.get("meta").get("offset")), 0)
        self.assertEqual(len(response.data.get("data")), 3)

        # Test that /groups/{uuid}/principals/ returns correct data for given offset and limit
        test_data = [
            {"limit": 10, "offset": 3, "expected_data_count": 0},
            {"limit": 10, "offset": 2, "expected_data_count": 1},
            {"limit": 1, "offset": 0, "expected_data_count": 1},
            {"limit": 2, "offset": 2, "expected_data_count": 1},
        ]
        for item in test_data:
            limit = item["limit"]
            offset = item["offset"]
            expected_data_count = item["expected_data_count"]
            url = f"{reverse('group-principals', kwargs={'uuid': group.uuid})}?limit={limit}&offset={offset}"
            client = APIClient()
            response = client.get(url, **self.headers)

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(int(response.data.get("meta").get("count")), 3)
            self.assertEqual(int(response.data.get("meta").get("limit")), limit)
            self.assertEqual(int(response.data.get("meta").get("offset")), offset)
            self.assertEqual(len(response.data.get("data")), expected_data_count)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_get_group_service_account_success(self, mock_request):
        """Test that getting the "service-account" type principals from a nonempty group returns successfully."""
        mocked_values = []
        for uuid in self.sa_client_ids:
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

        url = f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}?principal_type=service-account"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 3)
        self.assertEqual(len(response.data.get("data")), 3)

        sa = response.data.get("data")[0]
        self.assertCountEqual(
            list(sa.keys()),
            ["clientId", "name", "description", "owner", "time_created", "type", "username"],
        )

        for mock_sa in mocked_values:
            if mock_sa["clientId"] == sa.get("clientId"):
                self.assertEqual(sa.get("name"), mock_sa["name"])
                self.assertEqual(sa.get("description"), mock_sa["description"])
                self.assertEqual(sa.get("owner"), mock_sa["owner"])
                self.assertEqual(sa.get("type"), "service-account")
                self.assertEqual(sa.get("username"), mock_sa["username"])

    def test_get_group_service_account_username_only_success(self):
        """
        Test that getting the service account usernames from a group returns successfully
        with 'username_only' query parameter.
        """
        # We expected only usernames from RBAC database
        expected_usernames = [f"service-account-{sa}" for sa in self.sa_client_ids]

        sa_type_param = "principal_type=service-account"
        username_only_param = "username_only=true"
        url = f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}?{sa_type_param}&{username_only_param}"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 3)
        self.assertEqual(len(response.data.get("data")), 3)

        for sa in response.data.get("data"):
            self.assertIn(sa["username"], expected_usernames)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_get_group_service_account_empty_response(self, mock_request):
        """Test that empty response is returned when tenant doesn't have a service account in a group."""
        uuid = self.sa_client_ids[0]
        mock_request.return_value = [
            {
                "clientId": uuid,
                "name": f"service_account_name_{uuid.split('-')[0]}",
                "description": f"Service Account description {uuid.split('-')[0]}",
                "owner": "jsmith",
                "username": "service_account-" + uuid,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]

        url = f"{reverse('group-principals', kwargs={'uuid': self.groupB.uuid})}?principal_type=service-account"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 0)
        self.assertEqual(len(response.data.get("data")), 0)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_get_group_service_account_valid_limit_offset(self, mock_request):
        """Test that we can read a list of service accounts according to the given limit and offset."""
        mocked_values = []
        for uuid in self.sa_client_ids:
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
        url = f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}?principal_type=service-account"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(int(response.data.get("meta").get("count")), 3)
        self.assertEqual(len(response.data.get("data")), 3)

        # set custom limit and offset
        test_values = [(1, 1), (2, 2), (5, 5)]
        for limit, offset in test_values:
            base_url = f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}"
            query_params = f"?principal_type=service-account&limit={limit}&offset={offset}"
            url = f"{base_url}{query_params}"
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
    def test_get_group_service_account_invalid_limit_offset(self, mock_request):
        """Test that default values are used for invalid limit and offset."""
        mocked_values = []
        for uuid in self.sa_client_ids:
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

        test_values = [(-1, 0), (10, -2), ("xxx", 0), (10, "xxx")]
        for limit, offset in test_values:
            base_url = f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}"
            query_params = f"?principal_type=service-account&limit={limit}&offset={offset}"
            url = f"{base_url}{query_params}"
            client = APIClient()
            response = client.get(url, **self.headers)

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(int(response.data.get("meta").get("count")), 3)
            self.assertEqual(len(response.data.get("data")), 3)

    def test_get_group_principals_check_service_account_ids(self):
        """Test that the endpoint for checking if service accounts are part of a group works as expected."""
        # Create a group and associate principals to it.
        group = Group(name="it-service-group", platform_default=False, system=False, tenant=self.tenant)
        group.save()

        # The user principals should not be retrieved in the results.
        group.principals.add(Principal.objects.create(username="user-1", tenant=self.tenant))
        group.principals.add(Principal.objects.create(username="user-2", tenant=self.tenant))
        group.principals.add(Principal.objects.create(username="user-3", tenant=self.tenant))
        group.save()

        # Create some service accounts and add some of them to the group.
        client_uuid_1 = uuid4()
        client_uuid_2 = uuid4()

        sa_1 = Principal.objects.create(
            username=f"service-account-{client_uuid_1}",
            service_account_id=client_uuid_1,
            type="service-account",
            tenant=self.tenant,
        )
        sa_2 = Principal.objects.create(
            username=f"service-account-{client_uuid_2}",
            service_account_id=client_uuid_2,
            type="service-account",
            tenant=self.tenant,
        )

        group.principals.add(sa_1)
        group.principals.add(sa_2)
        group.save()

        # Create a set with the service accounts that will go in the group. It will make it easier to make assertions
        # below.
        group_service_accounts_set = {str(sa_1.service_account_id), str(sa_2.service_account_id)}

        # Create more service accounts that should not show in the results, since they're not going to be specified in
        # the "client_ids" parameter.
        Principal.objects.create(
            username=f"service-account-{uuid4()}",
            service_account_id=uuid4(),
            type="service-account",
            tenant=self.tenant,
        )
        Principal.objects.create(
            username=f"service-account-{uuid4()}",
            service_account_id=uuid4(),
            type="service-account",
            tenant=self.tenant,
        )
        Principal.objects.create(
            username=f"service-account-{uuid4()}",
            service_account_id=uuid4(),
            type="service-account",
            tenant=self.tenant,
        )

        # Create the UUIDs to be specified in the request.
        not_in_group = uuid4()
        not_in_group_2 = uuid4()
        not_in_group_3 = uuid4()

        # Also, create a set with the service accounts that will NOT go in the group to make it easier to assert that
        # the results flag them as such.
        service_accounts_not_in_group_set = {
            str(not_in_group),
            str(not_in_group_2),
            str(not_in_group_3),
        }

        # Create the query parameter.
        service_accounts_client_ids = (
            f"{client_uuid_1},{client_uuid_2},{not_in_group},{not_in_group_2},{not_in_group_3}"
        )

        url = (
            f"{reverse('group-principals', kwargs={'uuid': group.uuid})}"
            f"?service_account_client_ids={service_accounts_client_ids}"
        )

        # Call the endpoint under test.
        client = APIClient()
        response: Response = client.get(url, **self.headers)

        # Assert that we received a 200 response.
        self.assertEqual(
            status.HTTP_200_OK,
            response.status_code,
            "unexpected status code received",
        )

        # Assert that we received the correct results count.
        self.assertEqual(
            5,
            response.data.get("meta").get("count"),
            "The results of five client IDs should have been returned, since those were the ones sent to the endpoint",
        )

        # Assert that the mixed matches are identified correctly.
        for client_id, is_it_present_in_group in response.data.get("data").items():
            # If the value is "true" it should be present in the service accounts' result set from above. Else, it
            # means that the specified client IDs were not part of the group, and that they should have been flagged
            # as such.
            if is_it_present_in_group:
                self.assertEqual(
                    True,
                    client_id in group_service_accounts_set,
                    "a client ID which was not part of the group was incorrectly flagged as if it was",
                )
            else:
                self.assertEqual(
                    True,
                    client_id in service_accounts_not_in_group_set,
                    "a client ID which was part of the group was incorrectly flagged as if it wasn't",
                )

    def test_get_group_principals_check_service_account_ids_non_existent(self):
        """Test that when checking non-existent service account client IDs from another group the endpoint flags them as not present."""

        # Create the UUIDs to be specified in the request.
        not_in_group = uuid4()
        not_in_group_2 = uuid4()
        not_in_group_3 = uuid4()
        not_in_group_4 = uuid4()
        not_in_group_5 = uuid4()

        # Also, create a set with the service accounts that will NOT go in the group to make it easier to assert that
        # the results flag them as such.
        service_accounts_not_in_group_set = {
            str(not_in_group),
            str(not_in_group_2),
            str(not_in_group_3),
            str(not_in_group_4),
            str(not_in_group_5),
        }

        # Create the query parameter.
        service_accounts_client_ids = (
            f"{not_in_group},{not_in_group_2},{not_in_group_3},{not_in_group_4},{not_in_group_5}"
        )

        url = (
            f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}"
            f"?service_account_client_ids={service_accounts_client_ids}"
        )

        # Call the endpoint under test.
        client = APIClient()
        response: Response = client.get(url, **self.headers)

        # Assert that we received a 200 response.
        self.assertEqual(
            status.HTTP_200_OK,
            response.status_code,
            "unexpected status code received",
        )

        # Assert that we received the correct results count.
        self.assertEqual(
            5,
            response.data.get("meta").get("count"),
            "The results of five client IDs should have been returned, since those were the ones sent to the endpoint",
        )

        # Assert that the mixed matches are identified correctly.
        for client_id, is_it_present_in_group in response.data.get("data").items():
            # If the value is "true" it should be present in the service accounts' result set from above. Else, it
            # means that the specified client IDs were not part of the group, and that they should have been flagged
            # as such.
            if is_it_present_in_group:
                self.fail(
                    "no existing service accounts were specified in the query parameter. Still, some were flagged as"
                    " present in the group"
                )
            else:
                self.assertEqual(
                    True,
                    client_id in service_accounts_not_in_group_set,
                    "a client ID which was part of the group was incorrectly flagged as if it wasn't",
                )

    def test_get_group_principals_check_service_account_ids_with_limit_offset(self):
        """
        Test that the endpoint for checking if service accounts are part of a group works as expected
        with 'limit' and 'offset' present in the query.
        """
        # Create a group and associate principals to it.
        group = Group(name="it-service-group", platform_default=False, system=False, tenant=self.tenant)
        group.save()

        # Create a service account and it into group.
        client_uuid = uuid4()
        sa = Principal.objects.create(
            username=f"service-account-{client_uuid}",
            service_account_id=client_uuid,
            type="service-account",
            tenant=self.tenant,
        )
        group.principals.add(sa)
        group.save()

        url = (
            f"{reverse('group-principals', kwargs={'uuid': group.uuid})}"
            f"?service_account_client_ids={client_uuid}&limit=10&offset=0"
        )

        # Call the endpoint under test.
        client = APIClient()
        response: Response = client.get(url, **self.headers)

        # Assert that we received a 200 response.
        self.assertEqual(
            status.HTTP_200_OK,
            response.status_code,
            "unexpected status code received",
        )

        # Assert that we received the correct results.
        self.assertEqual(1, response.data.get("meta").get("count"))
        is_present_in_group = response.data.get("data")[str(client_uuid)]
        self.assertTrue(is_present_in_group)

    def test_get_group_principals_check_service_account_ids_incompatible_query_parameters(self):
        """Test that no other query parameter can be used along with the "service_account_ids" one."""
        # Use a few extra query parameter to test the behavior. Since we use a "len(query_params) > 1" condition it
        # really does not matter which other query parameter we use for the test, but we are adding a bunch in case
        # this changes in the future.
        query_parameters_to_test: list[str] = [
            "order_by",
            "principal_type",
            "principal_username",
            "service_account_name",
            "username_only",
        ]

        for query_parameter in query_parameters_to_test:
            url = (
                f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}"
                f"?service_account_client_ids={uuid4()}&{query_parameter}=abcde"
            )
            client = APIClient()
            response: Response = client.get(url, **self.headers)

            # Assert that we received a 400 response.
            self.assertEqual(
                status.HTTP_400_BAD_REQUEST,
                response.status_code,
                "unexpected status code received",
            )

            # Assert that the error message is the expected one.
            self.assertEqual(
                str(response.data.get("errors")[0].get("detail")),
                "The 'service_account_client_ids' parameter is incompatible with any other query parameter."
                " Please, use it alone",
            )

    def test_get_group_principals_check_service_account_ids_empty_client_ids(self):
        """Test that an empty service account IDs query param returns a bad request response"""
        url = f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}?service_account_client_ids="
        client = APIClient()
        response: Response = client.get(url, **self.headers)

        # Assert that we received a 400 response.
        self.assertEqual(
            status.HTTP_400_BAD_REQUEST,
            response.status_code,
            "unexpected status code received",
        )

        # Assert that the error message is the expected one.
        self.assertEqual(
            str(response.data.get("errors")[0].get("detail")),
            "Not a single client ID was specified for the client IDs filter",
            "unexpected error message detail",
        )

    def test_get_group_principals_check_service_account_ids_blank_string(self):
        """Test that a blank service account IDs query param returns a bad request response"""
        url = f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}?service_account_client_ids=     "
        client = APIClient()
        response: Response = client.get(url, **self.headers)

        # Assert that we received a 400 response.
        self.assertEqual(
            status.HTTP_400_BAD_REQUEST,
            response.status_code,
            "unexpected status code received",
        )

        # Assert that the error message is the expected one.
        self.assertEqual(
            str(response.data.get("errors")[0].get("detail")),
            "Not a single client ID was specified for the client IDs filter",
            "unexpected error message detail",
        )

    def test_get_group_principals_check_service_account_ids_invalid_uuid(self):
        """Test that an invalid service account ID query param returns a bad request response"""
        url = f"{reverse('group-principals', kwargs={'uuid': self.group.uuid})}?service_account_client_ids=abcde"
        client = APIClient()
        response: Response = client.get(url, **self.headers)

        # Assert that we received a 400 response.
        self.assertEqual(
            status.HTTP_400_BAD_REQUEST,
            response.status_code,
            "unexpected status code received",
        )

        # Assert that the error message is the expected one.
        self.assertEqual(
            str(response.data.get("errors")[0].get("detail")),
            "The specified client ID 'abcde' is not a valid UUID",
            "unexpected error message detail",
        )

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_get_group_service_account_filter_by_username_success(self, mock_request):
        """
        Test that filtering the Service Accounts by username returns expected results.
        """
        # Create a group with 2 Service Account
        group = Group.objects.create(name="group_with_sa", tenant=self.tenant)

        mocked_values = []
        uuid1 = "e78dc6b2-5930-4649-999f-266f4b926f3e"  # uuid without "a" char
        uuid2 = "d9f127fb-5e9d-41a0-b71a-f57273c3cd76"  # uuid with "a" char
        for uuid in [uuid1, uuid2]:
            mocked_values.append(
                {
                    "clientId": uuid,
                    "name": f"service_account_name_{uuid.split('-')[0]}",
                    "description": f"Service Account description {uuid.split('-')[0]}",
                    "owner": "jsmith",
                    "username": "service-account-" + uuid,
                    "time_created": 1706784741,
                    "type": "service-account",
                }
            )
            principal = Principal(
                username="service-account-" + uuid,
                tenant=self.tenant,
                type="service-account",
                service_account_id=uuid,
            )
            principal.save()
            group.principals.add(principal)

        mock_request.return_value = mocked_values
        group.save()

        # Test that only 1 SA is returned for SA with "a" in username
        service_account_principal = "principal_type=service-account"
        principal_username_filter = "principal_username=a"
        url = (
            f"{reverse('group-principals', kwargs={'uuid': group.uuid})}"
            f"?{service_account_principal}"
            f"&{principal_username_filter}"
        )
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 1)
        self.assertEqual(len(response.data.get("data")), 1)

        sa = response.data.get("data")[0]
        self.assertEqual(sa.get("clientId"), uuid2)
        self.assertEqual(sa.get("username"), "service-account-" + uuid2)

        # Test that 0 SA is returned for SA with "r" in username
        principal_username_filter = "principal_username=r"
        url = (
            f"{reverse('group-principals', kwargs={'uuid': group.uuid})}"
            f"?{service_account_principal}"
            f"&{principal_username_filter}"
        )
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(int(response.data.get("meta").get("count")), 0)
        self.assertEqual(len(response.data.get("data")), 0)


class GroupViewNonAdminTests(IdentityRequest):
    """Test the group view for nonadmin user."""

    def setUp(self):
        """Set up the group view nonadmin tests."""
        super().setUp()
        self.dummy_role_id = uuid4()
        self.user_data = self._create_user_data()
        self.customer = self._create_customer_data()
        self.request_context = self._create_request_context(self.customer, self.user_data, is_org_admin=False)

        request = self.request_context["request"]
        self.headers = request.META
        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [{"attributeFilter": {"key": "key1.id", "operation": "equal", "value": "value1"}}],
        }

        self.principal = Principal(username=self.user_data["username"], tenant=self.tenant)
        self.principal.save()
        self.admin_principal = Principal(username="user_admin", tenant=self.tenant)
        self.admin_principal.save()
        self.group = Group(name="groupA", tenant=self.tenant)
        self.group.save()
        self.group.principals.add(self.principal)
        self.group.save()
        self.roleB = Role.objects.create(name="roleB", system=False, tenant=self.tenant)
        self.roleB.save()
        self.role = Role.objects.create(
            name="roleA", description="A role for a group.", system=False, tenant=self.tenant
        )
        self.role.save()

        # Create 2 non org admin principals and 1 org admin
        # 1. user based principal
        self.user_based_principal = Principal(username="user_based_principal", tenant=self.tenant)
        self.user_based_principal.save()

        customer_data = {
            "account_id": self.tenant.account_id,
            "tenant_name": self.tenant.tenant_name,
            "org_id": self.tenant.org_id,
        }

        request_context_user_based_principal = self._create_request_context(
            customer_data=customer_data,
            user_data={"username": self.user_based_principal.username, "email": "test@email.com"},
            is_org_admin=False,
        )
        self.headers_user_based_principal = request_context_user_based_principal["request"].META

        # 2. service account based principal
        service_account_data = self._create_service_account_data()
        self.service_account_principal = Principal(
            username=service_account_data["username"],
            tenant=self.tenant,
            type="service-account",
            service_account_id=service_account_data["client_id"],
        )
        self.service_account_principal.save()

        request_context_service_account_principal = self._create_request_context(
            customer_data=customer_data,
            service_account_data=service_account_data,
            is_org_admin=False,
        )
        self.headers_service_account_principal = request_context_service_account_principal["request"].META

        # 3 org admin principal in the tenant
        self.org_admin = Principal(username="org_admin", tenant=self.tenant)
        self.org_admin.save()

        request_context_org_admin = self._create_request_context(
            customer_data=customer_data,
            user_data={"username": self.org_admin.username, "email": "test@email.com"},
            is_org_admin=True,
        )
        self.headers_org_admin = request_context_org_admin["request"].META

        # Error messages
        self.no_permission_err_message = "You do not have permission to perform this action."
        self.user_access_admin_group_err_message = (
            "Non org admin users are not allowed to create, modify, or delete a group with higher than 'read' RBAC "
            "permission."
        )
        self.invalid_value_for_scope_query_param = (
            "scope query parameter value 'foo' is invalid. ['org_id', 'principal'] are valid inputs."
        )
        self.user_access_admin_role_err_message = (
            "Non org admin users are not allowed to add RBAC role with higher than 'read' permission into groups."
        )

    def tearDown(self):
        """Tear down group view tests."""
        Group.objects.all().delete()
        Principal.objects.all().delete()
        Permission.objects.all().delete()
        Access.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()

    @staticmethod
    def _create_group_with_user_access_administrator_role(tenant: Tenant) -> Group:
        """Create a group with an associated User Access Administrator role."""
        # Replicate a "User Access Administrator" permission.
        rbac_user_access_admin_permission = Permission()
        rbac_user_access_admin_permission.application = "rbac"
        rbac_user_access_admin_permission.permission = "rbac:*:*"
        rbac_user_access_admin_permission.resource_type = "*"
        rbac_user_access_admin_permission.tenant = tenant
        rbac_user_access_admin_permission.verb = "*"
        rbac_user_access_admin_permission.save()

        # Replicate a "User Access Administrator" role.
        user_access_admin_role = Role()
        user_access_admin_role.admin_default = True
        user_access_admin_role.description = "Grants a non-org admin full access to configure and manage user access to services hosted on console.redhat.com. This role can only be viewed and assigned by Organization Administrators."
        user_access_admin_role.display_name = "User Access administrator"
        user_access_admin_role.name = "User Access administrator"
        user_access_admin_role.platform_default = False
        user_access_admin_role.system = True
        user_access_admin_role.tenant = tenant
        user_access_admin_role.version = 3
        user_access_admin_role.save()

        # Associate the role and the permission.
        access = Access()
        access.permission = rbac_user_access_admin_permission
        access.role = user_access_admin_role
        access.tenant = tenant
        access.save()

        # Create the group that will be associated with the role.
        user_access_admin_group = Group()
        user_access_admin_group.admin_default = False
        user_access_admin_group.description = "A group with the User Access Administrator associated role"
        user_access_admin_group.name = "user-access-admin-group"
        user_access_admin_group.platform_default = False
        user_access_admin_group.system = False
        user_access_admin_group.tenant = tenant
        user_access_admin_group.save()

        # Create a policy which will be associated with the role.
        user_access_admin_policy = Policy()
        user_access_admin_policy.group = user_access_admin_group
        user_access_admin_policy.name = "User Access Administrator policy for regular-group"
        user_access_admin_policy.system = True
        user_access_admin_policy.tenant = tenant
        user_access_admin_policy.save()

        user_access_admin_policy.roles.add(user_access_admin_role)
        user_access_admin_policy.save()

        return user_access_admin_group

    def test_nonadmin_RonR_list(self):
        """Test that a nonadmin user cannot list groups in tenant"""
        url = "{}?application={}".format(reverse("group-list"), "rbac")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_nonadmin_RonR_retrieve(self):
        """Test that a nonadmin user can't retrieve group RBAC resources"""
        url = reverse("group-detail", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_add_group_roles_as_non_admin(self):
        """Test that adding roles a group as a non-admin is forbidden."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        test_data = {"roles": [self.roleB.uuid, self.dummy_role_id]}

        response = client.post(url, test_data, format="json", **self.headers)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_remove_group_role_as_non_admin(self):
        """Test that removal of a role from a group is forbidden to non-admins."""
        url = reverse("group-roles", kwargs={"uuid": self.group.uuid})
        client = APIClient()
        url = "{}?roles={}".format(url, self.role.uuid)
        response = client.delete(url, format="json", **self.headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_group_role_filter_as_non_admin(self):
        url = "%s?exclude=FALSE" % (reverse("group-roles", kwargs={"uuid": self.group.uuid}))
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @override_settings(IT_BYPASS_IT_CALLS=True)
    @patch("management.principal.proxy.PrincipalProxy.request_filtered_principals")
    def test_group_service_account_with_user_administrator_role_add_principals(
        self, request_filtered_principals: Mock
    ):
        """Test that a service account with the User Access administrator role can manage principals in a group

        The way the test is performed is the following:
        - Creates a group with a User Access Administrator role associated to it.
        - Creates a regular group which we will use for the tests.
        - Sends a request with an unprivileged service account to attempt to add principals to the regular group.
        - Creates a service account principal and adds it to the User Access Administrator group.
        - Sends a request with the privileged service account and asserts that the principals were added to the regular
        group.
        """
        # Create the customer data we will be using for the tenant.
        customer_data = self._create_customer_data()

        # Create a tenant.
        user_access_admin_tenant = Tenant()
        user_access_admin_tenant.account_id = customer_data["account_id"]
        user_access_admin_tenant.org_id = customer_data["org_id"]
        user_access_admin_tenant.ready = True
        user_access_admin_tenant.tenant_name = "new-tenant"
        user_access_admin_tenant.save()

        user_access_admin_group = self._create_group_with_user_access_administrator_role(
            tenant=user_access_admin_tenant
        )

        # Create a regular group that we will use to attempt to add principals to.
        regular_group = Group()
        regular_group.admin_default = False
        regular_group.description = "Just a regular group"
        regular_group.name = "regular-group"
        regular_group.platform_default = False
        regular_group.system = False
        regular_group.tenant = user_access_admin_tenant
        regular_group.save()

        # Generate the URL for adding principals to the regular group.
        group_principals_url = reverse("group-principals", kwargs={"uuid": regular_group.uuid})
        api_client = APIClient()

        # Create a new principal to be added to the regular group.
        new_principal = Principal()
        new_principal.cross_account = False
        new_principal.tenant = user_access_admin_tenant
        new_principal.type = "user"
        new_principal.username = "fake-red-hat-user"
        new_principal.save()

        # Create a new service account to be added to the regular group.
        new_sa_principal = Principal()
        new_sa_principal.service_account_id = uuid4()
        new_sa_principal.tenant = user_access_admin_tenant
        new_sa_principal.type = "service-account"
        new_sa_principal.username = f"service-account-{new_sa_principal.service_account_id}"
        new_sa_principal.save()

        # Create the test data to add a service account and a regular user to the group.
        test_data = {
            "principals": [
                {"clientId": new_sa_principal.service_account_id, "type": "service-account"},
                {"username": new_principal.username},
            ]
        }

        # Make sure that before calling the endpoint the group has no members.
        self.assertEqual(
            0,
            regular_group.principals.count(),
            "the regular group should not have any principals associated with it",
        )

        # Create the request context for an unprivileged service account.
        unprivileged_request_context = self._create_request_context(
            customer_data=customer_data,
            user_data=None,
            service_account_data=self._create_service_account_data(),
            is_org_admin=False,
        )

        # Call the endpoint under test with an unprivileged service account.
        response = api_client.post(
            group_principals_url, test_data, format="json", **unprivileged_request_context["request"].META
        )

        # Assert that the service account does not have permission to perform this operation.
        self.assertEqual(
            status.HTTP_403_FORBIDDEN,
            response.status_code,
            "unexpected status code when an unprivileged service account attempts to add principals to a group",
        )

        # Assert that no principals were added to the group.
        self.assertEqual(
            0,
            regular_group.principals.count(),
            "after a failed request to add a principal, the regular group should still have zero associated principals",
        )

        # Add the user access admin service account principal to the user access admin group.
        service_account_data = self._create_service_account_data()

        user_access_admin_sa_principal = Principal()
        user_access_admin_sa_principal.cross_account = False
        user_access_admin_sa_principal.service_account_id = service_account_data["client_id"]
        user_access_admin_sa_principal.tenant = user_access_admin_tenant
        user_access_admin_sa_principal.type = "service-account"
        user_access_admin_sa_principal.username = service_account_data["username"]
        user_access_admin_sa_principal.save()

        user_access_admin_group.principals.add(user_access_admin_sa_principal)

        # Simulate that the proxy validates the specified user principal correctly.
        request_filtered_principals.return_value = {"data": [{"username": new_principal.username}]}

        # Create the request context for privileged service account.
        privileged_request_context = self._create_request_context(
            customer_data=customer_data, user_data=None, service_account_data=service_account_data, is_org_admin=False
        )

        # Call the endpoint under test with the user with "User Access Administrator" permissions.
        response_two = api_client.post(
            group_principals_url, test_data, format="json", **privileged_request_context["request"].META
        )

        # Assert that the response is the expected one.
        self.assertEqual(
            status.HTTP_200_OK,
            response_two.status_code,
            "unexpected status code when a service account with the User Access Administrator role attempts to"
            " manage principals on a group",
        )

        # Assert that both the service account and the user principal were added to the group.
        self.assertEqual(
            2,
            regular_group.principals.count(),
            "after adding a principal to the regular group, the added service account and the user principal"
            " should be present",
        )

        # Double check that the principals are just a service account and a regular user principal.
        for principal in regular_group.principals.all():
            if principal.type == "service-account":
                self.assertEqual(
                    new_sa_principal.uuid,
                    principal.uuid,
                    "the created service account principal in the regular group is not the same as the one we expected",
                )
            else:
                self.assertEqual(
                    new_principal.uuid,
                    principal.uuid,
                    "the created user principal in the regular group is not the same as the one we expected",
                )

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @override_settings(IT_BYPASS_IT_CALLS=True)
    def test_group_service_account_with_user_administrator_role_remove_principals(self):
        """Test that a service account with the User Access administrator role can manage principals in a group.

        The way the test is performed is the following:
        - Creates a group with a User Access Administrator role associated to it.
        - Creates a regular group which we will use for the tests.
        - Adds a couple of principals to the regular group.
        - Sends a request with an unprivileged service account to attempt to remove principals from the regular group.
        - Sends a request with the privileged service account and asserts that the principals were added to the regular group.
        """
        # Create the customer data we will be using for the tenant.
        customer_data = self._create_customer_data()

        # Create a tenant.
        user_access_admin_tenant = Tenant()
        user_access_admin_tenant.account_id = customer_data["account_id"]
        user_access_admin_tenant.org_id = customer_data["org_id"]
        user_access_admin_tenant.ready = True
        user_access_admin_tenant.tenant_name = "new-tenant"
        user_access_admin_tenant.save()

        user_access_admin_group = self._create_group_with_user_access_administrator_role(
            tenant=user_access_admin_tenant
        )

        # Create a regular group that we will use to attempt to remove principals from.
        regular_group = Group()
        regular_group.admin_default = False
        regular_group.description = "Just a regular group"
        regular_group.name = "regular-group"
        regular_group.platform_default = False
        regular_group.system = False
        regular_group.tenant = user_access_admin_tenant
        regular_group.save()

        # Add a service account principal to the group...
        service_account_principal_to_delete = Principal()
        service_account_principal_to_delete.service_account_id = uuid4()
        service_account_principal_to_delete.tenant = user_access_admin_tenant
        service_account_principal_to_delete.type = "service-account"
        service_account_principal_to_delete.username = (
            f"service-account-{service_account_principal_to_delete.service_account_id}"
        )
        service_account_principal_to_delete.save()

        regular_group.principals.add(service_account_principal_to_delete)

        # ... and a user principal one.
        user_principal_to_remove = Principal()
        user_principal_to_remove.cross_account = False
        user_principal_to_remove.tenant = user_access_admin_tenant
        user_principal_to_remove.type = "user"
        user_principal_to_remove.username = "fake-red-hat-user"
        user_principal_to_remove.save()

        regular_group.principals.add(user_principal_to_remove)

        # Generate the URL for removing the principals from the regular group.
        group_principals_url = reverse("group-principals", kwargs={"uuid": regular_group.uuid})
        group_principals_url = f"{group_principals_url}?service-accounts={service_account_principal_to_delete.service_account_id}&usernames={user_principal_to_remove.username}"
        api_client = APIClient()

        # Make sure that before calling the endpoint the group has the two principals.
        self.assertEqual(
            2,
            regular_group.principals.count(),
            "the regular group should have two principals before the deletion attempt",
        )

        # Create the request context for an unprivileged service account.
        unprivileged_request_context = self._create_request_context(
            customer_data=customer_data,
            user_data=None,
            service_account_data=self._create_service_account_data(),
            is_org_admin=False,
        )

        # Call the endpoint under test with an unprivileged service account.
        response = api_client.delete(
            path=group_principals_url, data=None, format="json", **unprivileged_request_context["request"].META
        )

        # Assert that the service account does not have permission to perform this operation.
        self.assertEqual(
            status.HTTP_403_FORBIDDEN,
            response.status_code,
            "unexpected status code when an unprivileged service account attempts to remove principals from a group",
        )

        # Assert that no principals were removed from the group.
        self.assertEqual(
            2,
            regular_group.principals.count(),
            "after a failed request to remove principals, the regular group should still two associated principals",
        )

        # Add the service account access admin principal to the user access admin group.
        service_account_data = self._create_service_account_data()

        user_access_admin_sa_principal = Principal()
        user_access_admin_sa_principal.cross_account = False
        user_access_admin_sa_principal.service_account_id = service_account_data["client_id"]
        user_access_admin_sa_principal.tenant = user_access_admin_tenant
        user_access_admin_sa_principal.type = "service-account"
        user_access_admin_sa_principal.username = service_account_data["username"]
        user_access_admin_sa_principal.save()

        user_access_admin_group.principals.add(user_access_admin_sa_principal)

        # Create the request context for privileged service account.
        privileged_request_context = self._create_request_context(
            customer_data=customer_data, user_data=None, service_account_data=service_account_data, is_org_admin=False
        )

        # Call the endpoint under test with the service account with "User Access Administrator" permissions.
        response_two = api_client.delete(
            path=group_principals_url, format="json", **privileged_request_context["request"].META
        )

        # Assert that the response is the expected one.
        self.assertEqual(
            status.HTTP_204_NO_CONTENT,
            response_two.status_code,
            "unexpected status code when a service account with the User Access Administrator role attempts to delete"
            " principals from a group",
        )

        # Assert that both the service account and the user principal were removed from the group.
        self.assertEqual(
            0,
            regular_group.principals.count(),
            "after removing the principals from the regular group, the added service account and the user"
            " principal should no longer be present",
        )

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @override_settings(IT_BYPASS_IT_CALLS=True)
    @patch("management.principal.proxy.PrincipalProxy.request_filtered_principals")
    def test_group_user_with_user_administrator_role_add_principals(self, request_filtered_principals: Mock):
        """Test that a user with the User Access administrator role can manage principals in a group

        The way the test is performed is the following:
        - Creates a group with a User Access Administrator role associated to it.
        - Creates a regular group which we will use for the tests.
        - Sends a request with an unprivileged user to attempt to add principals to the regular group.
        - Creates a user principal and adds it to the User Access Administrator group.
        - Sends a request with the privileged user and asserts that the principals were added to the regular group.
        """
        # Create the customer data we will be using for the tenant.
        customer_data = self._create_customer_data()

        # Create a tenant.
        user_access_admin_tenant = Tenant()
        user_access_admin_tenant.account_id = customer_data["account_id"]
        user_access_admin_tenant.org_id = customer_data["org_id"]
        user_access_admin_tenant.ready = True
        user_access_admin_tenant.tenant_name = "new-tenant"
        user_access_admin_tenant.save()

        user_access_admin_group = self._create_group_with_user_access_administrator_role(
            tenant=user_access_admin_tenant
        )

        # Create a regular group that we will use to attempt to add principals to.
        regular_group = Group()
        regular_group.admin_default = False
        regular_group.description = "Just a regular group"
        regular_group.name = "regular-group"
        regular_group.platform_default = False
        regular_group.system = False
        regular_group.tenant = user_access_admin_tenant
        regular_group.save()

        # Generate the URL for adding principals to the regular group.
        group_principals_url = reverse("group-principals", kwargs={"uuid": regular_group.uuid})
        api_client = APIClient()

        # Create a new principal to be added to the regular group.
        new_principal = Principal()
        new_principal.cross_account = False
        new_principal.tenant = user_access_admin_tenant
        new_principal.type = "user"
        new_principal.username = "fake-red-hat-user"
        new_principal.save()

        # Create a new service account to be added to the regular group.
        new_sa_principal = Principal()
        new_sa_principal.service_account_id = uuid4()
        new_sa_principal.tenant = user_access_admin_tenant
        new_sa_principal.type = "service-account"
        new_sa_principal.username = f"service-account-{new_sa_principal.service_account_id}"
        new_sa_principal.save()

        # Create the test data to add a service account and a regular user to the group.
        test_data = {
            "principals": [
                {"clientId": new_sa_principal.service_account_id, "type": "service-account"},
                {"username": new_principal.username},
            ]
        }

        # Make sure that before calling the endpoint the group has no members.
        self.assertEqual(
            0,
            regular_group.principals.count(),
            "the regular group should not have any principals associated with it",
        )

        # Create the request context for an unprivileged user.
        unprivileged_request_context = self._create_request_context(
            customer_data=customer_data, user_data=self._create_user_data(), is_org_admin=False
        )

        # Call the endpoint under test with an unprivileged user.
        response = api_client.post(
            path=group_principals_url, data=test_data, format="json", **unprivileged_request_context["request"].META
        )

        # Assert that the user does not have permission to perform this operation.
        self.assertEqual(
            status.HTTP_403_FORBIDDEN,
            response.status_code,
            "unexpected status code when an unprivileged user attempts to add principals to a group",
        )

        # Assert that no principals were added to the group.
        self.assertEqual(
            0,
            regular_group.principals.count(),
            "after a failed request to add a principal, the regular group should still have zero associated principals",
        )

        # Add the user access admin principal to the user access admin group.
        user_data = self._create_user_data()

        user_access_admin_principal = Principal()
        user_access_admin_principal.cross_account = False
        user_access_admin_principal.tenant = user_access_admin_tenant
        user_access_admin_principal.type = "user"
        user_access_admin_principal.username = user_data["username"]
        user_access_admin_principal.save()

        user_access_admin_group.principals.add(user_access_admin_principal)

        # Simulate that the proxy validates the specified user principal correctly.
        request_filtered_principals.return_value = {"data": [{"username": new_principal.username}]}

        # Create the request context for the privileged user.
        privileged_request_context = self._create_request_context(
            customer_data=customer_data, user_data=user_data, is_org_admin=False
        )

        # Call the endpoint under test with the user with "User Access Administrator" permissions.
        response_two = api_client.post(
            path=group_principals_url, data=test_data, format="json", **privileged_request_context["request"].META
        )

        # Assert that the response is the expected one.
        self.assertEqual(
            status.HTTP_200_OK,
            response_two.status_code,
            "unexpected status code when a user with the User Access Administrator role attempts to add"
            " principals to a group",
        )

        # Assert that both the service account and the user principal were added to the group.
        self.assertEqual(
            2,
            regular_group.principals.count(),
            "after adding a principal to the regular group, the added service account and the user principal"
            " should be present",
        )

        # Double check that the principals are just a service account and a regular user principal.
        for principal in regular_group.principals.all():
            if principal.type == "service-account":
                self.assertEqual(
                    new_sa_principal.uuid,
                    principal.uuid,
                    "the created service account principal in the regular group is not the same as the one we expected",
                )
            else:
                self.assertEqual(
                    new_principal.uuid,
                    principal.uuid,
                    "the created user principal in the regular group is not the same as the one we expected",
                )

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @override_settings(IT_BYPASS_IT_CALLS=True)
    def test_group_user_with_user_administrator_role_remove_principals(self):
        """Test that a user with the User Access administrator role can manage principals in a group

        The way the test is performed is the following:
        - Creates a group with a User Access Administrator role associated to it.
        - Creates a regular group which we will use for the tests.
        - Adds a couple of principals to the regular group.
        - Sends a request with an unprivileged user to attempt to remove principals from the regular group.
        - Sends a request with the privileged user and asserts that the principals were added to the regular group.
        """
        # Create the customer data we will be using for the tenant.
        customer_data = self._create_customer_data()

        # Create a tenant.
        user_access_admin_tenant = Tenant()
        user_access_admin_tenant.account_id = customer_data["account_id"]
        user_access_admin_tenant.org_id = customer_data["org_id"]
        user_access_admin_tenant.ready = True
        user_access_admin_tenant.tenant_name = "new-tenant"
        user_access_admin_tenant.save()

        user_access_admin_group = self._create_group_with_user_access_administrator_role(
            tenant=user_access_admin_tenant
        )

        # Create a regular group that we will use to attempt to remove principals from.
        regular_group = Group()
        regular_group.admin_default = False
        regular_group.description = "Just a regular group"
        regular_group.name = "regular-group"
        regular_group.platform_default = False
        regular_group.system = False
        regular_group.tenant = user_access_admin_tenant
        regular_group.save()

        # Add a service account principal to the group...
        service_account_principal_to_delete = Principal()
        service_account_principal_to_delete.service_account_id = uuid4()
        service_account_principal_to_delete.tenant = user_access_admin_tenant
        service_account_principal_to_delete.type = "service-account"
        service_account_principal_to_delete.username = (
            f"service-account-{service_account_principal_to_delete.service_account_id}"
        )
        service_account_principal_to_delete.save()

        regular_group.principals.add(service_account_principal_to_delete)

        # ... and a user principal one.
        user_principal_to_remove = Principal()
        user_principal_to_remove.cross_account = False
        user_principal_to_remove.tenant = user_access_admin_tenant
        user_principal_to_remove.type = "user"
        user_principal_to_remove.username = "fake-red-hat-user"
        user_principal_to_remove.save()

        regular_group.principals.add(user_principal_to_remove)

        # Generate the URL for removing the principals from the regular group.
        group_principals_url = reverse("group-principals", kwargs={"uuid": regular_group.uuid})
        group_principals_url = f"{group_principals_url}?service-accounts={service_account_principal_to_delete.service_account_id}&usernames={user_principal_to_remove.username}"
        api_client = APIClient()

        # Make sure that before calling the endpoint the group has the two principals.
        self.assertEqual(
            2,
            regular_group.principals.count(),
            "the regular group should have two principals before the deletion attempt",
        )

        # Create the request context for an unprivileged user.
        unprivileged_request_context = self._create_request_context(
            customer_data=customer_data, user_data=self._create_user_data(), is_org_admin=False
        )

        # Call the endpoint under test with an unprivileged user.
        response = api_client.delete(
            path=group_principals_url, data=None, format="json", **unprivileged_request_context["request"].META
        )

        # Assert that the user does not have permission to perform this operation.
        self.assertEqual(
            status.HTTP_403_FORBIDDEN,
            response.status_code,
            "unexpected status code when an unprivileged user attempts to remove principals from a group",
        )

        # Assert that no principals were removed from the group.
        self.assertEqual(
            2,
            regular_group.principals.count(),
            "after a failed request to remove principals, the regular group should still two associated principals",
        )

        # Add the user access admin principal to the user access admin group.
        user_data = self._create_user_data()

        user_access_admin_principal = Principal()
        user_access_admin_principal.cross_account = False
        user_access_admin_principal.tenant = user_access_admin_tenant
        user_access_admin_principal.type = "user"
        user_access_admin_principal.username = user_data["username"]
        user_access_admin_principal.save()

        user_access_admin_group.principals.add(user_access_admin_principal)

        # Create the request context for the privileged user.
        privileged_request_context = self._create_request_context(
            customer_data=customer_data, user_data=user_data, is_org_admin=False
        )

        # Call the endpoint under test with the user with "User Access Administrator" permissions.
        response_two = api_client.delete(
            path=group_principals_url, format="json", **privileged_request_context["request"].META
        )

        # Assert that the response is the expected one.
        self.assertEqual(
            status.HTTP_204_NO_CONTENT,
            response_two.status_code,
            "unexpected status code when a user with the User Access Administrator role attempts to delete"
            " principals from a group",
        )

        # Assert that both the service account and the user principal were added to the group.
        self.assertEqual(
            0,
            regular_group.principals.count(),
            "after removing the principals from the regular group, the added service account and the user"
            " principal should no longer be present",
        )

    def test_create_group_without_User_Access_Admin_fail(self):
        """Test that non org admin without 'User Access administrator' role cannot create a group."""
        url = reverse("group-list")
        client = APIClient()

        request_body = {"name": "New group name"}
        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

    def test_create_group_with_User_Access_Admin_success(self):
        """Test that non org admin with 'User Access administrator' role can create a group."""
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        url = reverse("group-list")
        client = APIClient()

        request_body = {"name": "New group created by user based principal"}
        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        request_body = {"name": "New group created by service account based principal"}
        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_update_group_without_User_Access_Admin_fail(self):
        """Test that non org admin without 'User Access administrator' role cannot update a group."""
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        url = reverse("group-detail", kwargs={"uuid": test_group.uuid})
        request_body = {"name": "new name"}
        client = APIClient()

        response = client.put(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.put(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

    def test_update_group_with_User_Access_Admin_success(self):
        """
        Test that non org admin with 'User Access administrator' role can update a group
        without 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        url = reverse("group-detail", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        new_name_user = "New name - user based principal"
        request_body = {"name": new_name_user}
        response = client.put(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["name"], new_name_user)

        new_name_sa = "New name - service account principal"
        request_body = {"name": new_name_sa}
        response = client.put(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["name"], new_name_sa)

    @patch("management.group.relation_api_dual_write_group_handler.OutboxReplicator._save_replication_event")
    def test_add_and_remove_role_to_group(self, mock_method):
        Permission.objects.create(permission="app:inventory:read", tenant=self.tenant)

        access_data = [
            {
                "permission": "app:inventory:read",
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "group.id", "operation": "equal", "value": "111"}}
                ],
            }
        ]

        test_data = {"name": "role_name", "display_name": "role_display", "access": access_data}

        url = reverse("role-list")
        # create a role
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers_org_admin)
        role = Role.objects.get(uuid=response.data["uuid"])
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        binding_mapping = BindingMapping.objects.get(role=role, resource_type_name="workspace", resource_id="111")

        # Create a group and role we need for the test
        group = Group.objects.create(name="test group", tenant=self.tenant)
        request_body = {"roles": [role.uuid]}
        url = reverse("group-roles", kwargs={"uuid": group.uuid})
        client = APIClient()

        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        actual_call_arg = mock_method.call_args[0][0]
        to_add = actual_call_arg["relations_to_add"]
        self.assertEqual(1, len(to_add))

        def assert_group_tuples(tuple_to_replicate):
            relation_tuple = relation_api_tuple(
                "role_binding", binding_mapping.mappings["id"], "subject", "group", str(group.uuid), "member"
            )

            self.assertIsNotNone(find_relation_in_list(tuple_to_replicate, relation_tuple))

        assert_group_tuples(to_add)

        url = reverse("group-roles", kwargs={"uuid": group.uuid})
        client = APIClient()

        url = "{}?roles={}".format(url, role.uuid)
        response = client.delete(url, format="json", **self.headers_org_admin)
        actual_call_arg = mock_method.call_args[0][0]
        to_remove = actual_call_arg["relations_to_remove"]
        self.assertEqual([], actual_call_arg["relations_to_add"])
        self.assertEqual(1, len(to_remove))

        assert_group_tuples(to_remove)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    @patch("management.group.relation_api_dual_write_group_handler.OutboxReplicator._save_replication_event")
    def test_add_and_remove_system_role_to_group(self, mock_method):
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create another group with 'User Access administrator' role we will try to update
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        user_access_admin_role = group_with_admin.roles()[0]
        request_body = {"roles": [user_access_admin_role.uuid]}

        url = reverse("group-roles", kwargs={"uuid": test_group.uuid})
        client = APIClient()
        response = client.post(url, request_body, format="json", **self.headers_org_admin)

        binding_mapping = BindingMapping.objects.filter(
            role=user_access_admin_role, resource_id=user_access_admin_role.tenant.org_id
        ).get()

        actual_call_arg = mock_method.call_args[0][0]
        to_add = actual_call_arg["relations_to_add"]
        self.assertEqual([], actual_call_arg["relations_to_remove"])
        self.assertEqual(3, len(to_add))

        def assert_group_tuples(tuple_to_replicate):
            relation_tuple = relation_api_tuple(
                "role_binding",
                binding_mapping.mappings["id"],
                "role",
                "role",
                str(user_access_admin_role.uuid),
            )
            self.assertIsNotNone(find_relation_in_list(tuple_to_replicate, relation_tuple))

            relation_tuple = relation_api_tuple(
                "role_binding",
                binding_mapping.mappings["id"],
                "subject",
                "group",
                str(test_group.uuid),
                "member",
            )

            self.assertIsNotNone(find_relation_in_list(tuple_to_replicate, relation_tuple))

            relation_tuple = relation_api_tuple(
                "workspace",
                test_group.tenant.org_id,
                "binding",
                "role_binding",
                str(binding_mapping.mappings["id"]),
            )

            self.assertIsNotNone(find_relation_in_list(tuple_to_replicate, relation_tuple))

        assert_group_tuples(to_add)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        url = reverse("group-roles", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        url = "{}?roles={}".format(url, user_access_admin_role.uuid)
        response = client.delete(url, format="json", **self.headers_org_admin)
        actual_call_arg = mock_method.call_args[0][0]
        to_remove = actual_call_arg["relations_to_remove"]
        self.assertEqual([], actual_call_arg["relations_to_add"])
        self.assertEqual(3, len(to_remove))

        assert_group_tuples(to_remove)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_update_group_with_User_Access_Admin_fail(self):
        """
        Test that non org admin with 'User Access administrator' role cannot update a group
        with 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create another group with 'User Access administrator' role we will try to update
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        user_access_admin_role = group_with_UA_admin.roles()[0]
        request_body = {"roles": [user_access_admin_role.uuid]}

        url = reverse("group-roles", kwargs={"uuid": test_group.uuid})
        client = APIClient()
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        # Role 'User Access administrator' added successfully into test group
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Try to update a group with 'User Access administrator'
        url = reverse("group-detail", kwargs={"uuid": test_group.uuid})
        request_body = {"name": "new name"}

        response = client.put(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        response = client.put(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        # Only Org Admin can update a group with 'User Access administrator'
        response = client.put(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch("management.role.relation_api_dual_write_handler.OutboxReplicator._save_replication_event")
    def test_remove_group_without_User_Access_Admin_fail(self, mock_method):
        """Test that non org admin without 'User Access administrator' role cannot remove a group."""
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        url = reverse("group-detail", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        response = client.delete(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)
        self.assertIsNone(mock_method.call_args)
        response = client.delete(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

    def test_remove_group_with_User_Access_Admin_success(self):
        """
        Test that non org admin with 'User Access administrator' role can remove a group
        without 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        client = APIClient()

        url = reverse("group-detail", kwargs={"uuid": test_group.uuid})
        response = client.delete(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        url = reverse("group-detail", kwargs={"uuid": test_group.uuid})
        response = client.delete(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_group_with_User_Access_Admin_fail(self):
        """
        Test that non org admin with 'User Access administrator' role cannot remove a group
        with 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create another group with 'User Access administrator' role we will try to remove
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        user_access_admin_role = group_with_UA_admin.roles()[0]
        request_body = {"roles": [user_access_admin_role.uuid]}

        url = reverse("group-roles", kwargs={"uuid": test_group.uuid})
        client = APIClient()
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        # Role 'User Access administrator' added successfully into test group
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Try to remove a group with 'User Access administrator'
        url = reverse("group-detail", kwargs={"uuid": test_group.uuid})

        response = client.delete(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        response = client.delete(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        # Only Org Admin can remove a group with 'User Access administrator'
        response = client.delete(url, **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_list_user_based_principals_in_group_without_User_Access_Admin_fail(self):
        """
        Test that non org admin without 'User Access administrator' role cannot list
        user based principals in group.
        """
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()
        test_group.principals.add(self.principal)
        test_group.save()

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Check that principal is in the db
        self.assertIsNotNone(Principal.objects.get(username=self.principal.username))

    def test_list_service_account_principals_in_group_without_User_Access_Admin_fail(self):
        """
        Test that non org admin without 'User Access administrator' role cannot list
        service account based principals in group.
        """
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()
        service_account_data = self._create_service_account_data()
        sa_principal = Principal(
            username=service_account_data["username"],
            tenant=self.tenant,
            type="service-account",
            service_account_id=service_account_data["client_id"],
        )
        sa_principal.save()
        test_group.principals.add(sa_principal)
        test_group.save()

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid}) + "?principal_type=service-account"
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Check that principal is in the db
        self.assertIsNotNone(Principal.objects.get(username=sa_principal.username))

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_list_user_based_principals_in_group_with_User_Access_Admin_success(self, mock_request):
        """
        Test that non org admin with 'User Access administrator' role can list
        user based principals in group.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()
        test_principal = Principal(username="test-principal", tenant=self.tenant)
        test_principal.save()
        test_group.principals.add(test_principal)
        test_group.save()

        # Set the return value for the mock
        mock_request.return_value["data"] = [{"username": test_principal.username}]

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        response = client.get(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

        response = client.get(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_list_service_account_principals_in_group_with_User_Access_Admin_success(self, mock_request):
        """
        Test that non org admin with 'User Access administrator' role can list
        service account based principals in group.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()
        service_account_data = self._create_service_account_data()
        sa_principal = Principal(
            username=service_account_data["username"],
            tenant=self.tenant,
            type="service-account",
            service_account_id=service_account_data["client_id"],
        )
        sa_principal.save()
        test_group.principals.add(sa_principal)
        test_group.save()

        # Set the return value for the mock
        sa_uuid = sa_principal.service_account_id
        mocked_values = [
            {
                "clientId": sa_uuid,
                "name": f"Service Account name",
                "description": f"Service Account description",
                "owner": "jsmith",
                "username": "service_account-" + sa_uuid,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]
        mock_request.return_value = mocked_values

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid}) + "?principal_type=service-account"
        client = APIClient()

        response = client.get(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

        response = client.get(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_add_user_based_principal_in_group_without_User_Access_Admin_fail(self, mock_request):
        """
        Test that non org admin without 'User Access administrator' role cannot add
        user based principal into a group without 'User Access administrator' role.
        """
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        test_principal = Principal(username="test-principal", tenant=self.tenant)
        test_principal.save()

        # Set the return value for the mock
        mock_request.return_value["data"] = [{"username": test_principal.username}]

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        request_body = {"principals": [{"username": test_principal.username}]}

        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Org Admin can add this principal into a group
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.role.relation_api_dual_write_handler.OutboxReplicator._save_replication_event")
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_add_service_account_principal_in_group_without_User_Access_Admin_fail(self, mock_request, mock_method):
        """
        Test that non org admin without 'User Access administrator' role cannot add
        service account based principal into a group without 'User Access administrator' role.
        """
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        service_account_data = self._create_service_account_data()
        sa_principal = Principal(
            username=service_account_data["username"],
            tenant=self.tenant,
            type="service-account",
            service_account_id=service_account_data["client_id"],
        )
        sa_principal.save()

        # Set the return value for the mock
        sa_uuid = sa_principal.service_account_id
        mocked_values = [
            {
                "clientId": sa_uuid,
                "name": f"Service Account name",
                "description": f"Service Account description",
                "owner": "jsmith",
                "username": "service_account-" + sa_uuid,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]
        mock_request.return_value = mocked_values

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        request_body = {"principals": [{"clientId": sa_uuid, "type": "service-account"}]}

        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Org Admin can add this principal into a group
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        actual_call_arg = mock_method.call_args[0][0]
        self.assertEqual(
            generate_replication_event_to_add_principals(str(test_group.uuid), str(sa_principal.uuid)), actual_call_arg
        )

    @patch("management.role.relation_api_dual_write_handler.OutboxReplicator._save_replication_event")
    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_add_user_based_principal_in_group_with_User_Access_Admin_success(self, mock_request, mock_method):
        """
        Test that non org admin with 'User Access administrator' role can add
        user based principal into a group without 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group and a principal
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        test_principal = Principal(username="test-principal", tenant=self.tenant)
        test_principal.save()

        # Set the return value for the mock
        mock_request.return_value["data"] = [{"username": test_principal.username}]

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        request_body = {"principals": [{"username": test_principal.username}]}

        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        actual_call_arg = mock_method.call_args[0][0]
        self.assertEqual(
            generate_replication_event_to_add_principals(str(test_group.uuid), str(test_principal.uuid)),
            actual_call_arg,
        )

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.role.relation_api_dual_write_handler.OutboxReplicator._save_replication_event")
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_add_service_account_principal_in_group_with_User_Access_Admin_success(self, mock_request, mock_method):
        """
        Test that non org admin with 'User Access administrator' role can add
        service account based principal into a group without 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group and a principal
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        service_account_data = self._create_service_account_data()
        sa_principal = Principal(
            username=service_account_data["username"],
            tenant=self.tenant,
            type="service-account",
            service_account_id=service_account_data["client_id"],
        )
        sa_principal.save()

        # Set the return value for the mock
        sa_uuid = sa_principal.service_account_id
        mocked_values = [
            {
                "clientId": sa_uuid,
                "name": f"Service Account name",
                "description": f"Service Account description",
                "owner": "jsmith",
                "username": "service_account-" + sa_uuid,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]
        mock_request.return_value = mocked_values

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        request_body = {"principals": [{"clientId": sa_uuid, "type": "service-account"}]}

        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        actual_call_arg = mock_method.call_args[0][0]
        self.assertEqual(
            generate_replication_event_to_add_principals(str(test_group.uuid), str(sa_principal.uuid)),
            actual_call_arg,
        )

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={"status_code": 200, "data": []},
    )
    def test_add_user_based_principal_in_group_with_User_Access_Admin_fail(self, mock_request):
        """
        Test that non org admin with 'User Access administrator' role cannot add
        user based principal into a group with 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group with 'User Access administrator' role and a principal
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        user_access_admin_role = group_with_UA_admin.roles()[0]
        request_body = {"roles": [user_access_admin_role.uuid]}

        url = reverse("group-roles", kwargs={"uuid": test_group.uuid})
        client = APIClient()
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        # Role 'User Access administrator' added successfully into test group
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        test_principal = Principal(username="test-principal", tenant=self.tenant)
        test_principal.save()

        # Set the return value for the mock
        mock_request.return_value["data"] = [{"username": test_principal.username}]

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        request_body = {"principals": [{"username": test_principal.username}]}

        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        # Only Org Admin can add a principal into a group with 'User Access administrator' role
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    @patch("management.principal.it_service.ITService.request_service_accounts")
    def test_add_service_account_principal_in_group_with_User_Access_Admin_fail(self, mock_request):
        """
        Test that non org admin with 'User Access administrator' role cannot add
        service account based principal into a group with 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group with 'User Access administrator' role and a principal
        test_group = Group.objects.create(name="test group", tenant=self.tenant)

        user_access_admin_role = group_with_UA_admin.roles()[0]
        request_body = {"roles": [user_access_admin_role.uuid]}

        url = reverse("group-roles", kwargs={"uuid": test_group.uuid})
        client = APIClient()
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        # Role 'User Access administrator' added successfully into test group
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        service_account_data = self._create_service_account_data()
        sa_principal = Principal(
            username=service_account_data["username"],
            tenant=self.tenant,
            type="service-account",
            service_account_id=service_account_data["client_id"],
        )
        sa_principal.save()

        # Set the return value for the mock
        sa_uuid = sa_principal.service_account_id
        mocked_values = [
            {
                "clientId": sa_uuid,
                "name": f"Service Account name",
                "description": f"Service Account description",
                "owner": "jsmith",
                "username": "service_account-" + sa_uuid,
                "time_created": 1706784741,
                "type": "service-account",
            }
        ]
        mock_request.return_value = mocked_values

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid})
        client = APIClient()

        request_body = {"principals": [{"clientId": sa_uuid, "type": "service-account"}]}

        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        # Only Org Admin can add a principal into a group with 'User Access administrator' role
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_remove_user_based_principal_from_group_without_User_Access_Admin_fail(self):
        """
        Test that non org admin without 'User Access administrator' role cannot remove
        user based principal from a group without 'User Access administrator' role.
        """
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()
        test_principal = Principal(username="test-principal", tenant=self.tenant)
        test_principal.save()
        test_group.principals.add(test_principal)
        test_group.save()

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid}) + f"?usernames={test_principal.username}"
        client = APIClient()

        response = client.delete(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.delete(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Org Admin can remove a principal from a group
        response = client.delete(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    def test_remove_service_account_principal_from_group_without_User_Access_Admin_fail(self):
        """
        Test that non org admin without 'User Access administrator' role cannot remove
        service account based principal from a group without 'User Access administrator' role.
        """
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        service_account_data = self._create_service_account_data()
        sa_principal = Principal(
            username=service_account_data["username"],
            tenant=self.tenant,
            type="service-account",
            service_account_id=service_account_data["client_id"],
        )
        sa_principal.save()
        test_group.principals.add(sa_principal)
        test_group.save()

        url = (
            reverse("group-principals", kwargs={"uuid": test_group.uuid})
            + f"?service-accounts={sa_principal.service_account_id}"
        )
        client = APIClient()

        response = client.delete(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.delete(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Org Admin can remove a principal from a group
        response = client.delete(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_user_based_principal_from_group_with_User_Access_Admin_success(self):
        """
        Test that non org admin with 'User Access administrator' role can remove
        user based principal from a group without 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()
        test_principal = Principal(username="test-principal", tenant=self.tenant)
        test_principal.save()
        test_group.principals.add(test_principal)
        test_group.save()

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid}) + f"?usernames={test_principal.username}"
        client = APIClient()

        response = client.delete(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Add once removed principal into group
        test_group.principals.add(test_principal)
        test_group.save()

        response = client.delete(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    @patch("management.role.relation_api_dual_write_handler.OutboxReplicator._save_replication_event")
    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    def test_remove_service_account_principal_from_group_with_User_Access_Admin_success(self, mock_method):
        """
        Test that non org admin with 'User Access administrator' role can remove
        service account based principal from a group without 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()
        service_account_data = self._create_service_account_data()
        sa_principal = Principal(
            username=service_account_data["username"],
            tenant=self.tenant,
            type="service-account",
            service_account_id=service_account_data["client_id"],
        )
        sa_principal.save()
        test_group.principals.add(sa_principal)
        test_group.save()

        url = (
            reverse("group-principals", kwargs={"uuid": test_group.uuid})
            + f"?service-accounts={sa_principal.service_account_id}"
        )
        client = APIClient()

        response = client.delete(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        actual_call_arg = mock_method.call_args[0][0]
        self.assertEqual(
            generate_replication_event_to_remove_principals(str(test_group.uuid), str(sa_principal.uuid)),
            actual_call_arg,
        )

        # Add once removed principal into group
        test_group.principals.add(sa_principal)
        test_group.save()

        response = client.delete(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_user_based_principal_from_group_with_User_Access_Admin_fail(self):
        """
        Test that non org admin with 'User Access administrator' role cannot remove
        user based principal from a group with 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group with 'User Access administrator' role and a principal
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        user_access_admin_role = group_with_UA_admin.roles()[0]
        request_body = {"roles": [user_access_admin_role.uuid]}

        url = reverse("group-roles", kwargs={"uuid": test_group.uuid})
        client = APIClient()
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        # Role 'User Access administrator' added successfully into test group
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        test_principal = Principal(username="test-principal", tenant=self.tenant)
        test_principal.save()
        test_group.principals.add(test_principal)
        test_group.save()

        url = reverse("group-principals", kwargs={"uuid": test_group.uuid}) + f"?usernames={test_principal.username}"
        client = APIClient()

        response = client.delete(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        response = client.delete(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        # Only Org admin can remove a principal from a group with 'User Access administrator' role
        response = client.delete(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    @override_settings(IT_BYPASS_TOKEN_VALIDATION=True)
    def test_remove_service_account_principal_from_group_with_User_Access_Admin_fail(self):
        """
        Test that non org admin with 'User Access administrator' role cannot remove
        service account based principal from a group with 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group with 'User Access administrator' role and a principal
        test_group = Group(name="test group", tenant=self.tenant)
        test_group.save()

        user_access_admin_role = group_with_UA_admin.roles()[0]
        request_body = {"roles": [user_access_admin_role.uuid]}

        url = reverse("group-roles", kwargs={"uuid": test_group.uuid})
        client = APIClient()
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        # Role 'User Access administrator' added successfully into test group
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        service_account_data = self._create_service_account_data()
        sa_principal = Principal(
            username=service_account_data["username"],
            tenant=self.tenant,
            type="service-account",
            service_account_id=service_account_data["client_id"],
        )
        sa_principal.save()
        test_group.principals.add(sa_principal)
        test_group.save()

        url = (
            reverse("group-principals", kwargs={"uuid": test_group.uuid})
            + f"?service-accounts={sa_principal.service_account_id}"
        )
        client = APIClient()

        response = client.delete(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        response = client.delete(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        # Only Org admin can remove a principal from a group with 'User Access administrator' role
        response = client.delete(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_list_roles_in_group_without_User_Access_Admin_fail(self):
        """Test that non org admin without 'User Access administrator' role cannot list roles in the group."""
        # Create a group, policy and role we need for the test
        group = Group.objects.create(name="test group", tenant=self.tenant)
        policy = Policy.objects.create(name="policy for test group", tenant=self.tenant)
        role = Role.objects.create(
            name="test role", description="test role description", system=False, tenant=self.tenant
        )
        policy.roles.add(role)
        group.policies.add(policy)

        url = reverse("group-roles", kwargs={"uuid": group.uuid})
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Check that role exists in the database
        self.assertIsNotNone(Role.objects.get(uuid=role.uuid))

        # Check that org admin can list the roles under group
        response = client.get(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

    def test_list_roles_in_group_with_User_Access_Admin_success(self):
        """Test that non org admin with 'User Access administrator' role can list roles in the group."""
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group, policy and role we need for the test
        group = Group.objects.create(name="test group", tenant=self.tenant)
        policy = Policy.objects.create(name="policy for test group", tenant=self.tenant)
        role = Role.objects.create(
            name="test role", description="test role description", system=False, tenant=self.tenant
        )
        policy.roles.add(role)
        group.policies.add(policy)

        url = reverse("group-roles", kwargs={"uuid": group.uuid})
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

    def test_add_role_in_group_without_User_Access_Admin_fail(self):
        """
        Test that non org admin without 'User Access administrator' role cannot add new role
        (different from 'User Access administrator') to the group without 'User Access administrator' role.
        """
        # Create a group and role we need for the test
        group = Group.objects.create(name="test group", tenant=self.tenant)
        role = Role.objects.create(
            name="test role", description="test role description", system=False, tenant=self.tenant
        )

        request_body = {"roles": [role.uuid]}
        url = reverse("group-roles", kwargs={"uuid": group.uuid})
        client = APIClient()

        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Check that org admin can add a role in group
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0].get("uuid"), str(role.uuid))

    def test_add_role_in_group_with_User_Access_Admin_success(self):
        """
        Test that non org admin with 'User Access administrator' role can add new role
        (different from 'User Access administrator') to the group without 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group and role we need for the test
        group = Group.objects.create(name="test group", tenant=self.tenant)
        role = Role.objects.create(
            name="test role", description="test role description", system=False, tenant=self.tenant
        )

        request_body = {"roles": [role.uuid]}
        url = reverse("group-roles", kwargs={"uuid": group.uuid})
        client = APIClient()

        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0].get("uuid"), str(role.uuid))

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0].get("uuid"), str(role.uuid))

    def test_add_User_Access_Admin_role_in_group_with_User_Access_Admin_fail(self):
        """
        Test that non org admin with 'User Access administrator' role cannot add the 'User Access
        administrator' role to the group.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group we need for the test
        group = Group.objects.create(name="test group", tenant=self.tenant)
        user_access_admin_role = group_with_UA_admin.roles()[0]

        request_body = {"roles": [user_access_admin_role.uuid]}
        url = reverse("group-roles", kwargs={"uuid": group.uuid})
        client = APIClient()

        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("errors")[0].get("detail"),
            self.user_access_admin_role_err_message.format(user_access_admin_role.display_name),
        )

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("errors")[0].get("detail"),
            self.user_access_admin_role_err_message.format(user_access_admin_role.display_name),
        )

        # Only Org Admin can add 'User Access administrator' role into a group
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0].get("uuid"), str(user_access_admin_role.uuid))

    def test_add_role_in_group_with_User_Access_Admin_fail(self):
        """
        Test that non org admin with 'User Access administrator' role cannot add new role
        (different from 'User Access administrator') to the group with 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a role we need for the test
        role = Role.objects.create(
            name="test role", description="test role description", system=False, tenant=self.tenant
        )

        request_body = {"roles": [role.uuid]}
        url = reverse("group-roles", kwargs={"uuid": group_with_UA_admin.uuid})
        client = APIClient()

        response = client.post(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        response = client.post(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        # Only Org Admin can add a role to a group with 'User Access administrator' role
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)

        role_uuid_from_response = [item.get("uuid") for item in response.data.get("data")]
        self.assertIn(str(role.uuid), role_uuid_from_response)

    def test_remove_role_from_group_without_User_Access_Admin_fail(self):
        """Test that non org admin without 'User Access administrator' role cannot remove a role from the group."""
        # Create a group, policy and role we need for the test
        group = Group.objects.create(name="test group", tenant=self.tenant)
        policy = Policy.objects.create(name="policy for test group", tenant=self.tenant)
        role = Role.objects.create(
            name="test role", description="test role description", system=False, tenant=self.tenant
        )
        policy.roles.add(role)
        group.policies.add(policy)

        url = reverse("group-roles", kwargs={"uuid": group.uuid}) + f"?roles={role.uuid}"
        client = APIClient()

        response = client.delete(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.delete(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Check that org admin can remove the roles from the group
        response = client.delete(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Check that the group doesn't contain the role anymore
        self.assertTrue(len(group.roles()) == 0)

    def test_remove_role_from_group_with_User_Access_Admin_success(self):
        """Test that non org admin with 'User Access administrator' role can remove a role from the group."""
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group, policy and role we need for the test
        group = Group.objects.create(name="test group", tenant=self.tenant)
        policy = Policy.objects.create(name="policy for test group", tenant=self.tenant)
        role = Role.objects.create(
            name="test role", description="test role description", system=False, tenant=self.tenant
        )
        policy.roles.add(role)
        group.policies.add(policy)

        url = reverse("group-roles", kwargs={"uuid": group.uuid}) + f"?roles={role.uuid}"
        client = APIClient()

        response = client.delete(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # Add the role again to the group for the test with service account in headers
        group.policies.add(policy)

        response = client.delete(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_role_from_group_with_User_Access_Admin_fail(self):
        """
        Test that non org admin with 'User Access administrator' role cannot remove a role
        (different from 'User Access administrator') from the group with 'User Access administrator' role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Add new role to the group with 'User Access administrator' role
        role = Role.objects.create(
            name="test role", description="test role description", system=False, tenant=self.tenant
        )
        request_body = {"roles": [role.uuid]}
        url = reverse("group-roles", kwargs={"uuid": group_with_UA_admin.uuid})
        client = APIClient()
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test that non org admin with 'User Access administrator' role cannot remove a role
        url = reverse("group-roles", kwargs={"uuid": group_with_UA_admin.uuid}) + f"?roles={role.uuid}"

        response = client.delete(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        response = client.delete(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        # Only Org Admin can remove role like this
        response = client.delete(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_User_Access_Admin_role_from_group_fail(self):
        """
        Test that non org admin with 'User Access administrator' role cannot remove the 'User Access administrator'
        role from the group.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group with 'User Access administrator' role
        group = Group.objects.create(name="test group", tenant=self.tenant)

        user_access_admin_role = group_with_UA_admin.roles()[0]
        request_body = {"roles": [user_access_admin_role.uuid]}

        url = reverse("group-roles", kwargs={"uuid": group.uuid})
        client = APIClient()
        response = client.post(url, request_body, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test that non org admin with 'User Access administrator' role cannot remove a role
        url = reverse("group-roles", kwargs={"uuid": group.uuid}) + f"?roles={user_access_admin_role.uuid}"

        response = client.delete(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        response = client.delete(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        # Only Org Admin can remove role like this
        response = client.delete(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_list_groups_without_User_Access_Admin_success(self):
        """Test that non org admin without 'User Access administrator' role cannot list groups."""
        url = reverse("group-list")
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

    def test_list_groups_with_User_Access_Admin_success(self):
        """Test that non org admin with 'User Access administrator' role can list groups."""
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        url = reverse("group-list")
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_read_group_without_User_Access_Admin_fail(self):
        """Test that non org admin without 'User Access administrator' role cannot read a group."""
        group = Group.objects.create(name="test group", tenant=self.tenant)

        url = reverse("group-detail", kwargs={"uuid": group.uuid})
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Org Admin can read detail of a group
        response = client.get(url, format="json", **self.headers_org_admin)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("uuid"), str(group.uuid))

    def test_read_group_with_User_Access_Admin_success(self):
        """Test that non org admin with 'User Access administrator' role can read a group."""
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        group = Group.objects.create(name="test group", tenant=self.tenant)

        url = reverse("group-detail", kwargs={"uuid": group.uuid})
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("uuid"), str(group.uuid))

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("uuid"), str(group.uuid))

    def test_read_group_with_scope_org_id_success(self):
        """
        Test that org admin and user with 'User Access administrator' role can list groups
        with '?scope=org_id' query param.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        url = reverse("group-list") + "?scope=org_id"
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = client.get(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_read_group_with_scope_org_id_fail(self):
        """
        Test that user without 'User Access administrator' role cannot list groups
        with '?scope=org_id' query param.
        """

        url = reverse("group-list") + "?scope=org_id"
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

    def test_read_group_with_scope_foo_fail(self):
        """
        Test that users cannot list groups with invalid '?scope=foo' query param.
        """
        url = reverse("group-list") + "?scope=foo"
        client = APIClient()

        # The response for non admins is 403
        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # The response for org admins and users with 'User Access administrator' role is 400
        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.invalid_value_for_scope_query_param)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.invalid_value_for_scope_query_param)

        response = client.get(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.invalid_value_for_scope_query_param)

    def test_read_group_with_scope_principal_success(self):
        """
        Test that users can list groups with '?scope=principal' query param.
        """
        url = reverse("group-list") + "?scope=principal"
        client = APIClient()

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 0)

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 0)

        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0]["uuid"], str(group_with_UA_admin.uuid))

        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0]["uuid"], str(group_with_UA_admin.uuid))

        response = client.get(url, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 0)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
    )
    def test_read_group_with_username_and_scope_params(self, mock):
        """
        Test that user based principal with 'User Access administrator' role can list groups
        with '?username=<value>' query param and adding the 'scope' param in the query doesn't
        affect the response.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal)

        mock.return_value = {
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": self.user_based_principal.username,
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        }

        # The usernames in header and in query are same
        client = APIClient()
        username_param = f"?username={self.user_based_principal.username}"
        url = reverse("group-list") + username_param

        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

        # Adding the 'scope' param doesn't affect the response because the 'scope' param is ignored
        # when query contains the 'username' param
        for scope in ("org_id", "principal"):
            url_with_scope = url + f"&scope={scope}"
            response = client.get(url_with_scope, format="json", **self.headers_user_based_principal)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(len(response.data.get("data")), 1)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
    )
    def test_read_group_with_username_param_and_user_based_rbac_admin(self, mock):
        """
        Test that user based principal with 'User Access administrator' role can list groups
        with '?username=<value>' query param.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal)

        # The usernames in header and in query are same
        client = APIClient()
        mock.return_value = {
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": self.user_based_principal.username,
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        }
        username_param = f"?username={self.user_based_principal.username}"
        url = reverse("group-list") + username_param
        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

        # The username in header and in query are not same
        username_param = f"?username={self.service_account_principal.username}"
        url = reverse("group-list") + username_param
        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 0)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
    )
    def test_read_group_with_username_param_and_user_based_non_admin(self, mock):
        """
        Test that user based principal without 'User Access administrator' role can list groups
        with '?username=<value>' query param only for themselves.
        """
        # The usernames in header and in query are same
        client = APIClient()
        mock.return_value = {
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": self.user_based_principal.username,
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        }
        username_param = f"?username={self.user_based_principal.username}"
        url = reverse("group-list") + username_param
        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 0)

        # The username in header and in query are not same
        username_param = f"?username={self.service_account_principal.username}"
        url = reverse("group-list") + username_param
        response = client.get(url, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
    )
    def test_read_group_with_username_param_and_service_account_based_rbac_admin(self, mock):
        """
        Test that service account based principal with 'User Access administrator' role can list groups
        with '?username=<value>' query param.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.service_account_principal)

        # The usernames in header and in query are same
        client = APIClient()

        username_param = f"?username={self.service_account_principal.username}"
        url = reverse("group-list") + username_param
        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)

        # The username in header and in query are not same
        mock.return_value = {
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": self.user_based_principal.username,
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        }
        username_param = f"?username={self.user_based_principal.username}"
        url = reverse("group-list") + username_param
        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 0)

    def test_read_group_with_username_param_and_service_account_based_non_admin(self):
        """
        Test that service account based principal without 'User Access administrator' role can list groups
        with '?username=<value>' query param only for themselves.
        """
        # The usernames in header and in query are same
        client = APIClient()
        username_param = f"?username={self.service_account_principal.username}"
        url = reverse("group-list") + username_param
        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 0)

        # The username in header and in query are not same
        username_param = f"?username={self.user_based_principal.username}"
        url = reverse("group-list") + username_param
        response = client.get(url, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

    def test_manipulate_with_group_with_rbac_read_permission(self):
        """
        Test that RBAC admin can manipulate with a group that contains RBAC viewer role.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_administrator_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        # Create a group with RBAC viewer role
        group_with_RBAC_viewer = Group.objects.create(name="test group", tenant=self.tenant)
        permission = Permission.objects.create(permission="rbac:principal:read", tenant=self.tenant)
        role = Role.objects.create(tenant=self.tenant, name="User Access principal viewer")
        access = Access.objects.create(permission=permission, role=role, tenant=self.tenant)
        policy = Policy.objects.create(group=group_with_RBAC_viewer, name="RBAC viewer policy", tenant=self.tenant)
        policy.roles.add(role)
        policy.save()

        # RBAC admin cannot update group with 'User Access administrator' role
        url = reverse("group-detail", kwargs={"uuid": group_with_UA_admin.uuid})
        request_body = {"name": "New name"}
        client = APIClient()

        response = client.put(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        response = client.put(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.user_access_admin_group_err_message)

        # RBAC admin can update group with 'User Access principal viewer' role
        url = reverse("group-detail", kwargs={"uuid": group_with_RBAC_viewer.uuid})

        response = client.put(url, request_body, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = client.put(url, request_body, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
