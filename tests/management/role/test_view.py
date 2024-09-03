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

import json
from uuid import uuid4

from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.test.utils import override_settings
from django.urls import reverse, resolve
from rest_framework import status
from rest_framework.test import APIClient

from management.cache import TenantCache
from management.models import (
    Group,
    Permission,
    Principal,
    Role,
    Access,
    Policy,
    ResourceDefinition,
    ExtRoleRelation,
    ExtTenant,
    Workspace,
    BindingMapping,
)

from tests.core.test_kafka import copy_call_args
from tests.identity_request import IdentityRequest
from unittest.mock import ANY, patch, call

URL = reverse("role-list")


def normalize_and_sort(json_obj):
    for key, value in json_obj.items():
        if isinstance(value, list):
            sorted_list = sorted([json.dumps(item, sort_keys=True, cls=DjangoJSONEncoder) for item in value])

            json_obj[key] = [json.loads(item) for item in sorted_list]
    return json_obj


def replication_event_for_v1_role(v1_role_uuid, root_workspace_uuid):
    """Create a replication event for a v1 role."""
    return {
        "relations_to_add": relation_api_tuples_for_v1_role(v1_role_uuid, root_workspace_uuid),
        "relations_to_remove": [],
    }


def relation_api_tuples_for_v1_role(v1_role_uuid, root_workspace_uuid):
    """Create a relation API tuple for a v1 role."""
    role_id = Role.objects.get(uuid=v1_role_uuid).id
    role_binding = BindingMapping.objects.filter(role=role_id).first()
    relations = []
    for role_binding_uuid, data in role_binding.mappings.items():
        relation_tuple = relation_api_tuple(
            "role_binding", str(role_binding_uuid), "granted", "role", str(data["v2_role_uuid"])
        )
        relations.append(relation_tuple)

        for permission in data["permissions"]:
            relation_tuple = relation_api_tuple("role", str(data["v2_role_uuid"]), permission, "user", "*")
            relations.append(relation_tuple)
        if "app_all_read" in data["permissions"]:
            relation_tuple = relation_api_tuple(
                "workspace", root_workspace_uuid, "user_grant", "role_binding", str(role_binding_uuid)
            )
            relations.append(relation_tuple)
        else:
            relation_tuple = relation_api_tuple("keya/id", "valueA", "workspace", "workspace", root_workspace_uuid)
            relations.append(relation_tuple)

            relation_tuple = relation_api_tuple(
                "keya/id", "valueA", "user_grant", "role_binding", str(role_binding_uuid)
            )
            relations.append(relation_tuple)
    return relations


def relation_api_tuple(resource_type, resource_id, relation, subject_type, subject_id):
    return {
        "resource": relation_api_resource(resource_type, resource_id),
        "relation": relation,
        "subject": relation_api_resource(subject_type, subject_id),
    }


def relation_api_resource(type_resource, id_resource):
    """Helper function for creating a relation resource in json."""
    return {"type": type_resource, "id": id_resource}


class RoleViewsetTests(IdentityRequest):
    """Test the role viewset."""

    def setUp(self):
        """Set up the role viewset tests."""
        super().setUp()
        sys_role_config = {"name": "system_role", "display_name": "system_display", "system": True}

        def_role_config = {"name": "default_role", "display_name": "default_display", "platform_default": True}

        admin_def_role_config = {
            "name": "admin_default_role",
            "display_name": "admin_default_display",
            "system": True,
            "admin_default": True,
        }

        platform_admin_def_role_config = {
            "name": "platform_admin_default_role",
            "display_name": "platform_admin_default_display",
            "system": True,
            "platform_default": True,
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
            "external_role_id",
            "external_tenant",
        }

        self.principal = Principal(username=self.user_data["username"], tenant=self.tenant)
        self.principal.save()
        self.policy = Policy.objects.create(name="policyA", tenant=self.tenant)
        self.group = Group(name="groupA", description="groupA description", tenant=self.tenant)
        self.group.save()
        self.group.principals.add(self.principal)
        self.group.policies.add(self.policy)
        self.group.save()

        self.policyTwo = Policy.objects.create(name="policyB", tenant=self.tenant)
        self.groupTwo = Group(name="groupB", description="groupB description", tenant=self.tenant)
        self.groupTwo.save()
        self.groupTwo.principals.add(self.principal)
        self.groupTwo.policies.add(self.policyTwo)
        self.groupTwo.save()

        self.adminRole = Role(**admin_def_role_config, tenant=self.tenant)
        self.adminRole.save()

        self.platformAdminRole = Role(**platform_admin_def_role_config, tenant=self.tenant)
        self.platformAdminRole.save()

        self.sysRole = Role(**sys_role_config, tenant=self.tenant)
        self.sysRole.save()

        self.defRole = Role(**def_role_config, tenant=self.tenant)
        self.defRole.save()
        self.defRole.save()

        self.ext_tenant = ExtTenant.objects.create(name="foo")
        self.ext_role_relation = ExtRoleRelation.objects.create(role=self.defRole, ext_tenant=self.ext_tenant)

        self.policy.roles.add(self.defRole, self.sysRole, self.adminRole, self.platformAdminRole)
        self.policy.save()

        self.policyTwo.roles.add(self.platformAdminRole)
        self.policyTwo.save()

        self.permission = Permission.objects.create(permission="app:*:*", tenant=self.tenant)
        self.permission2 = Permission.objects.create(permission="app2:*:*", tenant=self.tenant)
        self.permission3 = Permission.objects.create(permission="app:*:read", tenant=self.tenant)
        self.permission.permissions.add(self.permission3)
        self.access = Access.objects.create(permission=self.permission, role=self.defRole, tenant=self.tenant)
        self.access2 = Access.objects.create(permission=self.permission2, role=self.defRole, tenant=self.tenant)

        self.access3 = Access.objects.create(permission=self.permission2, role=self.sysRole, tenant=self.tenant)
        Permission.objects.create(permission="cost-management:*:*", tenant=self.tenant)
        self.root_workspace = Workspace.objects.create(name="root", description="Root workspace", tenant=self.tenant)

    def tearDown(self):
        """Tear down role viewset tests."""
        Group.objects.all().delete()
        Principal.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()
        Permission.objects.all().delete()
        Access.objects.all().delete()
        ExtTenant.objects.all().delete()
        ExtRoleRelation.objects.all().delete()
        Workspace.objects.all().delete()
        # we need to delete old test_tenant's that may exist in cache
        test_tenant_org_id = "100001"
        cached_tenants = TenantCache()
        cached_tenants.delete_tenant(test_tenant_org_id)

    def create_role(self, role_name, role_display="", in_access_data=None):
        """Create a role."""
        access_data = [
            {
                "permission": "app:*:*",
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "key1.id", "operation": "equal", "value": "value1"}}
                ],
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

    def create_group(self, group_name):
        """Create a group."""
        test_data = {"name": group_name, "description": "a group!"}
        url = reverse("group-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers)
        return response

    def create_policy(self, policy_name, group_uuid, role_uuids):
        """Create a policy to link a group to roles."""
        test_data = {"name": policy_name, "group": group_uuid, "roles": role_uuids}
        url = reverse("policy-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **self.headers)
        return response

    def add_principal_to_group(self, group_uuid, username):
        """Add principal to existing group."""
        url = reverse("group-principals", kwargs={"uuid": group_uuid})
        client = APIClient()
        test_data = {"principals": [{"username": username}]}
        response = client.post(url, test_data, format="json", **self.headers)
        return response

    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_create_role_success(self, send_kafka_message):
        """Test that we can create a role."""
        with self.settings(NOTIFICATIONS_ENABLED=True):
            role_name = "roleA"
            access_data = [
                {
                    "permission": "app:*:*",
                    "resourceDefinitions": [
                        {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                    ],
                },
                {"permission": "app:*:read", "resourceDefinitions": []},
            ]
            response = self.create_role(role_name, in_access_data=access_data)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

            # test whether newly created role is added correctly within audit log database
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
            self.assertEqual(al_dict_resource, "role")
            self.assertEqual(al_dict_action, "create")

            # test that we can retrieve the role
            url = reverse("role-detail", kwargs={"uuid": response.data.get("uuid")})
            client = APIClient()
            response = client.get(url, **self.headers)
            uuid = response.data.get("uuid")
            role = Role.objects.get(uuid=uuid)

            org_id = self.customer_data["org_id"]

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
            send_kafka_message.assert_called_with(
                settings.NOTIFICATIONS_TOPIC,
                {
                    "bundle": "console",
                    "application": "rbac",
                    "event_type": "custom-role-created",
                    "timestamp": ANY,
                    "events": [
                        {
                            "metadata": {},
                            "payload": {
                                "name": role.name,
                                "username": self.user_data["username"],
                                "uuid": str(role.uuid),
                            },
                        }
                    ],
                    "org_id": org_id,
                },
                ANY,
            )

    @patch("management.role.relation_api_dual_write_handler.RelationApiDualWriteHandler._save_replication_event")
    def test_create_role_with_display_success(self, mock_method):
        """Test that we can create a role."""
        role_name = "roleD"
        role_display = "display name for roleD"
        access_data = [
            {
                "permission": "app:*:*",
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
            },
            {"permission": "app:*:read", "resourceDefinitions": []},
        ]
        response = self.create_role(role_name, role_display=role_display, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        replication_event = replication_event_for_v1_role(response.data.get("uuid"), str(self.root_workspace.uuid))

        mock_method.assert_called_once()
        actual_call_arg = mock_method.call_args[0][0]
        expected_sorted = normalize_and_sort(replication_event)
        actual_sorted = normalize_and_sort(actual_call_arg)
        self.assertEqual(set(expected_sorted), set(actual_sorted))

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
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
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
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
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
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
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
                "resourceDefinitions": {"attributeFilter": {"key": "keyA.id", "operation": "in", "foo": "valueA"}},
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
                "resourceDefinitions": [{"attributeFilter": {"key": "keyA.id", "operation": "in", "foo": "valueA"}}],
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
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "boop", "value": "valueA"}}
                ],
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
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
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

        # list a role
        client = APIClient()
        response = client.get(URL, **self.headers)

        # three parts in response: meta, links and data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 5)

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

    def test_get_role_by_application_using_ext_tenant(self):
        """Test that getting roles by application returns roles based on external tenant name."""
        url = "{}?application={}".format(URL, "foo")
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
        url = "{}?application={}".format(URL, "foobar")
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
        self.assertEqual(response.data.get("meta").get("count"), 4)

    def test_get_role_by_partial_name_explicit(self):
        """Test that getting roles by name returns partial match when specified."""
        url = "{}?name={}&name_match={}".format(URL, "role", "partial")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 4)

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
        self.assertEqual(response.data.get("meta").get("count"), 4)

    def test_get_role_by_partial_display_name_explicit(self):
        """Test that getting roles by display_name returns partial match when specified."""
        url = "{}?display_name={}&name_match={}".format(URL, "display", "partial")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get("meta").get("count"), 4)

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

    @patch("management.principal.proxy.PrincipalProxy.request_filtered_principals")
    def test_list_role_with_groups_in_fields_with_username_param_for_non_org_admin(self, mock_request):
        """
        Test that we can read a list of roles and the groups_in fields is set correctly
        for a request with 'username' param for non org admin principal.
        """
        # Set existing groups as system groups
        default_access_group_name = "Default access"
        self.group.name = default_access_group_name
        self.group.system = self.group.platform_default = True
        self.group.save()

        default_admin_access_group_name = "Default admin access"
        self.groupTwo.name = default_admin_access_group_name
        self.groupTwo.system = self.groupTwo.admin_default = True
        self.groupTwo.save()

        # create a custom role
        custom_role_name = "NewRoleForJohn"
        custom_role = self.create_role(custom_role_name)
        self.assertEqual(custom_role.status_code, status.HTTP_201_CREATED)
        custom_role_uuid = custom_role.data.get("uuid")

        # create a custom group
        custom_group_name = "NewGroupForJohn"
        custom_group = self.create_group(custom_group_name)
        self.assertEqual(custom_group.status_code, status.HTTP_201_CREATED)
        custom_group_uuid = custom_group.data.get("uuid")

        # create a policy to link the role and group
        custom_policy_name = "NewPolicyForJohn"
        custom_policy = self.create_policy(custom_policy_name, custom_group_uuid, [custom_role_uuid])
        self.assertEqual(custom_policy.status_code, status.HTTP_201_CREATED)

        # create a principal
        john = Principal(username="john", tenant=self.tenant)

        # Mock return value for request_filtered_principals() -> user is NOT org admin
        mock_request.return_value = {
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": john.username,
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        }

        # add principal to the created group
        principal_response = self.add_principal_to_group(custom_group_uuid, john.username)
        self.assertEqual(principal_response.status_code, status.HTTP_200_OK, principal_response)

        # add groups_in and groups_in_count fields into display fields
        groups_in_count = "groups_in_count"
        groups_in = "groups_in"
        new_display_fields = self.display_fields
        new_display_fields.add(groups_in_count)
        new_display_fields.add(groups_in)

        url = f"{URL}?add_fields={groups_in_count},{groups_in}&username={john.username}"
        client = APIClient()
        response = client.get(url, **self.headers)

        # three parts in response: meta, links and data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)

        response_data = response.data.get("data")

        for iterRole in response_data:
            # fields displayed are same as defined incl. groups_in and groups_in_count
            self.assertEqual(new_display_fields, set(iterRole.keys()))
            self.assertIsNotNone(iterRole.get(groups_in)[0]["name"])
            self.assertIsNotNone(iterRole.get(groups_in)[0]["uuid"])
            self.assertIsNotNone(iterRole.get(groups_in)[0]["description"])

        # make sure created role exists in result set and has correct values
        created_role = next((iterRole for iterRole in response_data if iterRole["name"] == custom_role_name), None)
        self.assertIsNotNone(created_role)
        self.assertEqual(created_role[groups_in_count], 1)
        self.assertEqual(created_role[groups_in][0]["name"], custom_group_name)

        # make sure all roles are from:
        #       * custom group 'NewGroupForJohn' or
        #       * 'Default access' group
        groups = [default_access_group_name, custom_group_name]
        for role in response_data:
            for group in role[groups_in]:
                self.assertIn(group["name"], groups)

    @patch("management.principal.proxy.PrincipalProxy.request_filtered_principals")
    def test_list_role_with_groups_in_fields_with_username_param_for_org_admin(self, mock_request):
        """
        Test that we can read a list of roles and the groups_in fields is set correctly
        for a request with 'username' param for org admin principal.
        """
        # Set existing groups as system groups
        default_access_group_name = "Default access"
        self.group.name = default_access_group_name
        self.group.system = self.group.platform_default = True
        self.group.save()

        default_admin_access_group_name = "Default admin access"
        self.groupTwo.name = default_admin_access_group_name
        self.groupTwo.system = self.groupTwo.admin_default = True
        self.groupTwo.save()

        # create a custom role
        custom_role_name = "NewRoleForMary"
        custom_role = self.create_role(custom_role_name)
        self.assertEqual(custom_role.status_code, status.HTTP_201_CREATED)
        custom_role_uuid = custom_role.data.get("uuid")

        # create a custom group
        custom_group_name = "NewGroupForMary"
        custom_group = self.create_group(custom_group_name)
        self.assertEqual(custom_group.status_code, status.HTTP_201_CREATED)
        custom_group_uuid = custom_group.data.get("uuid")

        # create a policy to link the role and group
        custom_policy_name = "NewPolicyForMary"
        custom_policy = self.create_policy(custom_policy_name, custom_group_uuid, [custom_role_uuid])
        self.assertEqual(custom_policy.status_code, status.HTTP_201_CREATED)

        # create a principal
        mary = Principal(username="mary", tenant=self.tenant)

        # Mock return value for request_filtered_principals() -> user is NOT org admin
        mock_request.return_value = {
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": True,
                    "is_internal": False,
                    "id": 52567473,
                    "username": mary.username,
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        }

        # add principal to the created group
        principal_response = self.add_principal_to_group(custom_group_uuid, mary.username)
        self.assertEqual(principal_response.status_code, status.HTTP_200_OK, principal_response)

        # add groups_in and groups_in_count fields into display fields
        groups_in_count = "groups_in_count"
        groups_in = "groups_in"
        new_display_fields = self.display_fields
        new_display_fields.add(groups_in_count)
        new_display_fields.add(groups_in)

        url = f"{URL}?add_fields={groups_in_count},{groups_in}&username={mary.username}"
        client = APIClient()
        response = client.get(url, **self.headers)

        # three parts in response: meta, links and data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)

        response_data = response.data.get("data")

        for iterRole in response_data:
            # fields displayed are same as defined incl. groups_in and groups_in_count
            self.assertEqual(new_display_fields, set(iterRole.keys()))
            self.assertIsNotNone(iterRole.get(groups_in)[0]["name"])
            self.assertIsNotNone(iterRole.get(groups_in)[0]["uuid"])
            self.assertIsNotNone(iterRole.get(groups_in)[0]["description"])

        # make sure created role exists in result set and has correct values
        created_role = next((iterRole for iterRole in response_data if iterRole["name"] == custom_role_name), None)
        self.assertIsNotNone(created_role)
        self.assertEqual(created_role[groups_in_count], 1)
        self.assertEqual(created_role[groups_in][0]["name"], custom_group_name)

        # make sure all roles are from:
        #       * custom group 'NewGroupForJohn' or
        #       * 'Default access' group
        #       * 'Default admin access' group
        groups = [default_access_group_name, default_admin_access_group_name, custom_group_name]
        for role in response_data:
            for group in role[groups_in]:
                self.assertIn(group["name"], groups)

    @patch("management.principal.proxy.PrincipalProxy.request_filtered_principals")
    def test_list_role_with_groups_in_fields_for_principal_scope_success(self, mock_request):
        """
        Test that we can read a list of roles and the groups_in fields is set correctly
        for a principal scoped request.
        """
        mock_request.return_value = {
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": True,
                    "is_internal": False,
                    "id": 52567473,
                    "username": self.principal.username,
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        }

        # create a role
        role_name = "groupsInRole"
        created_role = self.create_role("groupsInRole")
        self.assertEqual(created_role.status_code, status.HTTP_201_CREATED)
        role_uuid = created_role.data.get("uuid")

        # create a group
        group_name = "groupsInGroup"
        created_group = self.create_group(group_name)
        self.assertEqual(created_group.status_code, status.HTTP_201_CREATED)
        group_uuid = created_group.data.get("uuid")

        # create a policy to link the 2
        policy_name = "groupsInPolicy"
        created_policy = self.create_policy(policy_name, group_uuid, [role_uuid])
        self.assertEqual(created_policy.status_code, status.HTTP_201_CREATED)

        # add user principal to the created group
        principal_response = self.add_principal_to_group(group_uuid, self.principal.username)
        self.assertEqual(principal_response.status_code, status.HTTP_200_OK, principal_response)

        # hit /roles?groups_in, group should appear in groups_in
        field_1 = "groups_in_count"
        field_2 = "groups_in"
        new_display_fields = self.display_fields
        new_display_fields.add(field_1)
        new_display_fields.add(field_2)

        url = "{}?add_fields={},{}&username={}".format(URL, field_1, field_2, self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)

        # three parts in response: meta, links and data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)

        response_data = response.data.get("data")

        for iterRole in response_data:
            # fields displayed are same as defined, groupsInCount is added
            self.assertEqual(new_display_fields, set(iterRole.keys()))
            self.assertIsNotNone(iterRole.get("groups_in")[0]["name"])
            self.assertIsNotNone(iterRole.get("groups_in")[0]["uuid"])
            self.assertIsNotNone(iterRole.get("groups_in")[0]["description"])

        # make sure created role exists in result set and has correct values
        created_role = next((iterRole for iterRole in response_data if iterRole["name"] == role_name), None)
        self.assertIsNotNone(created_role)
        self.assertEqual(created_role["groups_in_count"], 1)
        self.assertEqual(created_role["groups_in"][0]["name"], group_name)

        # make sure a default role exists in result set and has correct values
        default_role = next((iterRole for iterRole in response_data if iterRole["name"] == self.defRole.name), None)
        self.assertIsNotNone(default_role)
        self.assertEqual(default_role["groups_in_count"], 1)
        self.assertEqual(default_role["groups_in"][0]["name"], self.group.name)

    def test_list_role_with_groups_in_fields_for_admin_scope_success(self):
        """
        Test that we can read a list of roles and the groups_in fields is set correctly
        for an admin scoped request.
        """
        field_1 = "groups_in_count"
        field_2 = "groups_in"
        new_display_fields = self.display_fields
        new_display_fields.add(field_1)
        new_display_fields.add(field_2)

        url = "{}?add_fields={},{}".format(URL, field_1, field_2)
        client = APIClient()
        response = client.get(url, **self.headers)

        # three parts in response: meta, links and data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)

        response_data = response.data.get("data")

        for iterRole in response_data:
            # fields displayed are same as defined, groupsInCount is added
            self.assertEqual(new_display_fields, set(iterRole.keys()))
            self.assertIsNotNone(iterRole.get("groups_in")[0]["name"])
            self.assertIsNotNone(iterRole.get("groups_in")[0]["uuid"])
            self.assertIsNotNone(iterRole.get("groups_in")[0]["description"])

        # make sure a default role exists in result set and has correct values
        default_role = next((iterRole for iterRole in response_data if iterRole["name"] == self.defRole.name), None)
        self.assertIsNotNone(default_role)
        self.assertEqual(default_role["groups_in_count"], 1)
        self.assertEqual(default_role["groups_in"][0]["name"], self.group.name)

        # make sure an admin role exists in result set and has correct values
        admin_role = next((iterRole for iterRole in response_data if iterRole["name"] == self.adminRole.name), None)
        self.assertIsNotNone(admin_role)
        self.assertEqual(admin_role["groups_in_count"], 1)
        self.assertEqual(admin_role["groups_in"][0]["name"], self.group.name)

    def test_list_role_with_username_forbidden_to_nonadmin(self):
        """Test that non admin can not read a list of roles for username."""
        # Setup non admin request
        non_admin_request_context = self._create_request_context(
            self.customer_data, self.user_data, is_org_admin=False
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

    @patch("management.principal.proxy.PrincipalProxy.request_filtered_principals")
    def test_list_role_with_additional_fields_username_success(self, mock_request):
        """Test that we can read a list of roles and add fields for username."""
        field_1 = "groups_in_count"
        field_2 = "groups_in"
        new_display_fields = self.display_fields
        new_display_fields.add(field_1)
        new_display_fields.add(field_2)

        mock_request.return_value = {
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": True,
                    "is_internal": False,
                    "id": 52567473,
                    "username": self.principal.username,
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        }

        url = "{}?add_fields={},{}&username={}".format(URL, field_1, field_2, self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 4)

        role = response.data.get("data")[0]
        self.assertEqual(new_display_fields, set(role.keys()))
        self.assertEqual(role["groups_in_count"], 1)

    def test_list_role_with_additional_fields_principal_success(self):
        """Test that we can read a list of roles and add fields for principal."""
        field_1 = "groups_in_count"
        field_2 = "groups_in"
        new_display_fields = self.display_fields
        new_display_fields.add(field_1)
        new_display_fields.add(field_2)

        url = "{}?add_fields={},{}&scope=principal".format(URL, field_1, field_2)
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 4)

        role = response.data.get("data")[0]
        self.assertEqual(new_display_fields, set(role.keys()))
        self.assertEqual(role["groups_in_count"], 1)

    def test_list_role_with_additional_fields_access(self):
        """Test that we can read a list of roles and add field access."""
        field = "access"
        expected_fields = self.display_fields
        expected_fields.add(field)

        # list a role
        url = f"{URL}?add_fields={field}"
        client = APIClient()
        response = client.get(url, **self.headers)

        # three parts in response: meta, links and data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)

        self.assertIsInstance(response.data.get("data"), list)

        for iterRole in response.data.get("data"):
            # fields displayed are same as defined, field "access" is added
            self.assertEqual(expected_fields, set(iterRole.keys()))
            # if the role contains permissions, then check structure of access field
            if iterRole.get("accessCount") > 0:
                self.assertIsNotNone(iterRole.get("access"))
                for item in iterRole.get("access"):
                    for key in ["resourceDefinitions", "permission"]:
                        self.assertIn(key, item)

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

        # test whether newly edited (PATCH) role is added correctly within audit log database
        al_url = "/api/v1/auditlogs/"
        al_client = APIClient()
        al_response = al_client.get(al_url, **self.headers)
        retrieve_data = al_response.data.get("data")
        al_list = retrieve_data
        al_dict = al_list[1]

        al_dict_principal_username = al_dict["principal_username"]
        al_dict_description = al_dict["description"]
        al_dict_resource = al_dict["resource_type"]
        al_dict_action = al_dict["action"]

        self.assertEqual(self.user_data["username"], al_dict_principal_username)
        self.assertIsNotNone(al_dict_description)
        self.assertEqual(al_dict_resource, "role")
        self.assertEqual(al_dict_action, "edit")

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

    def test_patch_role_without_payload(self):
        """Test that we no-op when no payload supplied."""
        role_name = "role"
        response = self.create_role(role_name)
        updated_name = role_name + "_update"
        updated_description = role_name + "This is a test"
        role_uuid = response.data.get("uuid")
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        response = client.patch(
            url,
            format="json",
            **self.headers,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_update_role_success(self, send_kafka_message):
        """Test that we can update an existing role."""
        kafka_mock = copy_call_args(send_kafka_message)
        with self.settings(NOTIFICATIONS_ENABLED=True):
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

            org_id = self.customer_data["org_id"]

            self.assertEqual(response.status_code, status.HTTP_200_OK)

            self.assertIsNotNone(response.data.get("uuid"))
            self.assertEqual(updated_name, response.data.get("name"))
            self.assertEqual("cost-management:*:*", response.data.get("access")[0]["permission"])

            # test whether newly updatecd (post) role is added correctly within audit log database
            al_url = "/api/v1/auditlogs/"
            al_client = APIClient()
            al_response = al_client.get(al_url, **self.headers)
            retrieve_data = al_response.data.get("data")
            al_list = retrieve_data
            al_dict = al_list[1]

            al_dict_principal_username = al_dict["principal_username"]
            al_dict_description = al_dict["description"]
            al_dict_resource = al_dict["resource_type"]
            al_dict_action = al_dict["action"]

            self.assertEqual(self.user_data["username"], al_dict_principal_username)
            self.assertIsNotNone(al_dict_description)
            self.assertEqual(al_dict_resource, "role")
            self.assertEqual(al_dict_action, "edit")

            kafka_mock.assert_called_with(
                settings.NOTIFICATIONS_TOPIC,
                {
                    "bundle": "console",
                    "application": "rbac",
                    "event_type": "custom-role-updated",
                    "timestamp": ANY,
                    "events": [
                        {
                            "metadata": {},
                            "payload": {
                                "name": updated_name,
                                "username": self.user_data["username"],
                                "uuid": response.data.get("uuid"),
                            },
                        }
                    ],
                    "org_id": org_id,
                },
                ANY,
            )

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
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
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

    @patch("management.role.relation_api_dual_write_handler.RelationApiDualWriteHandler._save_replication_event")
    def test_update_role(self, mock_method):
        """Test that updating a role with an invalid permission returns an error."""
        # Set up
        role_name = "test_update_role"
        access_data = [
            {
                "permission": "app:*:*",
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
            },
            {"permission": "app:*:read", "resourceDefinitions": []},
        ]

        new_access_data = [
            {
                "permission": "app:*:*",
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
            },
            {"permission": "app:*:read", "resourceDefinitions": []},
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        test_data = response.data
        test_data["access"] = new_access_data
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        current_relations = relation_api_tuples_for_v1_role(role_uuid, str(self.root_workspace.uuid))

        response = client.put(url, test_data, format="json", **self.headers)
        replication_event = replication_event_for_v1_role(response.data.get("uuid"), str(self.root_workspace.uuid))
        replication_event["relations_to_remove"] = current_relations
        actual_call_arg = mock_method.call_args[0][0]
        expected_sorted = normalize_and_sort(replication_event)
        actual_sorted = normalize_and_sort(actual_call_arg)
        self.assertEqual(set(expected_sorted), set(actual_sorted))

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_update_role_invalid_resource_defs_structure(self):
        """Test that updating a role with an invalid resource definitions returns an error."""
        # Set up
        role_name = "permRole"
        access_data = [
            {
                "permission": "cost-management:*:*",
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
            }
        ]
        response = self.create_role(role_name, in_access_data=access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get("uuid")
        test_data = response.data
        test_data.get("access")[0]["resourceDefinitions"] = {
            "attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}
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
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
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
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
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

    @patch("management.role.relation_api_dual_write_handler.RelationApiDualWriteHandler._save_replication_event")
    def test_delete_role(self, mock_method):
        """Test that we can delete an existing role."""
        role_name = "roleA"
        access_data = [
            {
                "permission": "app:*:*",
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "keyA.id", "operation": "equal", "value": "valueA"}}
                ],
            },
            {"permission": "app:*:read", "resourceDefinitions": []},
        ]
        response = self.create_role(role_name, in_access_data=access_data)

        role_uuid = response.data.get("uuid")
        url = reverse("role-detail", kwargs={"uuid": role_uuid})
        client = APIClient()
        replication_event = {"relations_to_add": [], "relations_to_remove": []}
        current_relations = relation_api_tuples_for_v1_role(role_uuid, str(self.root_workspace.uuid))
        replication_event["relations_to_remove"] = current_relations
        response = client.delete(url, **self.headers)
        actual_call_arg = mock_method.call_args[0][0]
        expected_sorted = normalize_and_sort(replication_event)
        actual_sorted = normalize_and_sort(actual_call_arg)
        self.assertEqual(set(expected_sorted), set(actual_sorted))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_delete_role_success(self, send_kafka_message):
        """Test that we can delete an existing role."""
        with self.settings(NOTIFICATIONS_ENABLED=True):
            role_name = "roleA"
            response = self.create_role(role_name)

            role_uuid = response.data.get("uuid")
            url = reverse("role-detail", kwargs={"uuid": role_uuid})
            client = APIClient()
            response = client.delete(url, **self.headers)

            org_id = self.customer_data["org_id"]

            self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
            # test whether correctly added to audit logs
            al_url = "/api/v1/auditlogs/"
            al_client = APIClient()
            al_response = al_client.get(al_url, **self.headers)
            retrieve_data = al_response.data.get("data")
            al_list = retrieve_data
            al_dict = al_list[1]

            al_dict_principal_username = al_dict["principal_username"]
            al_dict_description = al_dict["description"]
            al_dict_resource = al_dict["resource_type"]
            al_dict_action = al_dict["action"]

            self.assertEqual(self.user_data["username"], al_dict_principal_username)
            self.assertIsNotNone(al_dict_description)
            self.assertEqual(al_dict_resource, "role")
            self.assertEqual(al_dict_action, "delete")

            send_kafka_message.assert_called_with(
                settings.NOTIFICATIONS_TOPIC,
                {
                    "bundle": "console",
                    "application": "rbac",
                    "event_type": "custom-role-deleted",
                    "timestamp": ANY,
                    "events": [
                        {
                            "metadata": {},
                            "payload": {
                                "name": role_name,
                                "username": self.user_data["username"],
                                "uuid": role_uuid,
                            },
                        }
                    ],
                    "org_id": org_id,
                },
                ANY,
            )

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
                "resourceDefinitions": [
                    {"attributeFilter": {"key": "key1.id", "operation": "equal", "value": "value1"}}
                ],
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

        self.assertEqual(len(response.data.get("data")), 4)

        url = f"{URL}?system=true"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 3)
        role = response.data.get("data")[0]
        self.assertEqual(role.get("system"), True)

        url = f"{URL}?system=false"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 1)
        role = response.data.get("data")[0]
        self.assertEqual(role.get("system"), False)

    def test_external_tenant_filter(self):
        """Test that we can filter roles based on external_tenant."""
        client = APIClient()
        response = client.get(URL, **self.headers)

        self.assertEqual(len(response.data.get("data")), 4)

        url = f"{URL}?external_tenant=foo"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 1)
        role = response.data.get("data")[0]
        self.assertEqual(role.get("external_tenant"), "foo")

    def test_list_role_admin_platform_default_groups(self):
        """Test roles with both admin and platform default groups."""
        client = APIClient()
        response = client.get(URL, **self.headers)

        self.assertEqual(len(response.data.get("data")), 4)

        url = f"{URL}?display_name=platform_admin_default_display&add_fields=groups_in_count%2Cgroups_in"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(len(response.data.get("data")), 1)
        role = response.data.get("data")[0]
        self.assertEqual(role.get("groups_in_count"), 2)


class RoleViewNonAdminTests(IdentityRequest):
    """Test the role view for nonadmin user."""

    def setUp(self):
        """Set up the role viewset nonadmin tests."""
        super().setUp()

        platform_default_role_config = {
            "name": "platform_default_role",
            "display_name": "Platform Default Role",
            "system": True,
            "platform_default": True,
            "admin_default": False,
        }
        self.platform_default_role = Role.objects.create(**platform_default_role_config, tenant=self.tenant)

        admin_default_role_config = {
            "name": "admin_default_role",
            "display_name": "Admin Default Role",
            "system": True,
            "platform_default": False,
            "admin_default": True,
        }
        self.admin_default_role = Role.objects.create(**admin_default_role_config, tenant=self.tenant)

        not_system_role_config = {
            "name": "not_system_role",
            "display_name": "Not System Role",
            "system": False,
            "platform_default": False,
            "admin_default": False,
        }

        self.not_system_role = Role.objects.create(**not_system_role_config, tenant=self.tenant)

        self.system_roles_count = 2
        self.non_system_roles_count = 1

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
            "external_role_id",
            "external_tenant",
        }

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

    def tearDown(self):
        """Tear down role viewset nonadmin tests."""
        Group.objects.all().delete()
        Principal.objects.all().delete()
        Role.objects.all().delete()

        # we need to delete old test_tenant's that may exist in cache
        test_tenant_org_id = "100001"
        cached_tenants = TenantCache()
        cached_tenants.delete_tenant(test_tenant_org_id)

    @staticmethod
    def _create_group_with_user_access_admin_role(tenant):
        """Create a group with a 'User Access administrator' role."""
        # Create a group with 'User Access administrator' role
        rbac_admin_permission = Permission.objects.create(
            application="rbac", permission="rbac:*:*", resource_type="*", verb="*", tenant=tenant
        )
        user_access_administrator_role = Role.objects.create(
            admin_default=True,
            description="User Access administrator role description",
            display_name="User Access administrator",
            platform_default=False,
            system=True,
            tenant=tenant,
        )
        Access.objects.create(permission=rbac_admin_permission, role=user_access_administrator_role, tenant=tenant)
        rbac_admin_group = Group.objects.create(
            admin_default=False,
            description="A group with the 'User Access administrator' role",
            name="rbac_admin_group",
            platform_default=False,
            system=False,
            tenant=tenant,
        )
        policy_for_rbac_admin_group = Policy.objects.create(
            group=rbac_admin_group, name="Policy for rbac_admin_group", system=True, tenant=tenant
        )
        policy_for_rbac_admin_group.roles.add(user_access_administrator_role)
        return rbac_admin_group

    def test_list_roles_without_User_Access_Admin_fail(self):
        """
        Test that principal without 'User Access administrator' role cannot read a list of roles.
        """
        client = APIClient()
        url = reverse("role-list")

        response = client.get(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.get(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Org Admin can list the roles
        response = client.get(url, **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_count = self.system_roles_count + self.non_system_roles_count
        self.assertEqual(len(response.data.get("data")), expected_count)

    def test_list_roles_with_User_Access_Admin_success(self):
        """
        Test that principal with 'User Access administrator' role can read a list of roles.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_admin_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        client = APIClient()
        url = reverse("role-list")

        response = client.get(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_count = self.system_roles_count + self.non_system_roles_count + 1
        self.assertEqual(len(response.data.get("data")), expected_count)

        response = client.get(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_count = self.system_roles_count + self.non_system_roles_count + 1
        self.assertEqual(len(response.data.get("data")), expected_count)

    def test_list_roles_without_User_Access_Admin_system_true_success(self):
        """
        Test that principal without 'User Access administrator' role can read a list of roles
        with '?system=true' in the request.
        """
        client = APIClient()
        url = reverse("role-list") + "?system=true"

        response = client.get(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), self.system_roles_count)

        response = client.get(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), self.system_roles_count)

    def test_list_roles_with_User_Access_Admin_system_true_success(self):
        """
        Test that principal with 'User Access administrator' role can read a list of roles
        with '?system=true' in the request.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_admin_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)
        client = APIClient()
        url = reverse("role-list") + "?system=true"

        response = client.get(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_count = self.system_roles_count + 1
        self.assertEqual(len(response.data.get("data")), expected_count)

        response = client.get(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_count = self.system_roles_count + 1
        self.assertEqual(len(response.data.get("data")), expected_count)

    def test_list_roles_without_User_Access_Admin_system_false_fail(self):
        """
        Test that principal without 'User Access administrator' role cannot read a list of roles
        with '?system=false' in the request.
        """
        client = APIClient()
        url = reverse("role-list") + "?system=false"

        response = client.get(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.get(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Org Admin can list the roles
        response = client.get(url, **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), self.non_system_roles_count)

    def test_list_roles_with_User_Access_Admin_system_false_success(self):
        """
        Test that principal with 'User Access administrator' role can read a list of roles
        with '?system=false' in the request.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_admin_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)
        client = APIClient()
        url = reverse("role-list") + "?system=false"

        response = client.get(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), self.non_system_roles_count)

        response = client.get(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), self.non_system_roles_count)

    def test_list_roles_without_User_Access_Admin_system_foo_fail(self):
        """
        Test that principal without 'User Access administrator' role cannot read a list of roles
        with '?system=foo' in the request (where 'foo' is not supported value for the 'system' param
        so the 'system' param is ignored in this case).
        """
        client = APIClient()
        url = reverse("role-list") + "?system=foo"

        response = client.get(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        response = client.get(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("errors")[0].get("detail"), self.no_permission_err_message)

        # Org Admin can list the roles
        response = client.get(url, **self.headers_org_admin)
        expected_count = self.system_roles_count + self.non_system_roles_count
        self.assertEqual(len(response.data.get("data")), expected_count)

    def test_list_roles_with_User_Access_Admin_system_foo_success(self):
        """
        Test that principal with 'User Access administrator' role can read a list of roles
        with '?system=foo' in the request (where 'foo' is not supported value for the 'system' param
        so the 'system' param is ignored in this case).
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_admin_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        client = APIClient()
        url = reverse("role-list")

        response = client.get(url, **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_count = self.system_roles_count + self.non_system_roles_count + 1
        self.assertEqual(len(response.data.get("data")), expected_count)

        response = client.get(url, **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_count = self.system_roles_count + self.non_system_roles_count + 1
        self.assertEqual(len(response.data.get("data")), expected_count)

    @override_settings(
        ROLE_CREATE_ALLOW_LIST="cost-management,remediations,inventory,drift,policies,advisor,catalog,approval,"
        "vulnerability,compliance,automation-analytics,notifications,patch,integrations,ros,"
        "staleness,config-manager"
    )
    def test_create_role_with_rbac_permission_fail(self):
        """
        Test that it is not possible to create a custom role with RBAC permission.
        """
        # Create a group with 'User Access administrator' role and add principals we use in headers
        group_with_UA_admin = self._create_group_with_user_access_admin_role(self.tenant)
        group_with_UA_admin.principals.add(self.user_based_principal, self.service_account_principal)

        Permission.objects.create(permission="rbac:principal:read", tenant=self.tenant)
        permissions_count = len(Permission.objects.all())

        client = APIClient()

        # Test that permissions are present in the RBAC db
        url = reverse("permission-list")
        response = client.get(url, **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), permissions_count)

        # It is not possible to create custom role with RBAC permission
        url = reverse("role-list")
        role_name = "My custom role"
        access_data = [{"permission": "rbac:*:*", "resourceDefinitions": []}]
        test_data = {"name": role_name, "access": access_data}

        response = client.post(url, test_data, format="json", **self.headers_user_based_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), "Custom roles cannot be created for rbac")

        response = client.post(url, test_data, format="json", **self.headers_service_account_principal)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), "Custom roles cannot be created for rbac")

        response = client.post(url, test_data, format="json", **self.headers_org_admin)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("errors")[0].get("detail"), "Custom roles cannot be created for rbac")
