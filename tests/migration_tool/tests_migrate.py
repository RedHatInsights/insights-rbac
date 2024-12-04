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
"""Test the utils module."""
from datetime import timedelta

from platform import system
from unittest.mock import Mock, call, patch

from uuid import uuid4

from django.test import TestCase, override_settings
from django.utils import timezone

from api.models import CrossAccountRequest, Tenant

from management.models import *
from migration_tool.migrate import migrate_data
from management.group.definer import seed_group, clone_default_group_in_public_schema


class MigrateTests(TestCase):
    """Test the utils module."""

    def setUp(self):
        """Set up the utils tests."""
        super().setUp()
        # public tenant
        public_tenant = Tenant.objects.get(tenant_name="public")

        # system roles
        self.system_role_1 = Role.objects.create(
            name="System Role 1", platform_default=True, tenant=public_tenant, system=True
        )
        self.system_role_2 = Role.objects.create(
            name="System Role 2", platform_default=True, system=True, tenant=public_tenant
        )
        # default group
        default_group, _ = seed_group()
        # permissions
        # This would be skipped
        permission1 = Permission.objects.create(permission="app1:hosts:read", tenant=public_tenant)
        permission2 = Permission.objects.create(permission="inventory:hosts:write", tenant=public_tenant)
        Access.objects.bulk_create(
            [
                Access(permission=permission1, role=self.system_role_2, tenant=public_tenant),
                Access(permission=permission2, role=self.system_role_2, tenant=public_tenant),
            ]
        )

        # two organizations
        # tenant 1 - org_id=1234567
        self.tenant = Tenant.objects.create(org_id="1234567", tenant_name="tenant", ready=True)
        self.root_workspace = Workspace.objects.create(
            type=Workspace.Types.ROOT, tenant=self.tenant, name="Root Workspace"
        )
        self.default_workspace = Workspace.objects.create(
            type=Workspace.Types.DEFAULT, tenant=self.tenant, name="Default Workspace", parent=self.root_workspace
        )
        # setup data for organization 1234567
        self.workspace_id_1 = "123456"
        self.workspace_id_2 = "654321"

        # This role will be skipped because it contains permission with skipping application
        self.role_a1 = Role.objects.create(name="role_a1", tenant=self.tenant)
        self.access_a11 = Access.objects.create(permission=permission1, role=self.role_a1, tenant=self.tenant)
        self.access_a12 = Access.objects.create(permission=permission2, role=self.role_a1, tenant=self.tenant)

        self.role_a2 = Role.objects.create(name="role_a2", tenant=self.tenant)
        self.access_a2 = Access.objects.create(permission=permission2, role=self.role_a2, tenant=self.tenant)
        self.resourceDef_a2 = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "equal",
                "value": self.workspace_id_1,
            },
            access=self.access_a2,
            tenant=self.tenant,
        )
        self.role_a3 = Role.objects.create(name="role_a3", tenant=self.tenant)
        self.access_a3 = Access.objects.create(permission=permission2, role=self.role_a3, tenant=self.tenant)
        self.resourceDef_a3 = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [self.workspace_id_1, self.workspace_id_2],
            },
            access=self.access_a3,
            tenant=self.tenant,
        )
        self.group_a2 = Group.objects.create(name="group_a2", tenant=self.tenant)
        self.principal1 = Principal.objects.create(username="principal1", tenant=self.tenant, user_id="user_id_1")
        self.principal2 = Principal.objects.create(username="principal2", tenant=self.tenant, user_id="user_id_2")
        self.group_a2.principals.add(self.principal1, self.principal2)
        self.policy_a2 = Policy.objects.create(name="System Policy_a2", group=self.group_a2, tenant=self.tenant)
        self.policy_a2.roles.add(self.role_a2)

        # tenant 2 - org_id=7654321
        another_tenant = Tenant.objects.create(org_id="7654321", ready=True)

        root_workspace_another_tenant = Workspace.objects.create(
            type=Workspace.Types.ROOT, tenant=another_tenant, name="Root Workspace"
        )
        self.default_workspace_for_another_tenant = Workspace.objects.create(
            type=Workspace.Types.DEFAULT,
            tenant=another_tenant,
            name="Default Workspace",
            parent=root_workspace_another_tenant,
        )
        self.another_tenant = another_tenant

        Group.objects.create(name="another_group", tenant=another_tenant)

        # setup data for another tenant 7654321
        self.role_b = Role.objects.create(name="role_b", tenant=another_tenant)
        self.access_b = Access.objects.create(permission=permission2, role=self.role_b, tenant=another_tenant)

        self.policy_a2.roles.add(self.system_role_1)
        self.policy_a2.save()

        # create custom default group
        self.custom_default_group = clone_default_group_in_public_schema(default_group, self.tenant)

        # Setup cross account request to migrate
        self.ref_time = timezone.now()
        self.cross_account_request = CrossAccountRequest.objects.create(
            target_account="098765",
            target_org="7654321",
            user_id="1111111",
            end_date=self.ref_time + timedelta(10),
            status="approved",
        )
        self.cross_account_request.roles.add(self.system_role_2)

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True, PRINCIPAL_USER_DOMAIN="redhat", READ_ONLY_API_MODE=True)
    @patch("management.relation_replicator.logging_replicator.logger")
    def test_migration_of_data(self, logger_mock):
        """Test that we get the correct access for a principal."""
        kwargs = {"exclude_apps": ["app1"], "orgs": ["1234567"]}
        migrate_data(**kwargs)

        org_id = self.tenant.org_id
        root_workspace_id = str(self.root_workspace.id)
        default_workspace_id = str(self.default_workspace.id)

        role_binding = BindingMapping.objects.filter(role=self.role_a2).get().get_role_binding()

        rolebinding_a2 = role_binding.id
        v2_role_a2 = role_binding.role.id

        role_binding_a3_1 = (
            BindingMapping.objects.filter(role=self.role_a3, resource_id=self.workspace_id_1).get().get_role_binding()
        )
        role_binding_a3_2 = (
            BindingMapping.objects.filter(role=self.role_a3, resource_id=self.workspace_id_2).get().get_role_binding()
        )
        v2_role_a31 = role_binding_a3_1.role.id
        v2_role_a32 = role_binding_a3_2.role.id

        rolebinding_a31 = role_binding_a3_1.id
        rolebinding_a32 = role_binding_a3_2.id

        workspace_1 = "123456"
        workspace_2 = "654321"
        # Switch these two if rolebinding order is not the same as v2 roles
        if call(f"role_binding:{rolebinding_a31}#role@role:{v2_role_a31}") not in logger_mock.info.call_args_list:
            rolebinding_a31, rolebinding_a32 = rolebinding_a32, rolebinding_a31
        # Switch these two if binding is not in correct order
        if (
            call(f"workspace:{self.workspace_id_1}#binding@role_binding:{rolebinding_a31}")
            not in logger_mock.info.call_args_list
        ):
            workspace_1, workspace_2 = workspace_2, workspace_1

        binding_mapping_system_role_1 = BindingMapping.objects.filter(
            role=self.system_role_1,
            resource_type_name="workspace",
            resource_type_namespace="rbac",
            resource_id=self.default_workspace.id,
        ).get()

        self.assertEqual(
            binding_mapping_system_role_1.mappings["groups"],
            [str(self.custom_default_group.uuid), str(self.group_a2.uuid)],
        )

        role_binding_system_role_1_uuid = binding_mapping_system_role_1.mappings["id"]

        binding_mapping_system_role_2 = BindingMapping.objects.filter(
            role=self.system_role_2,
            resource_type_name="workspace",
            resource_type_namespace="rbac",
            resource_id=self.default_workspace.id,
        ).get()

        self.assertEqual(binding_mapping_system_role_2.mappings["groups"][0], str(self.custom_default_group.uuid))

        role_binding_system_role_2_uuid = binding_mapping_system_role_2.mappings["id"]
        tuples = [
            # Org relationships of self.tenant
            # the other org is not included since it is not specified in the orgs parameter
            ## Group member
            call(f"group:{self.group_a2.uuid}#member@principal:{self.principal1.principal_resource_id()}"),
            call(f"group:{self.group_a2.uuid}#member@principal:{self.principal2.principal_resource_id()}"),
            ## Role binding to role_a2
            call(f"role_binding:{rolebinding_a2}#role@role:{v2_role_a2}"),
            call(f"role:{v2_role_a2}#inventory_hosts_write@principal:*"),
            call(f"role_binding:{rolebinding_a2}#subject@group:{self.group_a2.uuid}"),
            call(f"workspace:{self.workspace_id_1}#parent@workspace:{default_workspace_id}"),
            call(f"workspace:{self.workspace_id_1}#binding@role_binding:{rolebinding_a2}"),
            ## Role binding to role_a3
            call(f"role_binding:{rolebinding_a31}#role@role:{v2_role_a31}"),
            call(f"role:{v2_role_a31}#inventory_hosts_write@principal:*"),
            call(f"workspace:{workspace_1}#parent@workspace:{default_workspace_id}"),
            call(f"workspace:{workspace_1}#binding@role_binding:{rolebinding_a31}"),
            call(f"role_binding:{rolebinding_a32}#role@role:{v2_role_a32}"),
            call(f"role:{v2_role_a32}#inventory_hosts_write@principal:*"),
            call(f"workspace:{workspace_2}#parent@workspace:{default_workspace_id}"),
            call(f"workspace:{workspace_2}#binding@role_binding:{rolebinding_a32}"),
            ## System role 1 assigment to custom group
            call(f"workspace:{self.default_workspace.id}#binding@role_binding:{role_binding_system_role_1_uuid}"),
            call(f"role_binding:{role_binding_system_role_1_uuid}#subject@group:{self.group_a2.uuid}"),
            call(f"role_binding:{role_binding_system_role_1_uuid}#role@role:{self.system_role_1.uuid}"),
            ## System role 2 assigment to custom default group
            call(f"workspace:{self.default_workspace.id}#binding@role_binding:{role_binding_system_role_2_uuid}"),
            call(f"role_binding:{role_binding_system_role_2_uuid}#subject@group:{self.custom_default_group.uuid}"),
            call(f"role_binding:{role_binding_system_role_2_uuid}#role@role:{self.system_role_2.uuid}"),
        ]
        logger_mock.info.assert_has_calls(tuples, any_order=True)

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True, PRINCIPAL_USER_DOMAIN="redhat", READ_ONLY_API_MODE=True)
    @patch("management.relation_replicator.logging_replicator.logger")
    def test_migration_of_cross_account_requests(self, logger_mock):
        """Test that we get the correct access for a principal."""
        kwargs = {"exclude_apps": ["app1"], "orgs": ["7654321"]}
        migrate_data(**kwargs)

        binding_mapping_system_role_2 = BindingMapping.objects.filter(
            role=self.system_role_2,
            resource_type_name="workspace",
            resource_type_namespace="rbac",
            resource_id=self.default_workspace_for_another_tenant.id,
        ).get()

        role_binding_system_role_2_uuid = binding_mapping_system_role_2.mappings["id"]

        tuples = [
            ## Cross account request for system role 2
            call(
                f"role_binding:{role_binding_system_role_2_uuid}#subject@principal:redhat/{self.cross_account_request.user_id}"
            ),
            call(f"role_binding:{role_binding_system_role_2_uuid}#role@role:{self.system_role_2.uuid}"),
            call(
                f"workspace:{self.default_workspace_for_another_tenant.id}#binding@role_binding:{role_binding_system_role_2_uuid}"
            ),
        ]
        logger_mock.info.assert_has_calls(tuples, any_order=True)

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True, PRINCIPAL_USER_DOMAIN="redhat", READ_ONLY_API_MODE=True)
    def test_skips_orgs_without_org_ids(self):
        # Create a tenant without an org id
        Tenant.objects.create(tenant_name="tenant", ready=True)

        # Migrate without limiting org
        kwargs = {"exclude_apps": ["app1"]}

        try:
            migrate_data(**kwargs)
        except Exception:
            self.fail("migrate_data raised an exception when migrating tenant without org_id")
