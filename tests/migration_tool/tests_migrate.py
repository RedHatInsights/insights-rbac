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
from unittest.mock import Mock, call, patch

from django.test import TestCase

from api.models import Tenant
from management.models import *
from migration_tool.migrate import migrate_data


class MigrateTests(TestCase):
    """Test the utils module."""

    def setUp(self):
        """Set up the utils tests."""
        super().setUp()
        public_tenant = Tenant.objects.get(tenant_name="public")
        Group.objects.create(name="default", tenant=public_tenant, platform_default=True)
        # This would be skipped
        permission1 = Permission.objects.create(permission="app1:hosts:read", tenant=public_tenant)
        permission2 = Permission.objects.create(permission="inventory:hosts:write", tenant=public_tenant)
        # Two organization
        self.tenant = Tenant.objects.create(org_id="1234567", tenant_name="tenant")
        self.root_workspace = Workspace.objects.create(
            type=Workspace.Types.ROOT, tenant=self.tenant, name="Root Workspace"
        )
        self.default_workspace = Workspace.objects.create(
            type=Workspace.Types.DEFAULT, tenant=self.tenant, name="Default Workspace", parent=self.root_workspace
        )

        another_tenant = Tenant.objects.create(org_id="7654321")

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
        self.policy_a2.save()

        # setup data for another tenant 7654321
        self.role_b = Role.objects.create(name="role_b", tenant=another_tenant)
        self.access_b = Access.objects.create(permission=permission2, role=self.role_b, tenant=another_tenant)
        self.system_role = Role.objects.create(name="system_role", system=True, tenant=public_tenant)
        Access.objects.bulk_create(
            [
                Access(permission=permission1, role=self.system_role, tenant=public_tenant),
                Access(permission=permission2, role=self.system_role, tenant=public_tenant),
            ]
        )

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
        ]
        logger_mock.info.assert_has_calls(tuples, any_order=True)
