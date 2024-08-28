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
from management.workspace.model import Workspace


class MigrateTests(TestCase):
    """Test the utils module."""

    def setUp(self):
        """Set up the utils tests."""
        super().setUp()
        public_tenant = Tenant.objects.create(tenant_name="public")
        # This would be skipped
        permission1 = Permission.objects.create(permission="app1:hosts:read", tenant=public_tenant)
        permission2 = Permission.objects.create(permission="inventory:hosts:write", tenant=public_tenant)
        # Two organization
        self.tenant = Tenant.objects.create(org_id="1234567", tenant_name="tenant")
        another_tenant = Tenant.objects.create(org_id="7654321")

        # setup data for organization 1234567
        self.aws_account_id_1 = "123456"
        self.aws_account_id_2 = "654321"
        # This role will be skipped because it contains permission with skipping application
        self.role_a1 = Role.objects.create(name="role_a1", tenant=self.tenant)
        self.access_a11 = Access.objects.create(permission=permission1, role=self.role_a1, tenant=self.tenant)
        self.access_a12 = Access.objects.create(permission=permission2, role=self.role_a1, tenant=self.tenant)

        self.role_a2 = Role.objects.create(name="role_a2", tenant=self.tenant)
        self.access_a2 = Access.objects.create(permission=permission2, role=self.role_a2, tenant=self.tenant)
        self.resourceDef_a2 = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "cost-management.aws.account",
                "operation": "equal",
                "value": self.aws_account_id_1,
            },
            access=self.access_a2,
            tenant=self.tenant,
        )
        self.role_a3 = Role.objects.create(name="role_a3", tenant=self.tenant)
        self.access_a3 = Access.objects.create(permission=permission2, role=self.role_a3, tenant=self.tenant)
        self.resourceDef_a3 = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "aws.account",
                "operation": "in",
                "value": [self.aws_account_id_1, self.aws_account_id_2],
            },
            access=self.access_a3,
            tenant=self.tenant,
        )
        self.group_a2 = Group.objects.create(name="group_a2", tenant=self.tenant)
        self.principal1 = Principal.objects.create(username="principal1", tenant=self.tenant)
        self.principal2 = Principal.objects.create(username="principal2", tenant=self.tenant)
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

    @patch("migration_tool.utils.logger")
    def test_migration_of_data(self, logger_mock):
        """Test that we get the correct access for a principal."""
        kwargs = {"exclude_apps": ["app1"], "orgs": ["1234567"]}
        migrate_data(**kwargs)

        org_id = self.tenant.org_id
        root_workspace = Workspace.objects.get(name="root", tenant=self.tenant)

        role_binding = BindingMapping.objects.filter(role=self.role_a2).first()

        mappings_a2 = role_binding.mappings
        first_key = list(mappings_a2.keys())[0]

        v2_role_a2 = mappings_a2[first_key]["v2_role_uuid"] #self.role_a2.v2role_set.first()
        rolebinding_a2 = first_key

        role_binding_a3 = BindingMapping.objects.filter(role=self.role_a3).first()
        mappings_a3 = role_binding_a3.mappings
        first_key = list(mappings_a3.keys())[0]
        v2_role_a31_value = mappings_a3[first_key]["v2_role_uuid"]
        v2_role_a31 = v2_role_a31_value

        last_key = list(mappings_a3.keys())[-1]
        v2_role_a32 = mappings_a3[last_key]["v2_role_uuid"]

        rolebinding_a31 = first_key
        rolebinding_a32 = last_key

        workspace_1 = "123456"
        workspace_2 = "654321"
        # Switch these two if rolebinding order is not the same as v2 roles
        if (
            call(f"role_binding:{rolebinding_a31}#granted@role:{v2_role_a31}")
            not in logger_mock.info.call_args_list
        ):
            rolebinding_a31, rolebinding_a32 = rolebinding_a32, rolebinding_a31
        # Switch these two if binding is not in correct order
        if (
            call(f"workspace:{self.aws_account_id_1}#user_grant@role_binding:{rolebinding_a31}")
            not in logger_mock.info.call_args_list
        ):
            workspace_1, workspace_2 = workspace_2, workspace_1

        tuples = [
            # Org relationships of self.tenant
            # the other org is not included since it is not specified in the orgs parameter
            ## Workspaces root and default
            call(f"workspace:{org_id}#parent@workspace:{root_workspace.uuid}"),
            call(f"workspace:{root_workspace.uuid}#parent@tenant:{org_id}"),
            ## Realm
            call(f"tenant:{org_id}#realm@realm:stage"),
            ## Users to tenant
            call(f"tenant:{org_id}#member@user:{self.principal1.uuid}"),
            call(f"tenant:{org_id}#member@user:{self.principal2.uuid}"),
            ## Group member
            call(f"group:{self.group_a2.uuid}#member@user:{self.principal1.uuid}"),
            call(f"group:{self.group_a2.uuid}#member@user:{self.principal2.uuid}"),
            ## Role binding to role_a2
            call(f"role_binding:{rolebinding_a2}#granted@role:{v2_role_a2}"),
            call(f"role:{v2_role_a2}#inventory_hosts_write@user:*"),
            call(f"role_binding:{rolebinding_a2}#subject@group:{self.group_a2.uuid}"),
            call(f"workspace:{self.aws_account_id_1}#parent@workspace:{root_workspace.uuid}"),
            call(f"workspace:{self.aws_account_id_1}#user_grant@role_binding:{rolebinding_a2}"),
            ## Role binding to role_a3
            call(f"role_binding:{rolebinding_a31}#granted@role:{v2_role_a31}"),
            call(f"role:{v2_role_a31}#inventory_hosts_write@user:*"),
            call(f"workspace:{workspace_1}#parent@workspace:{root_workspace.uuid}"),
            call(f"workspace:{workspace_1}#user_grant@role_binding:{rolebinding_a31}"),
            call(f"role_binding:{rolebinding_a32}#granted@role:{v2_role_a32}"),
            call(f"role:{v2_role_a32}#inventory_hosts_write@user:*"),
            call(f"workspace:{workspace_2}#parent@workspace:{root_workspace.uuid}"),
            call(f"workspace:{workspace_2}#user_grant@role_binding:{rolebinding_a32}"),
        ]
        logger_mock.info.assert_has_calls(tuples, any_order=True)
