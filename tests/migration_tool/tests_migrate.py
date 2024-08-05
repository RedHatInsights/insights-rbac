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
import uuid

from django.test import TestCase

from api.models import Tenant
from management.models import *
from migration_tool.migrate import migrate_data


class MigrateTests(TestCase):
    """Test the utils module."""

    def setUp(self):
        """Set up the utils tests."""
        super().setUp()
        public_tenant = Tenant.objects.create(tenant_name="public")
        permission1 = Permission.objects.create(permission="app1:*:*", tenant=public_tenant)
        permission2 = Permission.objects.create(permission="app2:resource2:*", tenant=public_tenant)
        self.tenant = Tenant.objects.create(org_id="1234567", tenant_name="tenant")
        another_tenant = Tenant.objects.create(org_id="7654321")

        # setup data
        self.roleA1 = Role.objects.create(name="roleA1", tenant=self.tenant)
        self.accessA11 = Access.objects.create(permission=permission1, role=self.roleA1, tenant=self.tenant)
        self.accessA12 = Access.objects.create(permission=permission2, role=self.roleA1, tenant=self.tenant)

        self.roleA2 = Role.objects.create(name="roleA2", tenant=self.tenant)
        self.accessA2 = Access.objects.create(permission=permission2, role=self.roleA2, tenant=self.tenant)
        self.resourceDef = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "aws.account",
                "operation": "equal",
                "value": "admin",
            },
            access=self.accessA2,
            tenant=self.tenant,
        )
        self.groupA21 = Group.objects.create(name="groupA21", tenant=self.tenant)
        self.principal1 = Principal.objects.create(username="principal1", tenant=self.tenant)
        self.principal2 = Principal.objects.create(username="principal2", tenant=self.tenant)
        self.groupA21.principals.add(self.principal1, self.principal2)
        self.policyA21 = Policy.objects.create(name="System PolicyA21", group=self.groupA21, tenant=self.tenant)
        self.policyA21.roles.add(self.roleA2)
        self.policyA21.save()
        self.groupA22 = Group.objects.create(name="groupA22", tenant=self.tenant)
        self.policyA22 = Policy.objects.create(name="System PolicyA22", group=self.groupA22, tenant=self.tenant)
        self.policyA22.roles.add(self.roleA2)
        self.policyA22.save()

        # setup data for another tenant
        self.roleB = Role.objects.create(name="roleB", tenant=another_tenant)
        self.accessB = Access.objects.create(permission=permission2, role=self.roleB, tenant=another_tenant)
        self.system_role = Role.objects.create(name="system_role", system=True, tenant=public_tenant)
        Access.objects.bulk_create(
            [
                Access(permission=permission1, role=self.system_role, tenant=public_tenant),
                Access(permission=permission2, role=self.system_role, tenant=public_tenant),
            ]
        )

    @patch("migration_tool.migrate.logger")
    def test_migration_of_roles(self, logger_mock):
        """Test that we get the correct access for a principal."""
        kwargs = {"exclude_apps": ["app1"], "orgs": ["1234567"]}
        migrate_data(**kwargs)
        self.assertEqual(
            len(logger_mock.info.call_args_list),
            26,
        )
