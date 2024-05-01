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
from management.models import Access, Permission, ResourceDefinition, Role
from migration_tool.migrate import migrate_roles


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
                "key": "scope",
                "operation": "equal",
                "value": "admin",
            },
            access=self.accessA2,
            tenant=self.tenant,
        )

        # setup data for another tenant
        self.roleB = Role.objects.create(name="roleB", tenant=another_tenant)
        self.accessB = Access.objects.create(permission=permission2, role=self.roleB, tenant=another_tenant)

    @patch("migration_tool.migrate.logger")
    def test_migration_of_roles(self, logger_mock):
        """Test that we get the correct access for a principal."""
        kwargs = {"exclude_apps": ["app1"], "orgs": ["1234567"]}
        migrate_roles(**kwargs)
        self.assertEqual(
            logger_mock.info.call_args_list,
            [
                call("Migrating roles for tenant: tenant"),
                call("scope:admin#workspace@workspace:org_migration_root"),
                call("role_binding:2_rolea2_admin_b_team#granted@role:2_rolea2"),
                call("scope:admin#user_grant@role_binding:2_rolea2_admin_b_team"),
                call("role:2_rolea2#app2_resource2_all@user:*"),
                call("role_binding:2_rolea2_admin_a_team#granted@role:2_rolea2"),
                call("scope:admin#user_grant@role_binding:2_rolea2_admin_a_team"),
                call("Finished migrating roles for tenant: tenant. 1 of 1 tenants completed"),
                call("Finished migrating roles for all tenants"),
            ],
        )
