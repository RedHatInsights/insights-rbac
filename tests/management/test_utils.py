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
from tenant_schemas.utils import tenant_context

from api.models import Tenant
from management.models import Group, Permission, Principal, Policy, Role, Access
from management.utils import access_for_principal, groups_for_principal, policies_for_principal, roles_for_principal
from tests.identity_request import IdentityRequest
from unittest.mock import Mock


class UtilsTests(IdentityRequest):
    """Test the utils module."""

    def setUp(self):
        """Set up the utils tests."""
        super().setUp()
        self.public_tenant = Tenant.objects.get(schema_name="public")

        with tenant_context(self.tenant):
            # setup principal
            self.principal = Principal.objects.create(username="principalA", tenant=self.tenant)

            # setup data for the principal
            self.roleA = Role.objects.create(name="roleA", tenant=self.tenant)
            self.permission = Permission.objects.create(permission="app:*:*", tenant=self.tenant)
            self.accessA = Access.objects.create(permission=self.permission, role=self.roleA, tenant=self.tenant)
            self.policyA = Policy.objects.create(name="policyA", tenant=self.tenant)
            self.policyA.roles.add(self.roleA)
            self.groupA = Group.objects.create(name="groupA", tenant=self.tenant)
            self.groupA.policies.add(self.policyA)
            self.groupA.principals.add(self.principal)

            # setup data the principal does not have access to
            self.roleB = Role.objects.create(name="roleB", tenant=self.tenant)
            self.accessB = Access.objects.create(permission=self.permission, role=self.roleB, tenant=self.tenant)
            self.policyB = Policy.objects.create(name="policyB", tenant=self.tenant)
            self.policyB.roles.add(self.roleB)
            self.groupB = Group.objects.create(name="groupB", tenant=self.tenant)
            self.groupB.policies.add(self.policyB)

            # setup default group/role which all tenant users
            # should inherit without explicit association
            self.default_role = Role.objects.create(
                name="default role", platform_default=True, system=True, tenant=self.tenant
            )
            self.default_access = Access.objects.create(
                permission=self.permission, role=self.default_role, tenant=self.tenant
            )
            self.default_policy = Policy.objects.create(name="default policy", system=True, tenant=self.tenant)
            self.default_policy.roles.add(self.default_role)
            self.default_group = Group.objects.create(
                name="default group", system=True, platform_default=True, tenant=self.tenant
            )
            self.default_group.policies.add(self.default_policy)

    def tearDown(self):
        """Tear down the utils tests."""
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Principal.objects.all().delete()
            Policy.objects.all().delete()
            Role.objects.all().delete()
            Access.objects.all().delete()

    def test_access_for_principal(self):
        """Test that we get the correct access for a principal."""
        with tenant_context(self.tenant):
            request = {}
            kwargs = {"application": "app"}
            access = access_for_principal(self.principal, request, **kwargs)
            self.assertCountEqual(access, [self.accessA, self.default_access])

    def test_groups_for_principal(self):
        """Test that we get the correct groups for a principal."""
        with tenant_context(self.tenant):
            request = {}
            groups = groups_for_principal(self.principal, request)
            self.assertCountEqual(groups, [self.groupA, self.default_group])

    def test_groups_for_principal_from_public_with_custom_group(self):
        """Test that we get the correct groups (including custom defaul) for a principal serving from public."""
        with self.settings(SERVE_FROM_PUBLIC_SCHEMA=True):
            with tenant_context(self.public_tenant):
                default_group = Group.objects.create(
                    name="default group", system=True, platform_default=True, tenant=self.public_tenant
                )
                custom_default_group = Group.objects.create(
                    name="custom default group", system=True, platform_default=True, tenant=self.tenant
                )
                request = Mock(tenant=self.tenant)
                groups = groups_for_principal(self.principal, request)
                self.assertCountEqual(groups, [custom_default_group])

    def test_groups_for_principal_from_public_without_custom_group(self):
        """Test that we get the correct groups for a principal serving from public."""
        with self.settings(SERVE_FROM_PUBLIC_SCHEMA=True):
            with tenant_context(self.public_tenant):
                default_group = Group.objects.create(
                    name="default group", system=True, platform_default=True, tenant=self.public_tenant
                )
                request = Mock(tenant=self.tenant)
                groups = groups_for_principal(self.principal, request)
                self.assertCountEqual(groups, [default_group])

    def test_policies_for_principal(self):
        """Test that we get the correct groups for a principal."""
        with tenant_context(self.tenant):
            request = {}
            policies = policies_for_principal(self.principal, request)
            self.assertCountEqual(policies, [self.policyA, self.default_policy])

    def test_roles_for_principal(self):
        """Test that we get the correct groups for a principal."""
        with tenant_context(self.tenant):
            request = {}
            roles = roles_for_principal(self.principal, request)
            self.assertCountEqual(roles, [self.roleA, self.default_role])
