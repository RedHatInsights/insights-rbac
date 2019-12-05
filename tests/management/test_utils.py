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

from management.models import Group, Principal, Policy, Role, Access
from management.utils import access_for_principal
from tests.identity_request import IdentityRequest


class UtilsTests(IdentityRequest):
    """Test the utils module."""

    def setUp(self):
        """Set up the utils tests."""
        super().setUp()

        with tenant_context(self.tenant):
            # setup principal
            self.principal = Principal.objects.create(username='principalA')

            # setup data for the principal
            self.roleA = Role.objects.create(name='roleA')
            self.accessA = Access.objects.create(permission='app:*:*', role=self.roleA)
            self.policyA = Policy.objects.create(name='policyA')
            self.policyA.roles.add(self.roleA)
            self.groupA = Group.objects.create(name='groupA')
            self.groupA.policies.add(self.policyA)
            self.groupA.principals.add(self.principal)

            # setup data the principal does not have access to
            self.roleB = Role.objects.create(name='roleB')
            self.accessB = Access.objects.create(permission='app:*:*', role=self.roleB)
            self.policyB = Policy.objects.create(name='policyB')
            self.policyB.roles.add(self.roleB)
            self.groupB = Group.objects.create(name='groupB')
            self.groupB.policies.add(self.policyB)

            # setup default group/role which all tenant users
            # should inherit without explicit association
            self.default_role = Role.objects.create(name='default role', platform_default=True, system=True)
            self.default_access = Access.objects.create(permission='app:*:*', role=self.default_role)
            self.default_policy = Policy.objects.create(name='default policy', system=True)
            self.default_policy.roles.add(self.default_role)
            self.default_group = Group.objects.create(name='default group', system=True, platform_default=True)
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
            kwargs = {'application': 'app'}
            access = access_for_principal(self.principal, **kwargs)
            self.assertCountEqual(access, [self.accessA, self.default_access])
