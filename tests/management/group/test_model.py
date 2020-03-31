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
"""Test the group model."""
from django.test import TestCase
from tenant_schemas.utils import tenant_context
from unittest.mock import Mock

from management.models import Group, Role, Policy
from tests.identity_request import IdentityRequest


class GroupModelTests(IdentityRequest):
    """Test the group model."""

    def setUp(self):
        """Set up the group model tests."""
        super().setUp()

        with tenant_context(self.tenant):
            self.group = Group.objects.create(name='groupA', platform_default=True, system=True)
            self.groupB = Group.objects.create(name='groupB', system=True)
            self.roleA = Role.objects.create(name='roleA')
            self.roleB = Role.objects.create(name='roleB')
            self.policy = Policy(name='policyA', group=self.group)
            self.policy.save()
            self.policy.roles.add(self.roleA)
            self.policy.save()
            self.group.policies.add(self.policy)
            self.group.save()

    def tearDown(self):
        """Tear down group model tests."""
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Policy.objects.all().delete()
            Role.objects.all().delete()

    def test_roles_for_group(self):
        """Test that we can get roles for a group."""
        with tenant_context(self.tenant):
            self.assertEqual(list(self.group.roles()), [self.roleA])


    def test_role_count_for_group(self):
        """Test the role count for a group."""
        with tenant_context(self.tenant):
            self.assertEqual(self.group.role_count(), 1)

    def test_platform_default_set(self):
        """Test the platform default queryset only returns system groups."""
        with tenant_context(self.tenant):
            platform_default_groups = Group.platform_default_set()
            self.assertEqual(list(platform_default_groups), [self.group, self.groupB])
