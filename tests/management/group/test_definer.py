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
"""Test the group definer."""
from management.group.definer import seed_group, add_roles, remove_roles
from management.group.view import GroupViewSet
from management.role.definer import seed_roles
from tests.identity_request import IdentityRequest
from tenant_schemas.utils import tenant_context
from management.models import Group, Role

class GroupDefinerTests(IdentityRequest):
    """Test the group definer functions."""

    def setUp(self):
        """Set up the group definer tests."""
        super().setUp()
        seed_roles(self.tenant, update=True)
        seed_group(self.tenant)

    def test_default_group_seeding_properly(self):
        """Test that default group are seeded properly."""
        with tenant_context(self.tenant):
            group = Group.objects.get(platform_default=True)
            self.assertEqual(group.platform_default, True)
            self.assertEqual(group.system, True)
            self.assertEqual(group.policies.get(name='System Policy for Group {}'.format(group.uuid)).system, True)

    def test_default_group_seeding_skips(self):
        """Test that default groups with system flag false will be skipped during seeding"""

        self.modify_default_group(system=False)

        try:
            seed_group(self.tenant)
        except Exception:
            self.fail(msg='update seed_group encountered an exception')

        with tenant_context(self.tenant):
            group = Group.objects.get(platform_default=True)
            self.assertEqual(group.system, False)
            group.roles().get(name="RBAC Administrator")

    def test_default_group_seeding_reassign_roles(self):
        """Test that previous assigned roles would be eliminated before assigning new roles."""
        self.modify_default_group()

        try:
            seed_group(self.tenant)
        except Exception:
            self.fail(msg='update seed_group encountered an exception')

        with tenant_context(self.tenant):
            group = Group.objects.get(platform_default=True)
            self.assertEqual(group.system, True)
            self.assertRaises(Role.DoesNotExist, group.roles().get, name="RBAC Administrator")

    def modify_default_group(self, system=True):
        """ Add a role to the default group and/or change the system flag"""
        with tenant_context(self.tenant):
            group = Group.objects.get(platform_default=True)
            roles = Role.objects.filter(name="RBAC Administrator").values_list('uuid', flat=True)
            add_roles(group, roles)

            group.system = system
            group.save()