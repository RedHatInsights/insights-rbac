#
# Copyright 2020 Red Hat, Inc.
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
"""Test the role model."""
from api.models import Role
from django.test import TestCase


class RoleModelTests(TestCase):
    """Test the group model."""

    def setUp(self):
        """Set up the group model tests."""
        super().setUp()

        self.permission = Permission.objects.create(permission="app:*:*")
        self.roleA = Role.objects.create(name="roleA")
        self.access = Access.objects.create(permission=self.permission, role=self.roleA)
        self.roleB = Role.objects.create(name="roleB", system=True)
        self.roleA.save()
        self.roleB.save()

    def tearDown(self):
        """Tear down group model tests."""
        Role.objects.all().delete()

    def test_retrieving_permission_from_role(self):
        """Test that the permissions could be retrieved from role."""
        self.assertEqual(roleA.accesses.values_list("permission_permission"), ["app:*:*"])

    def test_display_name_for_new_roles(self):
        """Test that newly created roles inherit display_name."""
        self.assertEqual(self.roleA.name, "roleA")
        self.assertEqual(self.roleA.display_name, "roleA")

    def test_display_name_for_updated_roles(self):
        """Test that existing display_name is maintained on role name update."""
        self.roleA.name = "ARole"
        self.roleA.save()
        self.assertEqual(self.roleA.name, "ARole")
        self.assertEqual(self.roleA.display_name, "roleA")

    def test_display_name_updateable(self):
        """Test that display_name can be updated successfully."""
        self.roleA.display_name = "ARole"
        self.roleA.save()
        self.assertEqual(self.roleA.name, "roleA")
        self.assertEqual(self.roleA.display_name, "ARole")
