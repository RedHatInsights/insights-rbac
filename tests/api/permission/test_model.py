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
"""Test the permission model."""
from django.test import TestCase
from api.models import Permission


class PermissionModelTests(TestCase):
    """Test the permission model."""

    def setUp(self):
        """Set up the permission model tests."""
        super().setUp()

        self.permission = Permission.objects.create(permission="rbac:roles:read")
        self.permission.save()

    def tearDown(self):
        """Tear down permission model tests."""
        Permission.objects.all().delete()

    def test_permission_has_attributes(self):
        """Test the permission has expected attributes."""
        self.assertEqual(self.permission.application, "rbac")
        self.assertEqual(self.permission.resource_type, "roles")
        self.assertEqual(self.permission.verb, "read")
        self.assertEqual(self.permission.permission, "rbac:roles:read")
        self.assertEqual(len(Permission._meta.fields), 5)
