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
"""Test the permission model."""
# from django.test import TestCase
from tenant_schemas.utils import tenant_context

# from unittest.mock import Mock

from management.models import Permission
from tests.identity_request import IdentityRequest


class PermissionModelTests(IdentityRequest):
    """Test the permission model."""

    def setUp(self):
        """Set up the permission model tests."""
        super().setUp()

        with tenant_context(self.tenant):
            self.dependency_permission = Permission.objects.create(permission="rbac:roles:read", tenant=self.tenant)
            self.permission = Permission.objects.create(permission="rbac:roles:write", tenant=self.tenant)
            self.permission.save()
            self.permission.permissions.add(self.dependency_permission)

    def tearDown(self):
        """Tear down permission model tests."""
        with tenant_context(self.tenant):
            Permission.objects.all().delete()

    def test_permission_has_attributes(self):
        """Test the permission has expected attributes."""
        with tenant_context(self.tenant):
            self.assertEqual(self.permission.application, "rbac")
            self.assertEqual(self.permission.resource_type, "roles")
            self.assertEqual(self.permission.verb, "write")
            self.assertEqual(self.permission.permission, "rbac:roles:write")
            self.assertEqual(list(self.permission.permissions.all()), [self.dependency_permission])
            self.assertEqual(list(self.dependency_permission.requiring_permissions.all()), [self.permission])
