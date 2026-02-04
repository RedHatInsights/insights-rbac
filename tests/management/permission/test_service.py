#
# Copyright 2026 Red Hat, Inc.
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
"""Tests for PermissionService."""

from django.test import override_settings
from management.permission.model import Permission
from management.permission.service import PermissionService
from management.role.v2_exceptions import EmptyPermissionsError, PermissionsNotFoundError
from tests.identity_request import IdentityRequest


@override_settings(ATOMIC_RETRY_DISABLED=True)
class PermissionServiceTests(IdentityRequest):
    """Tests for PermissionService."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.service = PermissionService()

        self.permission1 = Permission.objects.create(
            permission="inventory:hosts:read",
            tenant=self.tenant,
        )
        self.permission2 = Permission.objects.create(
            permission="inventory:hosts:write",
            tenant=self.tenant,
        )

    def test_resolve_single_permission(self):
        """Test resolving a single permission."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        result = self.service.resolve(permission_data)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.permission1)

    def test_resolve_multiple_permissions(self):
        """Test resolving multiple permissions."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
            {"application": "inventory", "resource_type": "hosts", "operation": "write"},
        ]

        result = self.service.resolve(permission_data)

        self.assertEqual(len(result), 2)
        self.assertIn(self.permission1, result)
        self.assertIn(self.permission2, result)

    def test_resolve_with_verb_key(self):
        """Test that 'verb' key works as alternative to 'operation'."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "verb": "read"},
        ]

        result = self.service.resolve(permission_data)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.permission1)

    def test_resolve_operation_takes_precedence_over_verb(self):
        """Test that 'operation' takes precedence when both keys are present."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read", "verb": "write"},
        ]

        result = self.service.resolve(permission_data)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.permission1)

    def test_resolve_empty_list_raises_error(self):
        """Test that empty permission list raises EmptyPermissionsError."""
        with self.assertRaises(EmptyPermissionsError):
            self.service.resolve([])

    def test_resolve_not_found_raises_error(self):
        """Test that non-existent permission raises PermissionsNotFoundError."""
        permission_data = [
            {"application": "nonexistent", "resource_type": "foo", "operation": "bar"},
        ]

        with self.assertRaises(PermissionsNotFoundError) as context:
            self.service.resolve(permission_data)

        self.assertIn("nonexistent:foo:bar", str(context.exception))

    def test_resolve_partial_not_found_raises_error(self):
        """Test that if some permissions exist and some don't, it raises error with missing ones."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
            {"application": "nonexistent", "resource_type": "foo", "operation": "bar"},
        ]

        with self.assertRaises(PermissionsNotFoundError) as context:
            self.service.resolve(permission_data)

        self.assertIn("nonexistent:foo:bar", str(context.exception))
        self.assertNotIn("inventory:hosts:read", str(context.exception))

    def test_resolve_preserves_order(self):
        """Test that resolved permissions maintain input order."""
        permission_data = [
            {"application": "inventory", "resource_type": "hosts", "operation": "write"},
            {"application": "inventory", "resource_type": "hosts", "operation": "read"},
        ]

        result = self.service.resolve(permission_data)

        self.assertEqual(result[0], self.permission2)
        self.assertEqual(result[1], self.permission1)
