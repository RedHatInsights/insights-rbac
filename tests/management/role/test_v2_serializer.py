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
"""Test the RoleV2 serializers."""

from unittest.mock import Mock

from django.test import override_settings
from rest_framework import serializers

from management.models import Permission
from management.role.model import CustomRoleV2, RoleV2
from management.role.serializer import (
    PermissionSerializer,
    RoleV2RequestSerializer,
    RoleV2ResponseSerializer,
)
from tests.identity_request import IdentityRequest


class PermissionSerializerTests(IdentityRequest):
    """Test the PermissionSerializer."""

    def test_permission_serializer_input(self):
        """Test that PermissionSerializer correctly deserializes input."""
        data = {
            "application": "inventory",
            "resource_type": "hosts",
            "operation": "read",
        }
        serializer = PermissionSerializer(data=data)

        self.assertTrue(serializer.is_valid())
        # Note: 'operation' maps to 'verb' via source
        self.assertEqual(serializer.validated_data["application"], "inventory")
        self.assertEqual(serializer.validated_data["resource_type"], "hosts")
        self.assertEqual(serializer.validated_data["verb"], "read")

    def test_permission_serializer_missing_application(self):
        """Test that missing application field fails validation."""
        data = {"resource_type": "hosts", "operation": "read"}
        serializer = PermissionSerializer(data=data)

        self.assertFalse(serializer.is_valid())
        self.assertIn("application", serializer.errors)

    def test_permission_serializer_missing_resource_type(self):
        """Test that missing resource_type field fails validation."""
        data = {"application": "inventory", "operation": "read"}
        serializer = PermissionSerializer(data=data)

        self.assertFalse(serializer.is_valid())
        self.assertIn("resource_type", serializer.errors)

    def test_permission_serializer_missing_operation(self):
        """Test that missing operation field fails validation."""
        data = {"application": "inventory", "resource_type": "hosts"}
        serializer = PermissionSerializer(data=data)

        self.assertFalse(serializer.is_valid())
        self.assertIn("operation", serializer.errors)


class RoleV2ResponseSerializerTests(IdentityRequest):
    """Test the RoleV2ResponseSerializer (output serializer)."""

    def setUp(self):
        """Set up the serializer tests."""
        super().setUp()
        self.permission = Permission.objects.create(permission="inventory:hosts:read", tenant=self.tenant)
        self.role = CustomRoleV2.objects.create(
            name="Test Role",
            description="A test role",
            tenant=self.tenant,
        )
        self.role.permissions.add(self.permission)

    def tearDown(self):
        """Tear down serializer tests."""
        from management.utils import PRINCIPAL_CACHE

        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

        # Clear principal cache to avoid test isolation issues
        PRINCIPAL_CACHE.delete_all_principals_for_tenant(self.tenant.org_id)

        super().tearDown()

    def test_response_serializer_output_fields(self):
        """Test that response serializer includes all expected fields."""
        serializer = RoleV2ResponseSerializer(self.role)
        data = serializer.data

        self.assertIn("id", data)
        self.assertIn("name", data)
        self.assertIn("description", data)
        self.assertIn("permissions", data)
        self.assertIn("last_modified", data)
        # permissions_count not included until field masking is implemented

    def test_response_serializer_uuid_mapping(self):
        """Test that 'id' field maps to model's 'uuid'."""
        serializer = RoleV2ResponseSerializer(self.role)
        data = serializer.data

        self.assertEqual(str(self.role.uuid), data["id"])

    def test_response_serializer_last_modified_mapping(self):
        """Test that 'last_modified' field maps to model's 'modified'."""
        serializer = RoleV2ResponseSerializer(self.role)
        data = serializer.data

        self.assertIsNotNone(data["last_modified"])


@override_settings(ATOMIC_RETRY_DISABLED=True)
class RoleV2RequestSerializerTests(IdentityRequest):
    """Test the RoleV2RequestSerializer (request serializer for create/update)."""

    def setUp(self):
        """Set up the serializer tests."""
        super().setUp()
        self.permission = Permission.objects.create(permission="inventory:hosts:read", tenant=self.tenant)

        # Mock request with tenant
        self.mock_request = Mock()
        self.mock_request.tenant = self.tenant

    def tearDown(self):
        """Tear down serializer tests."""
        from management.utils import PRINCIPAL_CACHE

        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

        # Clear principal cache to avoid test isolation issues
        PRINCIPAL_CACHE.delete_all_principals_for_tenant(self.tenant.org_id)

        super().tearDown()

    def test_serializer_validates_required_name(self):
        """Test that name is required."""
        data = {
            "description": "A role",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }
        serializer = RoleV2RequestSerializer(data=data, context={"request": self.mock_request})

        self.assertFalse(serializer.is_valid())
        self.assertIn("name", serializer.errors)

    def test_serializer_validates_required_description(self):
        """Test that description is required per API spec."""
        data = {
            "name": "Test Role",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }
        serializer = RoleV2RequestSerializer(data=data, context={"request": self.mock_request})

        self.assertFalse(serializer.is_valid())
        self.assertIn("description", serializer.errors)

    def test_serializer_validates_required_permissions(self):
        """Test that permissions are required."""
        data = {
            "name": "Test Role",
            "description": "A role",
        }
        serializer = RoleV2RequestSerializer(data=data, context={"request": self.mock_request})

        self.assertFalse(serializer.is_valid())
        self.assertIn("permissions", serializer.errors)

    def test_serializer_rejects_blank_description(self):
        """Test that blank description is rejected."""
        data = {
            "name": "Test Role",
            "description": "",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }
        serializer = RoleV2RequestSerializer(data=data, context={"request": self.mock_request})

        self.assertFalse(serializer.is_valid())
        self.assertIn("description", serializer.errors)

    def test_serializer_create_success(self):
        """Test that serializer.create() creates a role successfully."""
        data = {
            "name": "New Role",
            "description": "A new role",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }
        serializer = RoleV2RequestSerializer(data=data, context={"request": self.mock_request})

        self.assertTrue(serializer.is_valid())
        role = serializer.save()

        self.assertIsInstance(role, CustomRoleV2)
        self.assertEqual(role.name, "New Role")
        self.assertEqual(role.description, "A new role")
        self.assertEqual(role.permissions.count(), 1)

    def test_serializer_create_duplicate_name_raises_validation_error(self):
        """Test that creating a role with duplicate name raises ValidationError."""
        # Create first role
        CustomRoleV2.objects.create(
            name="Duplicate Role",
            description="First role",
            tenant=self.tenant,
        )

        # Try to create via serializer
        data = {
            "name": "Duplicate Role",
            "description": "Second role",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }
        serializer = RoleV2RequestSerializer(data=data, context={"request": self.mock_request})

        self.assertTrue(serializer.is_valid())
        with self.assertRaises(serializers.ValidationError) as cm:
            serializer.save()

        self.assertIn("name", cm.exception.detail)

    def test_serializer_create_invalid_permission_raises_validation_error(self):
        """Test that non-existent permission raises ValidationError."""
        data = {
            "name": "Role with Bad Permission",
            "description": "Has invalid permission",
            "permissions": [{"application": "nonexistent", "resource_type": "resource", "operation": "action"}],
        }
        serializer = RoleV2RequestSerializer(data=data, context={"request": self.mock_request})

        self.assertTrue(serializer.is_valid())
        with self.assertRaises(serializers.ValidationError) as cm:
            serializer.save()

        self.assertIn("permissions", cm.exception.detail)

    def test_serializer_service_injectable_via_context(self):
        """Test that service can be overridden via context."""
        mock_service = Mock()
        mock_service.create.return_value = CustomRoleV2(
            name="Injected",
            description="Via context",
            tenant=self.tenant,
        )

        data = {
            "name": "Injected Role",
            "description": "Test",
            "permissions": [{"application": "inventory", "resource_type": "hosts", "operation": "read"}],
        }
        serializer = RoleV2RequestSerializer(
            data=data,
            context={"request": self.mock_request, "role_service": mock_service},
        )
        serializer.is_valid()
        serializer.save()

        # Verify the injected service was used
        mock_service.create.assert_called_once()
