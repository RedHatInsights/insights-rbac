#
# Copyright 2025 Red Hat, Inc.
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
"""Test the RoleV2 models."""

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from rest_framework import serializers

from management.models import Permission, RoleV2, CustomRoleV2, SeededRoleV2, PlatformRoleV2
from tests.identity_request import IdentityRequest


class RoleV2ModelTests(IdentityRequest):
    """Test the RoleV2 models."""

    def setUp(self):
        """Set up the RoleV2 model tests."""
        super().setUp()

        self.permission1 = Permission.objects.create(permission="app:resource:read", tenant=self.tenant)
        self.permission2 = Permission.objects.create(permission="app:resource:write", tenant=self.tenant)

    def tearDown(self):
        """Tear down RoleV2 model tests."""
        RoleV2.objects.all().delete()
        Permission.objects.filter(tenant=self.tenant).delete()

    def test_rolev2_creation(self):
        """Test basic RoleV2 creation."""
        role = RoleV2.objects.create(
            name="test_role",
            description="Test role description",
            tenant=self.tenant,
        )
        self.assertEqual(role.name, "test_role")
        self.assertEqual(role.description, "Test role description")
        self.assertEqual(role.type, RoleV2.Types.CUSTOM)  # Default type is CUSTOM
        self.assertEqual(role.tenant, self.tenant)
        self.assertTrue(role.uuid)  # UUID exists and is auto-generated

    def test_rolev2_unique_name_per_tenant(self):
        """Test unique name per tenant."""
        RoleV2.objects.create(name="unique_test_role_1", tenant=self.tenant)
        with self.assertRaises(ValidationError):
            RoleV2.objects.create(name="unique_test_role_1", tenant=self.tenant)

    def test_role2_creation_with_wrong_type(self):
        """Test RoleV2 creation with wrong type."""
        with self.assertRaises(ValidationError) as cm:
            RoleV2.objects.create(name="test_role", type="wrong_type", tenant=self.tenant)
        self.assertIn("Value 'wrong_type' is not a valid choice.", str(cm.exception))

    def test_custom_role_creation(self):
        """Test V2 Custom Role creation."""
        role = CustomRoleV2.objects.create(name="custom_role", tenant=self.tenant)
        self.assertEqual(role.type, RoleV2.Types.CUSTOM)
        self.assertIsInstance(role, CustomRoleV2)
        self.assertIsInstance(role, RoleV2)

    def test_custom_role_creation_with_type(self):
        """Test V2 Custom Role creation with type."""
        role = CustomRoleV2.objects.create(name="custom_role", type=RoleV2.Types.CUSTOM, tenant=self.tenant)
        self.assertEqual(role.type, RoleV2.Types.CUSTOM)
        self.assertIsInstance(role, CustomRoleV2)
        self.assertIsInstance(role, RoleV2)

    def test_custom_role_creation_from_base_role(self):
        """Test V2 Custom Role creation from base role."""
        role = RoleV2.objects.create(name="custom_role", type=RoleV2.Types.CUSTOM, tenant=self.tenant)
        self.assertEqual(role.type, RoleV2.Types.CUSTOM)
        self.assertIsInstance(role, RoleV2)

        custom_role = CustomRoleV2.objects.get(id=role.id)
        self.assertEqual(custom_role.type, RoleV2.Types.CUSTOM)
        self.assertIsInstance(custom_role, CustomRoleV2)
        self.assertIsInstance(custom_role, RoleV2)

    def test_custom_role_creation_with_wrong_type(self):
        """Test V2 Custom Role creation with wrong type causes the exception."""
        with self.assertRaises(serializers.ValidationError) as cm:
            CustomRoleV2.objects.create(name="custom_role", type=RoleV2.Types.PLATFORM, tenant=self.tenant)
        self.assertIn("Expected role to have type custom, but found platform", str(cm.exception))

    def test_custom_role_type_validation_on_init(self):
        """Test type validation when creating V2 Custom Role with wrong type."""
        # Create base role with type = PLATFORM
        base_role = RoleV2.objects.create(name="platform_role", type=RoleV2.Types.PLATFORM, tenant=self.tenant)

        # Try to wrap as CustomRoleV2 - should fail
        with self.assertRaises(serializers.ValidationError) as cm:
            CustomRoleV2(id=base_role.id, name=base_role.name, type=base_role.type, tenant=self.tenant)
        self.assertIn("Expected role to have type custom, but found platform", str(cm.exception))

        # No custom roles exist with this id
        with self.assertRaises(CustomRoleV2.DoesNotExist):
            CustomRoleV2.objects.get(id=base_role.id)

        # Role exists as platform role
        platform_role = PlatformRoleV2.objects.get(id=base_role.id)
        self.assertEqual(platform_role.type, RoleV2.Types.PLATFORM)
        self.assertIsInstance(platform_role, PlatformRoleV2)
        self.assertIsInstance(platform_role, RoleV2)

    def test_custom_role_type_validation_on_save(self):
        """Test type validation when saving V2 Custom Role with wrong type."""
        role = CustomRoleV2(name="test_role", tenant=self.tenant)
        role.type = RoleV2.Types.PLATFORM  # Wrong type

        with self.assertRaises(serializers.ValidationError) as cm:
            role.save()
        self.assertIn("Expected role to have type custom, but found platform", str(cm.exception))

    def test_custom_role_cannot_have_children(self):
        """Test that V2 Custom Role cannot have children."""
        parent = CustomRoleV2.objects.create(name="parent", tenant=self.tenant)
        child = CustomRoleV2.objects.create(name="child", tenant=self.tenant)

        with transaction.atomic():
            with self.assertRaises(serializers.ValidationError) as cm:
                parent.children.add(child)
            self.assertIn("Custom roles cannot have children", str(cm.exception))

    def test_seeded_role_creation(self):
        """Test V2 Seeded Role creation."""
        role = SeededRoleV2.objects.create(name="seeded_role", tenant=self.tenant)
        self.assertEqual(role.type, RoleV2.Types.SEEDED)
        self.assertIsInstance(role, SeededRoleV2)
        self.assertIsInstance(role, RoleV2)

    def test_seeded_role_creation_with_type(self):
        """Test V2 Seeded Role creation with type."""
        role = SeededRoleV2.objects.create(name="seeded_role", type=RoleV2.Types.SEEDED, tenant=self.tenant)
        self.assertEqual(role.type, RoleV2.Types.SEEDED)
        self.assertIsInstance(role, SeededRoleV2)
        self.assertIsInstance(role, RoleV2)

    def test_seeded_role_creation_from_base_role(self):
        """Test V2 Seeded Role creation from base role."""
        role = RoleV2.objects.create(name="seeded_role", type=RoleV2.Types.SEEDED, tenant=self.tenant)
        self.assertEqual(role.type, RoleV2.Types.SEEDED)
        self.assertIsInstance(role, RoleV2)

        seeded_role = SeededRoleV2.objects.get(id=role.id)
        self.assertEqual(seeded_role.type, RoleV2.Types.SEEDED)
        self.assertIsInstance(seeded_role, SeededRoleV2)
        self.assertIsInstance(seeded_role, RoleV2)

    def test_seeded_role_creation_with_wrong_type(self):
        """Test V2 Seeded Role creation with wrong type causes the exception."""
        with self.assertRaises(serializers.ValidationError) as cm:
            SeededRoleV2.objects.create(name="seeded_role", type=RoleV2.Types.CUSTOM, tenant=self.tenant)
        self.assertIn("Expected role to have type seeded, but found custom", str(cm.exception))

    def test_seeded_role_type_validation_on_init(self):
        """Test type validation when creating V2 Seeded Role with wrong type."""
        # Create base role with wrong type
        base_role = RoleV2.objects.create(name="custom_role", type=RoleV2.Types.CUSTOM, tenant=self.tenant)

        # Try to wrap as SeededRoleV2 - should fail
        with self.assertRaises(serializers.ValidationError) as cm:
            SeededRoleV2(id=base_role.id, name=base_role.name, type=base_role.type, tenant=self.tenant)
        self.assertIn("Expected role to have type seeded, but found custom", str(cm.exception))

        # No seeded roles exist with this id
        with self.assertRaises(SeededRoleV2.DoesNotExist):
            SeededRoleV2.objects.get(id=base_role.id)

        # Role exists as custom role
        custom_role = CustomRoleV2.objects.get(id=base_role.id)
        self.assertEqual(custom_role.type, RoleV2.Types.CUSTOM)
        self.assertIsInstance(custom_role, CustomRoleV2)
        self.assertIsInstance(custom_role, RoleV2)

    def test_seeded_role_type_validation_on_save(self):
        """Test type validation when saving V2 Seeded Role with wrong type."""
        role = SeededRoleV2(name="test_role", tenant=self.tenant)
        role.type = RoleV2.Types.PLATFORM  # Wrong type

        with self.assertRaises(serializers.ValidationError) as cm:
            role.save()
        self.assertIn("Expected role to have type seeded", str(cm.exception))

    def test_seeded_role_cannot_have_children(self):
        """Test that V2 Seeded Role cannot have children."""
        parent = SeededRoleV2.objects.create(name="parent", tenant=self.tenant)
        child = SeededRoleV2.objects.create(name="child", tenant=self.tenant)

        with transaction.atomic():
            with self.assertRaises(serializers.ValidationError) as cm:
                parent.children.add(child)
            self.assertIn("Seeded roles cannot have children", str(cm.exception))

    def test_platform_role_creation(self):
        """Test V2 Platform Role creation."""
        role = PlatformRoleV2.objects.create(name="platform_role", tenant=self.tenant)
        self.assertEqual(role.type, RoleV2.Types.PLATFORM)
        self.assertIsInstance(role, PlatformRoleV2)
        self.assertIsInstance(role, RoleV2)

    def test_platform_role_creation_with_type(self):
        """Test V2 Platform Role creation with type."""
        role = PlatformRoleV2.objects.create(name="platform_role", type=RoleV2.Types.PLATFORM, tenant=self.tenant)
        self.assertEqual(role.type, RoleV2.Types.PLATFORM)
        self.assertIsInstance(role, PlatformRoleV2)
        self.assertIsInstance(role, RoleV2)

    def test_platform_role_creation_from_base_role(self):
        """Test V2 Platform Role creation from base role."""
        role = RoleV2.objects.create(name="platform_role", type=RoleV2.Types.PLATFORM, tenant=self.tenant)
        self.assertEqual(role.type, RoleV2.Types.PLATFORM)
        self.assertIsInstance(role, RoleV2)

        platform_role = PlatformRoleV2.objects.get(id=role.id)
        self.assertEqual(platform_role.type, RoleV2.Types.PLATFORM)
        self.assertIsInstance(platform_role, PlatformRoleV2)
        self.assertIsInstance(platform_role, RoleV2)

    def test_platform_role_creation_with_wrong_type(self):
        """Test V2 Platform Role creation with wrong type causes the exception."""
        with self.assertRaises(serializers.ValidationError) as cm:
            PlatformRoleV2.objects.create(name="platform_role", type=RoleV2.Types.SEEDED, tenant=self.tenant)
        self.assertIn("Expected role to have type platform, but found seeded", str(cm.exception))

    def test_platform_role_type_validation_on_init(self):
        """Test type validation when creating V2 Platform Role with wrong type."""
        # Create base role with wrong type
        base_role = RoleV2.objects.create(name="seeded_role", type=RoleV2.Types.SEEDED, tenant=self.tenant)

        # Try to wrap as PlatformRoleV2 - should fail
        with self.assertRaises(serializers.ValidationError) as cm:
            PlatformRoleV2(id=base_role.id, name=base_role.name, type=base_role.type, tenant=self.tenant)
        self.assertIn("Expected role to have type platform, but found seeded", str(cm.exception))

        # No platform roles exist with this id
        with self.assertRaises(PlatformRoleV2.DoesNotExist):
            PlatformRoleV2.objects.get(id=base_role.id)

        # Role exists as seeded role
        seeded_role = SeededRoleV2.objects.get(id=base_role.id)
        self.assertEqual(seeded_role.type, RoleV2.Types.SEEDED)
        self.assertIsInstance(seeded_role, SeededRoleV2)
        self.assertIsInstance(seeded_role, RoleV2)

    def test_platform_role_type_validation_on_save(self):
        """Test type validation when saving V2 Platform Role with wrong type."""
        role = PlatformRoleV2(name="test_role", tenant=self.tenant)
        role.type = RoleV2.Types.CUSTOM  # Wrong type

        with self.assertRaises(serializers.ValidationError) as cm:
            role.save()
        self.assertIn("Expected role to have type platform", str(cm.exception))

    def test_platform_role_can_have_seeded_children(self):
        """Test that V2 Platform Role can have seeded children."""
        parent = PlatformRoleV2.objects.create(name="parent", tenant=self.tenant)
        child = SeededRoleV2.objects.create(name="child", tenant=self.tenant)
        # No exception should be raised
        try:
            parent.children.add(child)
        except serializers.ValidationError:
            self.fail("V2 Platform Role should be able to have seeded children")

        children = parent.children.all()
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].id, child.id)

    def test_platform_role_cannot_have_custom_children(self):
        """Test that V2 Platform Role cannot have custom children."""
        parent = PlatformRoleV2.objects.create(name="parent", tenant=self.tenant)
        child = CustomRoleV2.objects.create(name="child", tenant=self.tenant)

        with transaction.atomic():
            with self.assertRaises(serializers.ValidationError) as cm:
                parent.children.add(child)
            self.assertIn("Platform roles can only have seeded roles as children", str(cm.exception))

    def test_platform_role_cannot_have_platform_children(self):
        """Test that V2 Platform Role cannot have platform children."""
        parent = PlatformRoleV2.objects.create(name="parent", tenant=self.tenant)
        child = PlatformRoleV2.objects.create(name="child", tenant=self.tenant)

        with transaction.atomic():
            with self.assertRaises(serializers.ValidationError) as cm:
                parent.children.add(child)
            self.assertIn("Platform roles can only have seeded roles as children", str(cm.exception))

    def test_platform_role_mixed_children_validation(self):
        """Test V2 Platform Role validation with mixed valid/invalid children."""
        parent = PlatformRoleV2.objects.create(name="parent", tenant=self.tenant)
        valid_child = SeededRoleV2.objects.create(name="seeded_child", tenant=self.tenant)
        invalid_child = CustomRoleV2.objects.create(name="custom_child", tenant=self.tenant)

        with transaction.atomic():
            with self.assertRaises(serializers.ValidationError) as cm:
                parent.children.add(invalid_child)
            self.assertIn("Platform roles can only have seeded roles as children", str(cm.exception))

    def test_custom_role_add_permissions(self):
        """Test adding permissions to a custom role."""
        role = CustomRoleV2.objects.create(name="test_role", tenant=self.tenant)

        role.permissions.add(self.permission1, self.permission2)

        self.assertEqual(role.permissions.count(), 2)
        self.assertIn(self.permission1, role.permissions.all())
        self.assertIn(self.permission2, role.permissions.all())

    def test_custom_role_remove_permissions(self):
        """Test removing permissions from a custom role."""
        role = CustomRoleV2.objects.create(name="test_role", tenant=self.tenant)
        role.permissions.add(self.permission1, self.permission2)
        role.permissions.remove(self.permission1)
        self.assertEqual(role.permissions.count(), 1)
        self.assertNotIn(self.permission1, role.permissions.all())
        self.assertIn(self.permission2, role.permissions.all())

    def test_platform_role_add_permissions(self):
        """Test adding permissions to a platform role."""
        role = PlatformRoleV2.objects.create(name="test_role", tenant=self.tenant)

        role.permissions.add(self.permission1, self.permission2)

        self.assertEqual(role.permissions.count(), 2)
        self.assertIn(self.permission1, role.permissions.all())
        self.assertIn(self.permission2, role.permissions.all())

    def test_platform_role_remove_permissions(self):
        """Test removing permissions from a platform role."""
        role = PlatformRoleV2.objects.create(name="test_role", tenant=self.tenant)
        role.permissions.add(self.permission1, self.permission2)
        role.permissions.remove(self.permission1)
        self.assertEqual(role.permissions.count(), 1)
        self.assertNotIn(self.permission1, role.permissions.all())
        self.assertIn(self.permission2, role.permissions.all())

    def test_seeded_role_add_permissions(self):
        """Test adding permissions to a seeded role."""
        role = SeededRoleV2.objects.create(name="test_role", tenant=self.tenant)

        role.permissions.add(self.permission1, self.permission2)

        self.assertEqual(role.permissions.count(), 2)
        self.assertIn(self.permission1, role.permissions.all())
        self.assertIn(self.permission2, role.permissions.all())

    def test_seeded_role_remove_permissions(self):
        """Test removing permissions from a seeded role."""
        role = SeededRoleV2.objects.create(name="test_role", tenant=self.tenant)
        role.permissions.add(self.permission1, self.permission2)
        role.permissions.remove(self.permission1)
        self.assertEqual(role.permissions.count(), 1)
        self.assertNotIn(self.permission1, role.permissions.all())
        self.assertIn(self.permission2, role.permissions.all())

    def test_role_hierarchy(self):
        """Test role parent-child relationships."""
        parent = PlatformRoleV2.objects.create(name="parent", tenant=self.tenant)
        child1 = SeededRoleV2.objects.create(name="child1", tenant=self.tenant)
        child2 = SeededRoleV2.objects.create(name="child2", tenant=self.tenant)

        parent.children.add(child1, child2)

        self.assertEqual(parent.children.count(), 2)
        self.assertEqual(child1.parents.count(), 1)
        self.assertEqual(child1.parents.first(), parent)

    def test_mixed_type_queries(self):
        """Test querying across different role types."""
        custom_role = CustomRoleV2.objects.create(name=RoleV2.Types.CUSTOM, tenant=self.tenant)
        seeded_role = SeededRoleV2.objects.create(name=RoleV2.Types.SEEDED, tenant=self.tenant)
        platform_role = PlatformRoleV2.objects.create(name=RoleV2.Types.PLATFORM, tenant=self.tenant)

        # Base RoleV2 manager should return all types
        all_roles = RoleV2.objects.all()
        self.assertEqual(len(all_roles), 3)

        # Type-specific managers should filter correctly
        self.assertEqual(CustomRoleV2.objects.count(), 1)
        self.assertEqual(SeededRoleV2.objects.count(), 1)
        self.assertEqual(PlatformRoleV2.objects.count(), 1)

    def test_type_field_values(self):
        """Test that type field contains correct values."""
        custom_role = CustomRoleV2.objects.create(name=RoleV2.Types.CUSTOM, tenant=self.tenant)
        seeded_role = SeededRoleV2.objects.create(name=RoleV2.Types.SEEDED, tenant=self.tenant)
        platform_role = PlatformRoleV2.objects.create(name=RoleV2.Types.PLATFORM, tenant=self.tenant)

        # Refresh from DB to ensure values are persisted correctly
        custom_role.refresh_from_db()
        seeded_role.refresh_from_db()
        platform_role.refresh_from_db()

        self.assertEqual(custom_role.type, RoleV2.Types.CUSTOM)
        self.assertEqual(seeded_role.type, RoleV2.Types.SEEDED)
        self.assertEqual(platform_role.type, RoleV2.Types.PLATFORM)
