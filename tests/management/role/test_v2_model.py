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

import uuid

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from rest_framework import serializers

from api.models import Tenant
from management.models import (
    CustomRoleV2,
    Group,
    Permission,
    PlatformRoleV2,
    RoleBinding,
    RoleBindingGroup,
    RoleV2,
    SeededRoleV2,
)
from management.principal.model import Principal
from management.role.model import Access
from management.role.v2_model import RoleBindingPrincipal
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


class RoleBindingModelTests(IdentityRequest):
    """Test the RoleBinding models."""

    def setUp(self):
        """Set up the RoleBinding model tests."""
        super().setUp()

        # Test role
        self.role = RoleV2.objects.create(name="test_role", tenant=self.tenant)

        self.role.permissions.add(
            Permission.objects.create(
                tenant=Tenant.objects.get(tenant_name="public"),
                permission="app:resource:verb",
            )
        )

        # Test groups
        self.group1 = Group.objects.create(name="group1", tenant=self.tenant)
        self.group2 = Group.objects.create(name="group2", tenant=self.tenant)

        self.principal1: Principal = Principal.objects.create(tenant=self.tenant, username="p1", user_id="p1")
        self.principal2: Principal = Principal.objects.create(tenant=self.tenant, username="p2", user_id="p2")

    def tearDown(self):
        """Tear down RoleBinding model tests."""
        RoleBinding.objects.all().delete()
        RoleBindingGroup.objects.all().delete()
        RoleV2.objects.all().delete()
        Group.objects.all().delete()

    def test_rolebinding_creation(self):
        """Test basic RoleBinding creation."""
        binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        self.assertEqual(binding.role, self.role)
        self.assertEqual(binding.resource_type, "workspace")
        self.assertEqual(binding.resource_id, "ws-12345")
        self.assertEqual(binding.tenant, self.tenant)
        self.assertTrue(binding.uuid)

    def test_rolebinding_unique_constraint(self):
        """Test unique constraint on (role, resource_type, resource_id)."""
        resource_type = "workspace"
        resource_id = "ws-12345"
        RoleBinding.objects.create(
            role=self.role,
            resource_type=resource_type,
            resource_id=resource_id,
            tenant=self.tenant,
        )

        # Try to create duplicate
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                RoleBinding.objects.create(
                    role=self.role,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    tenant=self.tenant,
                )

    def test_rolebinding_different_resources_same_role(self):
        """Test that same role can be bound to different resources."""
        binding1 = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        binding2 = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-67890",
            tenant=self.tenant,
        )

        self.assertNotEqual(binding1.id, binding2.id)
        self.assertEqual(binding1.role, binding2.role)

    def test_rolebinding_cascade_delete_on_role(self):
        """Test that deleting a role deletes its bindings."""
        binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        binding_id = binding.id
        self.role.delete()

        # Binding should be deleted
        with self.assertRaises(RoleBinding.DoesNotExist):
            RoleBinding.objects.get(id=binding_id)

    def test_rolebinding_cascade_delete_on_tenant(self):
        """Test that deleting a tenant deletes its role bindings."""
        # Create separate tenant with role and binding
        new_tenant = Tenant.objects.create(
            tenant_name="test_tenant_delete",
            org_id="test_org_delete",
        )

        new_role = RoleV2.objects.create(name="temp_role", tenant=new_tenant)
        binding = RoleBinding.objects.create(
            role=new_role,
            resource_type="workspace",
            resource_id="ws-temp",
            tenant=new_tenant,
        )

        binding_id = binding.id
        new_tenant.delete()

        # Binding should be deleted
        with self.assertRaises(RoleBinding.DoesNotExist):
            RoleBinding.objects.get(id=binding_id)

        # Role should be deleted
        with self.assertRaises(RoleV2.DoesNotExist):
            RoleV2.objects.get(id=new_role.id)

    def test_rolebindinggroup_creation(self):
        """Test basic RoleBindingGroup creation."""
        binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        binding_group = RoleBindingGroup.objects.create(
            group=self.group1,
            binding=binding,
        )

        self.assertEqual(binding_group.group, self.group1)
        self.assertEqual(binding_group.binding, binding)

    def test_rolebindinggroup_unique_constraint(self):
        """Test unique constraint on (group, binding)."""
        binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        RoleBindingGroup.objects.create(
            group=self.group1,
            binding=binding,
        )

        # Try to create duplicate
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                RoleBindingGroup.objects.create(
                    group=self.group1,
                    binding=binding,
                )

    def test_rolebindinggroup_different_groups_same_binding(self):
        """Test that different groups can have same binding."""
        binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        bg1 = RoleBindingGroup.objects.create(
            group=self.group1,
            binding=binding,
        )

        bg2 = RoleBindingGroup.objects.create(
            group=self.group2,
            binding=binding,
        )

        self.assertNotEqual(bg1.id, bg2.id)
        self.assertEqual(bg1.binding, bg2.binding)

    def test_rolebindinggroup_cascade_delete_on_binding(self):
        """Test that deleting a binding deletes its group entries."""
        binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        bg = RoleBindingGroup.objects.create(
            group=self.group1,
            binding=binding,
        )

        bg_id = bg.id
        binding.delete()

        # Group entry should be deleted
        with self.assertRaises(RoleBindingGroup.DoesNotExist):
            RoleBindingGroup.objects.get(id=bg_id)

    def test_rolebindinggroup_cascade_delete_on_group(self):
        """Test that deleting a group deletes its binding entries."""
        binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        bg = RoleBindingGroup.objects.create(
            group=self.group1,
            binding=binding,
        )

        bg_id = bg.id
        group_id = self.group1.id
        self.group1.delete()

        with self.assertRaises(Group.DoesNotExist):
            Group.objects.get(id=group_id)

        # Group entry should be deleted
        with self.assertRaises(RoleBindingGroup.DoesNotExist):
            RoleBindingGroup.objects.get(id=bg_id)

    def test_complete_rolebinding_scenario(self):
        """Test a complete scenario with role binding and groups."""
        # Create binding
        binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        # Add groups
        RoleBindingGroup.objects.create(
            group=self.group1,
            binding=binding,
        )
        RoleBindingGroup.objects.create(
            group=self.group2,
            binding=binding,
        )

        # Verify relationships
        self.assertEqual(binding.group_entries.count(), 2)

        # Verify reverse relationships
        self.assertEqual(self.group1.role_binding_entries.count(), 1)
        self.assertEqual(self.group2.role_binding_entries.count(), 1)

    def test_rolebinding_related_names(self):
        """Test related_name attributes from binding classes work correctly."""
        binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        # Test role.bindings
        self.assertIn(binding, self.role.bindings.all())

        # Test binding.group_entries
        bg = RoleBindingGroup.objects.create(
            group=self.group1,
            binding=binding,
        )

        self.assertIn(bg, binding.group_entries.all())

        # Test group.role_binding_entries
        self.assertIn(bg, self.group1.role_binding_entries.all())

    def test_as_migration_value(self):
        binding: RoleBinding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        binding.group_entries.create(
            group=self.group1,
            binding=binding,
        )

        migration_value = binding.as_migration_value()

        self.assertEqual(str(binding.uuid), migration_value.id)
        self.assertEqual(("rbac", "workspace"), migration_value.resource.resource_type)
        self.assertEqual("ws-12345", migration_value.resource.resource_id)
        self.assertEqual(str(self.role.uuid), migration_value.role.id)
        self.assertCountEqual(["app_resource_verb"], migration_value.role.permissions)
        self.assertFalse(migration_value.role.is_system)
        self.assertCountEqual([str(self.group1.uuid)], migration_value.groups)
        self.assertEqual({}, migration_value.users)

    def test_as_migration_value_force_groups(self):
        binding: RoleBinding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        group_uuid = uuid.uuid4()
        migration_value = binding.as_migration_value(force_group_uuids=[str(group_uuid)])

        self.assertEqual(str(binding.uuid), migration_value.id)
        self.assertEqual(("rbac", "workspace"), migration_value.resource.resource_type)
        self.assertEqual("ws-12345", migration_value.resource.resource_id)
        self.assertEqual(str(self.role.uuid), migration_value.role.id)
        self.assertCountEqual(["app_resource_verb"], migration_value.role.permissions)
        self.assertFalse(migration_value.role.is_system)
        self.assertCountEqual([str(group_uuid)], migration_value.groups)
        self.assertEqual({}, migration_value.users)

    def test_update_groups(self):
        binding: RoleBinding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        binding.update_groups([self.group1])
        self.assertCountEqual([self.group1], binding.bound_groups())

        binding.update_groups([self.group2])
        self.assertCountEqual([self.group2], binding.bound_groups())

        binding.update_groups([self.group1, self.group2])
        self.assertCountEqual([self.group1, self.group2], binding.bound_groups())

        binding.update_groups([])
        self.assertCountEqual([], binding.bound_groups())

    def test_update_groups_by_uuid(self):
        binding: RoleBinding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        binding.update_groups_by_uuid([self.group1.uuid])
        self.assertCountEqual([self.group1], binding.bound_groups())

        binding.update_groups_by_uuid([self.group2.uuid])
        self.assertCountEqual([self.group2], binding.bound_groups())

        binding.update_groups_by_uuid([self.group1.uuid, self.group2.uuid])
        self.assertCountEqual([self.group1, self.group2], binding.bound_groups())

        binding.update_groups_by_uuid([])
        self.assertCountEqual([], binding.bound_groups())

    def test_update_groups_by_uuid_invalid(self):
        binding: RoleBinding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        binding.update_groups_by_uuid([self.group1.uuid, self.group2.uuid])
        self.assertCountEqual([self.group1, self.group2], binding.bound_groups())

        with self.assertRaises(ValueError):
            # Attempt to pass a non-existent group UUID.
            binding.update_groups_by_uuid([self.group1.uuid, uuid.uuid4()])

        # The set of groups should not change after a failed attempt to set the groups.
        self.assertCountEqual([self.group1, self.group2], binding.bound_groups())

    def test_update_principals(self):
        binding: RoleBinding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        pair1 = ("car/1", self.principal1)
        pair2 = ("car/2", self.principal2)

        binding.update_principals([pair1])
        self.assertCountEqual([self.principal1], binding.bound_principals())

        binding.update_principals([pair2])
        self.assertCountEqual([self.principal2], binding.bound_principals())

        binding.update_principals([pair1, pair2])
        self.assertCountEqual([self.principal1, self.principal2], binding.bound_principals())

        binding.update_principals([])
        self.assertCountEqual([], binding.bound_principals())

        # Multiple principals from the same source should work.
        binding.update_principals([("car", self.principal1), ("car", self.principal2)])
        self.assertCountEqual([self.principal1, self.principal2], binding.bound_principals())

        # Multiple sources of the same principal should work.
        binding.update_principals([("car/1", self.principal1), ("car/2", self.principal1)])
        self.assertCountEqual([self.principal1], binding.bound_principals())
        self.assertEqual(binding.principal_entries.all().count(), 2)

    def test_update_principals_by_user_id(self):
        binding: RoleBinding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        pair1: tuple[str, str] = ("car/1", self.principal1.user_id)
        pair2: tuple[str, str] = ("car/2", self.principal2.user_id)

        binding.update_principals_by_user_id([pair1])
        self.assertCountEqual([self.principal1], binding.bound_principals())

        binding.update_principals_by_user_id([pair2])
        self.assertCountEqual([self.principal2], binding.bound_principals())

        binding.update_principals_by_user_id([pair1, pair2])
        self.assertCountEqual([self.principal1, self.principal2], binding.bound_principals())

        binding.update_principals_by_user_id([])
        self.assertCountEqual([], binding.bound_principals())

        # Multiple principals from the same source should work.
        binding.update_principals_by_user_id([("car", self.principal1.user_id), ("car", self.principal2.user_id)])
        self.assertCountEqual([self.principal1, self.principal2], binding.bound_principals())

        # Multiple sources of the same principal should work.
        binding.update_principals_by_user_id([("car/1", self.principal1.user_id), ("car/2", self.principal1.user_id)])
        self.assertCountEqual([self.principal1], binding.bound_principals())
        self.assertEqual(binding.principal_entries.all().count(), 2)

    def test_update_principals_by_user_id_nonexistent(self):
        binding: RoleBinding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        binding.update_principals([("car/1", self.principal1)])

        with self.assertRaisesRegex(ValueError, ".*test_nonexistent.*"):
            binding.update_principals_by_user_id([("car", "test_nonexistent")])

        # The existing principals should be unchanged.
        self.assertCountEqual([self.principal1], binding.bound_principals())

    def test_principal_no_source(self):
        binding: RoleBinding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id="ws-12345",
            tenant=self.tenant,
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                RoleBindingPrincipal.objects.create(
                    binding=binding,
                    principal=self.principal1,
                )
