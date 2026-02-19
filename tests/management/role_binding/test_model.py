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
"""Test the RoleBinding models."""

import uuid

from django.db import IntegrityError, transaction

from api.models import Tenant
from management.models import (
    Group,
    Permission,
    RoleBinding,
    RoleBindingGroup,
    RoleV2,
)
from management.principal.model import Principal
from management.role_binding.model import RoleBindingPrincipal
from tests.identity_request import IdentityRequest


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
