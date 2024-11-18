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
from django.db import IntegrityError, transaction

from management.models import BindingMapping, ExtRoleRelation, ExtTenant, Role
from tests.identity_request import IdentityRequest
from migration_tool.models import (
    V2role,
    V2rolebinding,
    V2boundresource,
)
from migration_tool.utils import create_relationship


class RoleModelTests(IdentityRequest):
    """Test the group model."""

    def setUp(self):
        """Set up the group model tests."""
        super().setUp()

        self.roleA = Role.objects.create(name="roleA", tenant=self.tenant)
        self.roleB = Role.objects.create(name="roleB", system=True, tenant=self.tenant)

    def tearDown(self):
        """Tear down group model tests."""
        Role.objects.all().delete()

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

    def test_ext_role_relation_creation(self):
        """Test external role relation creation."""
        ocm = ExtTenant.objects.create(name="ocm")
        # Can not create without role
        with transaction.atomic():
            self.assertRaises(IntegrityError, ExtRoleRelation.objects.create, ext_id="OCMRoleTest1", ext_tenant=ocm)

        # Ext_id with ext_tenant is unique, conflict would raise exception
        ExtRoleRelation.objects.create(ext_id="OCMRoleTest1", ext_tenant=ocm, role=self.roleA)
        with transaction.atomic():
            self.assertRaises(
                IntegrityError,
                ExtRoleRelation.objects.create,
                ext_id="OCMRoleTest1",
                ext_tenant=ocm,
                role=self.roleB,
            )

        # Same ext_id but different ext_tenant is fine
        kcp = ExtTenant.objects.create(name="kcp")
        ExtRoleRelation.objects.create(ext_id="OCMRoleTest1", ext_tenant=kcp, role=self.roleB)

    def test_ext_role_relation_attachment(self):
        """Test that the external role relation could be attached to a role."""
        ocm = ExtTenant.objects.create(name="ocm")
        ext_relation1 = ExtRoleRelation.objects.create(ext_id="OCMRoleTest1", ext_tenant=ocm, role=self.roleA)

        # Can access role from relation and vice versa
        ext_relation1.role.name = self.roleA.name
        self.roleA.ext_relation.id = ext_relation1.id

        # Can not attach a role belong to another external relation
        with transaction.atomic():
            self.assertRaises(
                IntegrityError,
                ExtRoleRelation.objects.create,
                ext_id="OCMRoleTest2",
                ext_tenant=ocm,
                role=self.roleA,
            )


class BindingMappingTests(IdentityRequest):
    """Test the BindingMapping model."""

    def setUp(self):
        """Set up the BindingMapping model tests."""
        super().setUp()

        self.role = Role.objects.create(name="role", tenant=self.tenant)
        self.v2role = V2role(id="v2role", is_system=False, permissions=frozenset(["perm1", "perm2"]))
        self.resource = V2boundresource(resource_type=("namespace", "type"), resource_id="resource_id")
        self.v2rolebinding = V2rolebinding(
            id="v2rolebinding", role=self.v2role, resource=self.resource, groups=frozenset(), users=frozenset()
        )
        self.binding_mapping = BindingMapping.for_role_binding(self.v2rolebinding, self.role)

    def test_is_unassigned(self):
        """Test that it is only unassigned when there are no groups and no users."""
        self.assertTrue(self.binding_mapping.is_unassigned())

        self.binding_mapping.add_group_to_bindings("group1")
        self.assertFalse(self.binding_mapping.is_unassigned())

        self.binding_mapping.remove_group_from_bindings("group1")
        self.binding_mapping.add_user_to_bindings("user1")
        self.assertFalse(self.binding_mapping.is_unassigned())

    def test_add_group_to_bindings(self):
        """Test that adding groups adds to the groups array in the mapping with group uuids."""
        self.binding_mapping.add_group_to_bindings("group1")
        self.binding_mapping.add_group_to_bindings("group2")
        self.assertIn("group1", self.binding_mapping.mappings["groups"])
        self.assertIn("group2", self.binding_mapping.mappings["groups"])

    def test_add_user_to_bindings(self):
        """Test that adding users adds to the users array in the mapping with user ids."""
        self.binding_mapping.add_user_to_bindings("user1")
        self.binding_mapping.add_user_to_bindings("user2")
        self.assertIn("user1", self.binding_mapping.mappings["users"])
        self.assertIn("user2", self.binding_mapping.mappings["users"])

    def test_remove_group_from_bindings(self):
        """Test that after removing groups, they aren't in the mapping except for ones which were removed."""
        self.binding_mapping.add_group_to_bindings("group1")
        self.binding_mapping.add_group_to_bindings("group2")
        self.binding_mapping.remove_group_from_bindings("group1")
        self.assertNotIn("group1", self.binding_mapping.mappings["groups"])
        self.assertIn("group2", self.binding_mapping.mappings["groups"])

    def test_remove_user_from_bindings(self):
        """Test that after removing users, they aren't in the mapping except for ones which were removed."""
        self.binding_mapping.add_user_to_bindings("user1")
        self.binding_mapping.add_user_to_bindings("user2")
        self.binding_mapping.remove_user_from_bindings("user1")
        self.assertNotIn("user1", self.binding_mapping.mappings["users"])
        self.assertIn("user2", self.binding_mapping.mappings["users"])

    def test_add_group_to_bindings_returns_tuple(self):
        """Test that add_group_to_bindings method returns the expected tuple."""
        relationship = self.binding_mapping.add_group_to_bindings("group1")
        self.assertEqual(
            relationship,
            create_relationship(
                ("rbac", "role_binding"),
                "v2rolebinding",
                ("rbac", "group"),
                "group1",
                "subject",
                subject_relation="member",
            ),
        )

    def test_add_user_to_bindings_returns_tuple(self):
        """Test that add_user_to_bindings method returns the expected tuple."""
        relationship = self.binding_mapping.add_user_to_bindings("user1")
        self.assertEqual(
            relationship,
            create_relationship(
                ("rbac", "role_binding"),
                "v2rolebinding",
                ("rbac", "principal"),
                "redhat/user1",
                "subject",
            ),
        )

    def test_remove_group_from_bindings_returns_tuple(self):
        """Test that remove_group_from_bindings method returns the expected tuple."""
        self.binding_mapping.add_group_to_bindings("group1")
        relationship = self.binding_mapping.remove_group_from_bindings("group1")
        self.assertEqual(
            relationship,
            create_relationship(
                ("rbac", "role_binding"),
                "v2rolebinding",
                ("rbac", "group"),
                "group1",
                "subject",
                subject_relation="member",
            ),
        )

    def test_remove_user_from_bindings_returns_tuple(self):
        """Test that remove_user_from_bindings method returns the expected tuple."""
        self.binding_mapping.add_user_to_bindings("user1")
        relationship = self.binding_mapping.remove_user_from_bindings("user1")
        self.assertEqual(
            relationship,
            create_relationship(
                ("rbac", "role_binding"),
                "v2rolebinding",
                ("rbac", "principal"),
                "redhat/user1",
                "subject",
            ),
        )

    def test_as_tuples_includes_group_and_user_tuples(self):
        """Test that when converted to tuples it includes both group and user tuples."""
        self.binding_mapping.add_group_to_bindings("group1")
        self.binding_mapping.add_user_to_bindings("user1")
        tuples = self.binding_mapping.as_tuples()
        self.assertIn(
            create_relationship(
                ("rbac", "role_binding"),
                "v2rolebinding",
                ("rbac", "group"),
                "group1",
                "subject",
                subject_relation="member",
            ),
            tuples,
        )
        self.assertIn(
            create_relationship(
                ("rbac", "role_binding"),
                "v2rolebinding",
                ("rbac", "principal"),
                "redhat/user1",
                "subject",
            ),
            tuples,
        )

    def test_remove_all_groups_unassigned(self):
        """Test that removing all groups means the mapping is now unassigned."""
        self.binding_mapping.add_group_to_bindings("group1")
        self.binding_mapping.add_group_to_bindings("group2")
        self.binding_mapping.remove_group_from_bindings("group1")
        self.binding_mapping.remove_group_from_bindings("group2")
        self.assertTrue(self.binding_mapping.is_unassigned())

    def test_remove_all_users_unassigned(self):
        """Test that removing all users means the mapping is now unassigned."""
        self.binding_mapping.add_user_to_bindings("user1")
        self.binding_mapping.add_user_to_bindings("user2")
        self.binding_mapping.remove_user_from_bindings("user1")
        self.binding_mapping.remove_user_from_bindings("user2")
        self.assertTrue(self.binding_mapping.is_unassigned())

    def test_get_role_binding_includes_groups_and_users(self):
        """Test that get_role_binding includes both groups and users."""
        self.binding_mapping.add_group_to_bindings("group1")
        self.binding_mapping.add_group_to_bindings("group1")
        self.binding_mapping.add_user_to_bindings("user1")
        self.binding_mapping.add_user_to_bindings("user1")
        role_binding = self.binding_mapping.get_role_binding()
        self.assertIn("group1", role_binding.groups)
        self.assertIn("user1", role_binding.users)
        self.assertEqual(len(role_binding.groups), 2)
        self.assertEqual(len(role_binding.users), 2)

    def test_get_role_binding_includes_duplicate_users(self):
        """Test that get_role_binding includes duplicate users."""
        self.binding_mapping.add_user_to_bindings("user1")
        self.binding_mapping.add_user_to_bindings("user1")
        role_binding = self.binding_mapping.get_role_binding()
        self.assertIn("user1", role_binding.users)
        self.assertEqual(len(role_binding.users), 2)

    def test_get_role_binding_includes_duplicate_groups(self):
        """Test that get_role_binding includes duplicate groups."""
        self.binding_mapping.add_group_to_bindings("group1")
        self.binding_mapping.add_group_to_bindings("group1")
        role_binding = self.binding_mapping.get_role_binding()
        self.assertIn("group1", role_binding.groups)
        self.assertEqual(len(role_binding.groups), 2)
