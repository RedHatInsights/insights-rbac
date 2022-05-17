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

from management.models import ExtRoleRelation, ExtTenant, Role
from tests.identity_request import IdentityRequest


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
