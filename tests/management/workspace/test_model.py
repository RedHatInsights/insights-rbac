#
# Copyright 2024 Red Hat, Inc.
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
"""Test the workspace model."""
from api.models import Tenant
from management.models import Workspace
from tests.identity_request import IdentityRequest

from django.core.exceptions import ValidationError
from django.db.models import ProtectedError


class WorkspaceModelTests(IdentityRequest):
    """Test the workspace model."""

    def setUp(self):
        """Set up the workspace model tests."""
        super().setUp()

    def tearDown(self):
        """Tear down workspace model tests."""
        Workspace.objects.update(parent=None)
        Workspace.objects.all().delete()

    def test_child_parent_relations(self):
        """Test that workspaces can add/have parents as well as children"""
        tenant = Tenant.objects.create(tenant_name="Child/Parent Relations")
        parent = Workspace.objects.create(name="Parent", tenant=tenant, type=Workspace.Types.ROOT)
        child = Workspace.objects.create(name="Child", tenant=tenant, parent=parent, type=Workspace.Types.DEFAULT)
        self.assertEqual(child.parent, parent)
        self.assertEqual(list(parent.children.all()), [child])

    def test_delete_fails_when_children(self):
        """Test that workspaces will not be deleted when children exist"""
        tenant = Tenant.objects.create(tenant_name="Delete Fails With Children")
        parent = Workspace.objects.create(name="Parent", tenant=tenant, type=Workspace.Types.ROOT)
        child = Workspace.objects.create(name="Child", tenant=tenant, parent=parent, type=Workspace.Types.DEFAULT)
        self.assertRaises(ProtectedError, parent.delete)

    def test_ancestors(self):
        """Test ancestors on a workspace"""
        root = Workspace.objects.create(name="Root", tenant=self.tenant, parent=None, type=Workspace.Types.ROOT)
        level_1 = Workspace.objects.create(name="Level 1", tenant=self.tenant, parent=root)
        level_2 = Workspace.objects.create(name="Level 2", tenant=self.tenant, parent=level_1)
        level_3 = Workspace.objects.create(name="Level 3", tenant=self.tenant, parent=level_2)
        level_4 = Workspace.objects.create(name="Level 4", tenant=self.tenant, parent=level_3)
        self.assertCountEqual(level_3.ancestors(), [root, level_1, level_2])


class Types(IdentityRequest):
    """Test types on a workspace."""

    def setUp(self):
        """Set up the workspace model tests."""
        self.tenant_1_root_workspace = Workspace.objects.create(
            name="T1 Root Workspace", tenant=self.tenant, type=Workspace.Types.ROOT
        )
        self.tenant_1_default_workspace = Workspace.objects.create(
            name="T1 Default Workspace",
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            parent=self.tenant_1_root_workspace,
        )
        self.tenant_1_ungrouped_workspace = Workspace.objects.create(
            name="T1 Ungrouped Workspace",
            tenant=self.tenant,
            type=Workspace.Types.UNGROUPED,
            parent=self.tenant_1_root_workspace,
        )
        self.tenant_1_standard_workspace = Workspace.objects.create(
            name="T1 Standard Workspace",
            tenant=self.tenant,
            parent=self.tenant_1_default_workspace,
        )
        super().setUp()

    def tearDown(self):
        """Tear down workspace model tests."""
        Workspace.objects.update(parent=None)
        Workspace.objects.all().delete()

    def test_default_value(self):
        """Test the default value of a workspace type when not supplied"""
        self.assertEqual(self.tenant_1_standard_workspace.type, "standard")

    def test_single_root_per_tenant(self):
        """Test tenant can only have one root workspace"""
        with self.assertRaises(ValidationError) as assertion:
            Workspace.objects.create(name="T1 Root Workspace Number 2", type=Workspace.Types.ROOT, tenant=self.tenant)
        error_messages = assertion.exception.messages
        self.assertEqual(len(error_messages), 1)
        self.assertIn("unique_default_root_workspace_per_tenant", error_messages[0])

    def test_single_default_per_tenant(self):
        """Test tenant can only have one default workspace"""
        with self.assertRaises(ValidationError) as assertion:
            Workspace.objects.create(
                name="T1 Default Workspace Number 2",
                type=Workspace.Types.DEFAULT,
                tenant=self.tenant,
                parent=self.tenant_1_root_workspace,
            )
        error_messages = assertion.exception.messages
        self.assertEqual(len(error_messages), 1)
        self.assertIn("unique_default_root_workspace_per_tenant", error_messages[0])

    def test_single_ungrouped_per_tenant(self):
        """Test tenant can only have one ungrouped workspace"""
        with self.assertRaises(ValidationError) as assertion:
            Workspace.objects.create(
                name="T1 Ungrouped Workspace Number 2",
                type=Workspace.Types.UNGROUPED,
                tenant=self.tenant,
                parent=self.tenant_1_root_workspace,
            )
        error_messages = assertion.exception.messages
        self.assertEqual(len(error_messages), 1)
        self.assertIn("unique_default_root_workspace_per_tenant", error_messages[0])

    def test_multiple_specific_ws_multiple_tenants(self):
        """Test that multiple tenants can have more than one root/default/ungrouped workspace"""
        try:
            tenant_2 = Tenant.objects.create(tenant_name="Tenant 2")
            root = Workspace.objects.create(name="Root Workspace Number 2", type=Workspace.Types.ROOT, tenant=tenant_2)
            default = Workspace.objects.create(
                name="Default Workspace Number 2",
                type=Workspace.Types.DEFAULT,
                tenant=tenant_2,
                parent=root,
            )
            ungrouped = Workspace.objects.create(
                name="Ungrouped Workspace Number 2",
                type=Workspace.Types.UNGROUPED,
                tenant=tenant_2,
                parent=root,
            )
        except ValidationError as e:
            self.fail("test_multiple_root_and_default_multiple_tenants raised ValidationError unexpectedly")

    def test_multiple_standard_per_tenant(self):
        """Test tenant can have multiple standard workspaces"""
        try:
            for n in ["1", "2", "3"]:
                Workspace.objects.create(
                    name=f"T1 Standard Workspace Number {n}",
                    type=Workspace.Types.STANDARD,
                    tenant=self.tenant,
                    parent=self.tenant_1_default_workspace,
                )
        except ValidationError as e:
            self.fail("test_multiple_standard_per_tenant raised ValidationError unexpectedly")

    def test_standard_can_belong_to_root(self):
        """Test that a standard workspace can belong to a root workspace"""
        try:
            workspace = Workspace.objects.create(
                name=f"T1 Standard Workspace",
                type=Workspace.Types.STANDARD,
                tenant=self.tenant,
                parent=self.tenant_1_root_workspace,
            )
            self.assertEqual(workspace.parent, self.tenant_1_root_workspace)
        except ValidationError as e:
            self.fail("test_standard_can_belong_to_root raised ValidationError unexpectedly")

    def test_invalid_type(self):
        """Test invalid workspace type"""
        invalid_type = "foo"
        with self.assertRaises(ValidationError) as assertion:
            Workspace.objects.create(
                name="Invalid Type Workspace",
                type=invalid_type,
                tenant=self.tenant,
                parent=self.tenant_1_default_workspace,
            )
        error_messages = assertion.exception.messages
        self.assertEqual(len(error_messages), 1)
        self.assertEqual(f"Value '{invalid_type}' is not a valid choice.", error_messages[0])

    def test_default_no_parent(self):
        """Test default workspace creation with no parent"""
        tenant = Tenant.objects.create(tenant_name="Default no parent")
        with self.assertRaises(ValidationError) as assertion:
            Workspace.objects.create(name="Default", type=Workspace.Types.DEFAULT, tenant=tenant)
        self.assertEqual(
            {"parent_id": ["This field cannot be blank for non-root type workspaces."]},
            assertion.exception.message_dict,
        )

    def test_ungrouped_no_parent(self):
        """Test ungrouped workspace creation with no parent"""
        tenant = Tenant.objects.create(tenant_name="Ungrouped no parent")
        with self.assertRaises(ValidationError) as assertion:
            Workspace.objects.create(name="Ungrouped", type=Workspace.Types.UNGROUPED, tenant=tenant)
        self.assertEqual(
            {"parent_id": ["This field cannot be blank for non-root type workspaces."]},
            assertion.exception.message_dict,
        )
