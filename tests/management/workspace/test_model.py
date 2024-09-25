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
from management.models import Workspace
from tests.identity_request import IdentityRequest

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
        parent = Workspace.objects.create(name="Parent", tenant=self.tenant)
        child = Workspace.objects.create(name="Child", tenant=self.tenant, parent=parent)
        self.assertEqual(child.parent, parent)
        self.assertEqual(list(parent.children.all()), [child])

    def test_delete_fails_when_children(self):
        """Test that workspaces will not be deleted when children exist"""
        parent = Workspace.objects.create(name="Parent", tenant=self.tenant)
        child = Workspace.objects.create(name="Child", tenant=self.tenant, parent=parent)
        self.assertRaises(ProtectedError, parent.delete)

    def test_ancestors(self):
        """Test ancestors on a workspce"""
        root = Workspace.objects.create(name="Root", tenant=self.tenant, parent=None)
        level_1 = Workspace.objects.create(name="Level 1", tenant=self.tenant, parent=root)
        level_2 = Workspace.objects.create(name="Level 2", tenant=self.tenant, parent=level_1)
        level_3 = Workspace.objects.create(name="Level 3", tenant=self.tenant, parent=level_2)
        level_4 = Workspace.objects.create(name="Level 4", tenant=self.tenant, parent=level_3)
        self.assertCountEqual(level_3.ancestors(), [root, level_1, level_2])
