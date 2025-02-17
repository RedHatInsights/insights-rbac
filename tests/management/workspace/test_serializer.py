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
from django.test import TestCase
from unittest.mock import Mock
from api.models import Tenant
from management.models import Workspace
from management.workspace.serializer import (
    WorkspaceAncestrySerializer,
    WorkspaceSerializer,
    WorkspaceWithAncestrySerializer,
)


class WorkspaceSerializerTest(TestCase):
    """Test the workspace serializer"""

    def setUp(self):
        """Set up workspace serializer tests."""
        tenant = Tenant.objects.get(tenant_name="public")
        self.parent = Workspace.objects.create(
            name="Parent",
            description="Parent desc",
            tenant=tenant,
            type=Workspace.Types.ROOT,
        )
        self.child = Workspace.objects.create(
            name="Child", description="Child desc", tenant=tenant, parent=self.parent
        )

    def tearDown(self):
        """Tear down workspace serializer tests."""
        Workspace.objects.update(parent=None)
        Workspace.objects.all().delete()

    def _format_timestamps(self, timestamp):
        return timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z")

    def test_get_workspace_detail_child(self):
        """Return GET /workspace/<id>/ serializer response for child"""
        serializer = WorkspaceSerializer(self.child)
        expected_data = {
            "id": str(self.child.id),
            "name": self.child.name,
            "description": self.child.description,
            "parent_id": str(self.parent.id),
            "created": self._format_timestamps(self.child.created),
            "modified": self._format_timestamps(self.child.modified),
            "type": self.child.type,
        }

        self.assertDictEqual(serializer.data, expected_data)

    def test_get_workspace_detail_parent(self):
        """Return GET /workspace/<id>/ serializer response for parent"""
        serializer = WorkspaceSerializer(self.parent)
        expected_data = {
            "id": str(self.parent.id),
            "name": self.parent.name,
            "description": self.parent.description,
            "parent_id": None,
            "created": self._format_timestamps(self.parent.created),
            "modified": self._format_timestamps(self.parent.modified),
            "type": self.parent.type,
        }

        self.assertDictEqual(serializer.data, expected_data)

    def test_get_workspace_detail_with_ancestry(self):
        """Test workspace serializer with ancestry"""
        serializer = WorkspaceWithAncestrySerializer(self.child)
        expected_data = {
            "id": str(self.child.id),
            "name": self.child.name,
            "description": self.child.description,
            "parent_id": str(self.parent.id),
            "created": self._format_timestamps(self.child.created),
            "modified": self._format_timestamps(self.child.modified),
            "ancestry": [{"name": self.parent.name, "id": str(self.parent.id), "parent_id": None}],
            "created": self._format_timestamps(self.child.created),
            "modified": self._format_timestamps(self.child.modified),
            "type": self.child.type,
        }

        self.assertDictEqual(serializer.data, expected_data)

    def test_workspace_ancestry(self):
        """Test workspace ancestry serializer"""
        serializer = WorkspaceAncestrySerializer(self.child)
        expected_data = {"name": self.child.name, "parent_id": str(self.parent.id), "id": str(self.child.id)}

        self.assertDictEqual(serializer.data, expected_data)
