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
from management.workspace.serializer import WorkspaceSerializer
import uuid


class WorkspaceSerializerTest(TestCase):
    """Test the workspace serializer"""

    def setUp(self):
        """Set up workspace serializer tests."""
        tenant = Tenant.objects.get(tenant_name="public")
        self.parent = Workspace.objects.create(
            name="Parent", description="Parent desc", tenant=tenant, uuid=uuid.uuid4()
        )
        self.child = Workspace.objects.create(
            name="Child", description="Child desc", tenant=tenant, parent=self.parent, uuid=uuid.uuid4()
        )

    def tearDown(self):
        """Tear down workspace serializer tests."""
        Workspace.objects.update(parent=None)
        Workspace.objects.all().delete()

    def test_get_workspace_detail(self):
        """Return GET /workspace/<uuid>/ serializer response"""
        serializer = WorkspaceSerializer(self.child)
        expected_data = {
            "uuid": str(self.child.uuid),
            "name": self.child.name,
            "description": self.child.description,
            "parent_id": str(self.parent.uuid),
        }

        self.assertDictEqual(serializer.data, expected_data)
