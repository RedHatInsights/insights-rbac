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
from django.test import TestCase
from rest_framework import serializers
from api.models import Tenant
from management.models import Workspace
from management.workspace.service import WorkspaceService
from django.conf import settings
from django.core.exceptions import ValidationError
from django.test.utils import override_settings


class WorkspaceServiceTestBase(TestCase):
    """Base test class"""

    @classmethod
    def setUpTestData(cls):
        """Set up workspace service tests."""
        cls.service = WorkspaceService()
        cls.tenant = Tenant.objects.create(tenant_name="Foo Tenant")
        cls.root_workspace = Workspace.objects.create(name="Root", type=Workspace.Types.ROOT, tenant=cls.tenant)
        cls.default_workspace = Workspace.objects.create(
            name="Default", type=Workspace.Types.DEFAULT, tenant=cls.tenant, parent=cls.root_workspace
        )
        cls.standard_workspace = Workspace.objects.create(
            name="Standard", type=Workspace.Types.STANDARD, tenant=cls.tenant, parent=cls.default_workspace
        )
        cls.standard_child_workspace = Workspace.objects.create(
            name="Standard Child", type=Workspace.Types.STANDARD, tenant=cls.tenant, parent=cls.standard_workspace
        )
        cls.ungrouped_workspace = Workspace.objects.create(
            name="Ungrouped", type=Workspace.Types.UNGROUPED_HOSTS, tenant=cls.tenant, parent=cls.default_workspace
        )


class WorkspaceServiceCreateTests(WorkspaceServiceTestBase):
    """Tests for the create method"""

    def test_create_unique_per_parent(self):
        """Test the create method enforces name uniqueness per tenant"""
        validated_data = {"name": "Standard", "parent_id": self.default_workspace.id}
        with self.assertRaises(serializers.ValidationError) as context:
            self.service.create(validated_data, self.tenant)
        self.assertIn("Can't create workspace with same name within same parent workspace", str(context.exception))

    def test_create_validation_error(self):
        """Test the create method handles other validation errors"""
        with self.assertRaises(serializers.ValidationError) as context:
            self.service.create({}, self.tenant)
        self.assertIn("This field cannot be blank.", str(context.exception))

    def test_create_success_with_parent_id(self):
        """Test the create method successfully with a parent"""
        validated_data = {"name": "Unique Standard Child", "parent_id": self.default_workspace.id}
        workspace = self.service.create(validated_data, self.tenant)
        self.assertEqual(workspace.tenant, self.tenant)

    def test_create_success_without_parent_id(self):
        """Test the create method successfully without a parent"""
        validated_data = {"name": "Unique Standard Child"}
        workspace = self.service.create(validated_data, self.tenant)
        self.assertEqual(workspace.tenant, self.tenant)


class WorkspaceServiceUpdateTests(WorkspaceServiceTestBase):
    """Tests for the update method"""

    def test_update_success(self):
        """Test the update method succeeds"""
        validated_data = {"name": "Bar Name", "description": "Bar Desc"}
        updated_instance = self.service.update(self.standard_workspace, validated_data)
        self.assertEqual(updated_instance.name, validated_data["name"])
        self.assertEqual(updated_instance.description, validated_data["description"])

    def test_update_parent_id_same(self):
        """Test the update method when the parent is the same"""
        validated_data = {"parent_id": self.standard_workspace.parent_id}
        updated_instance = self.service.update(self.standard_workspace, validated_data)
        self.assertEqual(updated_instance.parent_id, self.standard_workspace.parent_id)

    def test_update_parent_id_different(self):
        """Test the update method when the parent is being changed"""
        validated_data = {"parent_id": self.default_workspace.parent_id}
        with self.assertRaises(serializers.ValidationError) as context:
            self.service.update(self.standard_workspace, validated_data)
        self.assertIn("Can't update the 'parent_id' on a workspace directly", str(context.exception))

    def test_update_root_workspace(self):
        """Test we cannot update the root workspace."""
        validated_data = {"name": "Bar Name", "description": "Bar Desc"}
        with self.assertRaises(serializers.ValidationError) as context:
            self.service.update(self.root_workspace, validated_data)
        self.assertIn("The root workspace cannot be updated.", str(context.exception))

    def test_update_default_workspace(self):
        """Test we can update the default workspace."""
        validated_data = {"name": "Default new name", "description": "Default new description"}
        updated_instance = self.service.update(self.default_workspace, validated_data)
        self.assertEqual(updated_instance.name, validated_data["name"])
        self.assertEqual(updated_instance.description, validated_data["description"])

    def test_update_ungrouped_workspace(self):
        """Test we cannot update the ungrouped workspace."""
        validated_data = {"name": "Bar Name", "description": "Bar Desc"}
        with self.assertRaises(serializers.ValidationError) as context:
            self.service.update(self.ungrouped_workspace, validated_data)
        self.assertIn("The ungrouped-hosts workspace cannot be updated.", str(context.exception))

    def test_update_name_unique_per_parent(self):
        """Test we cannot update the workspace name if the same name already exists under same parent."""
        wsA = Workspace.objects.create(
            name="Workspace A", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=self.default_workspace
        )
        wsB = Workspace.objects.create(
            name="Workspace B", type=Workspace.Types.STANDARD, tenant=self.tenant, parent=self.default_workspace
        )

        # Try to update the Workspace A with name="Workspace B"
        validated_data = {"name": wsB.name}
        with self.assertRaises(serializers.ValidationError) as context:
            self.service.update(wsA, validated_data)
        self.assertIn(
            f"A workspace with the name '{wsB.name}' already exists under same parent.", str(context.exception)
        )


class WorkspaceServiceDestroyTests(WorkspaceServiceTestBase):
    """Tests for the destroy method"""

    def test_destroy_non_standard(self):
        """Test the destroy method on non-standard workspaces"""
        for workspace in (self.default_workspace, self.root_workspace, self.ungrouped_workspace):
            with self.assertRaises(serializers.ValidationError) as context:
                self.service.destroy(workspace)
            self.assertIn(f"Unable to delete {workspace.type} workspace", str(context.exception))

    def test_destroy_when_parent(self):
        """Test the destroy method on parent workspaces"""
        with self.assertRaises(serializers.ValidationError) as context:
            self.service.destroy(self.standard_workspace)
        self.assertIn("Unable to delete due to workspace dependencies", str(context.exception))

    def test_destroy_success(self):
        """Test the destroy method successfully"""
        self.service.destroy(self.standard_child_workspace)
        self.assertFalse(Workspace.objects.filter(id=self.standard_child_workspace.id).exists())


class WorkspaceHierarchyTests(WorkspaceServiceTestBase):
    """Tests for hierarchy enforcement"""

    def test_enforce_hierarchy_depth_exceeded(self):
        """Test when hierarchy depth is exceeded"""
        with self.assertRaises(serializers.ValidationError) as context:
            self.service._enforce_hierarchy_depth(self.standard_workspace.id, self.tenant)
        self.assertIn(
            f"Workspaces may only nest {settings.WORKSPACE_HIERARCHY_DEPTH_LIMIT} levels deep.", str(context.exception)
        )

    def test_enforce_hierarchy_depth_is_within_range_but_peer_violation(self):
        """Test when hierarchy depth is within range but there are peer restrictions"""
        with self.assertRaises(serializers.ValidationError) as context:
            self.service._enforce_hierarchy_depth(self.root_workspace.id, self.tenant)
        self.assertIn("Sub-workspaces may only be created under the default workspace.", str(context.exception))

    def test_enforce_hierarchy_depth_is_within_range_and_no_peer_violation(self):
        """Test when hierarchy depth is within range and no peer restrictions"""
        self.assertEqual(self.service._enforce_hierarchy_depth(self.default_workspace.id, self.tenant), None)

    @override_settings(WORKSPACE_HIERARCHY_DEPTH_LIMIT=100, WORKSPACE_RESTRICT_DEFAULT_PEERS=False)
    def test_enforce_hierarchy_depth_is_within_range_and_peer_validation_is_off(self):
        """Test when hierarchy depth is within range and no peer restrictions"""
        self.assertEqual(self.service._enforce_hierarchy_depth(self.root_workspace.id, self.tenant), None)
