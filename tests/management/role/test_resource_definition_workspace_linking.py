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
# MERCHANTABILITY or FITNESS FOR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Test the resource definition workspace linker."""
import logging
import uuid
from unittest.mock import Mock, patch
from django.test import TestCase
from django.db import IntegrityError, transaction

from api.models import Tenant
from management.role.model import ResourceDefinition, ResourceDefinitionsWorkspaces, Access, Permission
from management.workspace.model import Workspace


class TestResourceDefinitionWorkspaceLinking(TestCase):
    """Test the resource definition workspace linking features."""

    def setUp(self):
        """Set up the test fixtures."""
        self.tenant = Tenant.objects.get(tenant_name="public")
        self.permission = Permission.objects.create(permission="test:resource:read", tenant=self.tenant)
        self.access = Access.objects.create(permission=self.permission, tenant=self.tenant)

    @patch("management.workspace.model.Workspace.objects.filter")
    @patch("management.role.model.ResourceDefinitionsWorkspaces.objects.filter")
    @patch("management.role.model.ResourceDefinitionsWorkspaces.objects.create")
    def test_link_resource_definition_workspaces_non_group_id_key(
        self,
        mock_resource_definitions_workspaces_create,
        mock_resource_definitions_workspaces_filter,
        mock_workspace_filter,
    ):
        """Test that when a resource definition does not have 'group.id' key, correct log is returned and no database calls are made."""
        logger = logging.getLogger("management.role.model")
        with self.assertLogs(logger=logger.name, level=logging.INFO) as log_context:
            # The "log_context" disables the "INFO" by resetting the logger's
            # configuration. We override that setting here so that we can
            # capture the log properly.
            logger._cache[logging.INFO] = True

            # Create a resource definition with a key other than "group.id".
            resource_definition = ResourceDefinition.objects.create(
                attributeFilter={"key": "some.other.key", "operation": "equal", "value": "some-value"},
                access=self.access,
                tenant=self.tenant,
            )

        # Verify that the logger was called with the right log message. The
        # first log output corresponds to the "dual writes", so we can skip
        # directly to the log we're interested in.
        expected_info_message = (
            f"[resource_definition_id: {resource_definition.id}][tenant_id: {resource_definition.tenant_id}] "
            f"Linking resource definition to workspaces skipped because the resource definition's key "
            f'"some.other.key" does not have the expected "group.id" value'
        )
        self.assertIn(expected_info_message, log_context.output[1])

        # Verify that no database calls were made for fetching workspaces.
        mock_workspace_filter.assert_not_called()

        # Verify that no database calls were made to removing "ResourceDefinitionsWorkspaces" objects.
        mock_resource_definitions_workspaces_filter.assert_not_called()

        # Verify that no database calls were made for creating ResourceDefinitionsWorkspaces objects.
        mock_resource_definitions_workspaces_create.assert_not_called()

    @patch("management.workspace.model.Workspace.objects.filter")
    @patch("management.role.model.ResourceDefinitionsWorkspaces.objects.filter")
    @patch("management.role.model.ResourceDefinitionsWorkspaces.objects.create")
    def test_link_resource_definition_workspaces_unrecognized_operation(
        self,
        mock_resource_definitions_workspaces_create,
        mock_resource_definitions_workspaces_filter,
        mock_workspace_filter,
    ):
        """Test that when a resource definition has 'group.id' key but unrecognized operation, warning log is issued and no database calls are made."""
        logger = logging.getLogger("management.role.model")
        with self.assertLogs(logger=logger.name, level=logging.WARNING) as log_context:
            # The "log_context" disables the "WARNING" by resetting the
            # logger's configuration. We override that setting here so that we
            # can capture the log properly.
            logger._cache[logging.WARNING] = True

            # Create a resource definition with "group.id" key but unrecognized operation
            resource_definition = ResourceDefinition.objects.create(
                attributeFilter={"key": "group.id", "operation": "unrecognized_operation", "value": "some-value"},
                access=self.access,
                tenant=self.tenant,
            )

        # Verify that the logger was called with the right log message.
        expected_warning_message = f'[resource_definition_id: "{resource_definition.id}"] Unable to create relation between the resource definition and the workspace because the operation "unrecognized_operation" is unrecognized'
        self.assertIn(expected_warning_message, log_context.output[0])

        # Verify that no database calls were made for fetching workspaces.
        mock_workspace_filter.assert_not_called()

        # Verify that no database calls were made to removing "ResourceDefinitionsWorkspaces" objects.
        mock_resource_definitions_workspaces_filter.assert_not_called()

        # Verify that no database calls were made for creating ResourceDefinitionsWorkspaces objects.
        mock_resource_definitions_workspaces_create.assert_not_called()

    @patch("management.workspace.model.Workspace.objects.filter")
    @patch("management.role.model.ResourceDefinitionsWorkspaces.objects.filter")
    @patch("management.role.model.ResourceDefinitionsWorkspaces.objects.create")
    def test_link_resource_definition_workspaces_invalid_uuids_in_array(
        self,
        mock_resource_definitions_workspaces_create,
        mock_resource_definitions_workspaces_filter,
        mock_workspace_filter,
    ):
        """Test that when a resource definition has 'group.id' key and 'in' operation but invalid UUIDs, error log is issued and no ResourceDefinitionsWorkspaces objects are created."""
        logger = logging.getLogger("management.role.model")
        with self.assertLogs(logger=logger.name, level=logging.ERROR) as log_context:
            # The "log_context" disables the "ERROR" by resetting the
            # logger's configuration. We override that setting here so that we
            # can capture the log properly.
            logger._cache[logging.ERROR] = True

            # Create a resource definition with "group.id" key, "in" operation, but invalid UUID strings.
            resource_definition = ResourceDefinition.objects.create(
                attributeFilter={
                    "key": "group.id",
                    "operation": "in",
                    "value": ["invalid-uuid-string", "another-invalid-uuid"],
                },
                access=self.access,
                tenant=self.tenant,
            )

        # Verify that error log messages were called for each invalid UUID.
        expected_error_message_1 = f'[resource_definition_id: "{resource_definition.id}"] Unable to parse workspace ID "invalid-uuid-string" as a valid UUID: '
        expected_error_message_2 = f'[resource_definition_id: "{resource_definition.id}"] Unable to parse workspace ID "another-invalid-uuid" as a valid UUID: '

        # Check that error was called twice —once for each invalid UUID—.
        self.assertEqual(len(log_context.output), 2)

        # Check that the error calls contain the expected messages.
        self.assertTrue(any(expected_error_message_1 in log_message for log_message in log_context.output))
        self.assertTrue(any(expected_error_message_2 in log_message for log_message in log_context.output))

        # Verify that database call was made with an empty set —since all UUIDs were invalid—.
        mock_workspace_filter.assert_called_once_with(id__in=set())

        # Verify that ResourceDefinitionsWorkspaces.objects.filter was called once.
        mock_resource_definitions_workspaces_filter.assert_called_once_with(resource_definition=resource_definition)

        # Verify that no database calls were made for creating "ResourceDefinitionsWorkspaces" objects.
        mock_resource_definitions_workspaces_create.assert_not_called()

    def test_link_resource_definition_workspaces_invalid_uuids_removes_existing_links(self):
        """Test resource definition workspace linking. When an invalid "UUID" is specified for the resource definition, it verifies that the existing links are removed."""
        # Create three workspaces in a hierarchy with proper types.
        root_workspace = Workspace.objects.create(name="Root Workspace", tenant=self.tenant, type=Workspace.Types.ROOT)
        default_workspace = Workspace.objects.create(
            name="Default Workspace", tenant=self.tenant, parent=root_workspace, type=Workspace.Types.DEFAULT
        )
        child_workspace = Workspace.objects.create(
            name="Child Workspace", tenant=self.tenant, parent=default_workspace, type=Workspace.Types.STANDARD
        )

        # Verify that workspaces are not linked to any resource definitions initially.
        self.assertEqual(ResourceDefinitionsWorkspaces.objects.count(), 0)

        # Create a resource definition with the three workspaces' IDs.
        resource_definition = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [str(root_workspace.id), str(default_workspace.id), str(child_workspace.id)],
            },
            access=self.access,
            tenant=self.tenant,
        )

        # Verify that the resource definition is now linked to the three workspaces.
        linked_workspaces = ResourceDefinitionsWorkspaces.objects.filter(resource_definition=resource_definition)
        self.assertEqual(linked_workspaces.count(), 3)

        linked_workspace_ids = set(linked_workspaces.values_list("workspace_id", flat=True))
        expected_workspace_ids = {root_workspace.id, default_workspace.id, child_workspace.id}
        self.assertEqual(linked_workspace_ids, expected_workspace_ids)

        # Update the resource definition with an invalid UUID string.
        logger = logging.getLogger("management.role.model")
        with self.assertLogs(logger=logger.name, level=logging.INFO) as log_context:
            # The "log_context" disables the "INFO" by resetting the logger's configuration.
            # We override that setting here so that we can capture the log properly.
            logger._cache[logging.INFO] = True

            resource_definition.attributeFilter["value"] = ["invalid-uuid-string"]
            resource_definition.save()

        # Verify that info logs are written for each removed workspace link.
        # The first log output corresponds to the "dual writes", so we can skip it.
        # The next three logs should be the "Link removed" messages for each workspace.
        self.assertGreaterEqual(len(log_context.output), 4)  # At least 4 logs: dual writes + 3 removed links.

        # Check that the "Link removed" info logs are written for each workspace.
        expected_removed_logs = [
            f'[resource_definition_id: "{resource_definition.id}"][tenant_id: "{resource_definition.tenant_id}"][workspace_id: "{root_workspace.id}"] Link removed',
            f'[resource_definition_id: "{resource_definition.id}"][tenant_id: "{resource_definition.tenant_id}"][workspace_id: "{default_workspace.id}"] Link removed',
            f'[resource_definition_id: "{resource_definition.id}"][tenant_id: "{resource_definition.tenant_id}"][workspace_id: "{child_workspace.id}"] Link removed',
        ]

        for expected_log in expected_removed_logs:
            self.assertTrue(
                any(expected_log in log_message for log_message in log_context.output),
                f"Expected log message not found: {expected_log}",
            )

        # Verify that the links have been deleted from the database.
        remaining_links = ResourceDefinitionsWorkspaces.objects.filter(resource_definition=resource_definition)
        self.assertEqual(remaining_links.count(), 0)

        # Verify that no new links have been created —since all UUIDs were invalid—.
        total_links = ResourceDefinitionsWorkspaces.objects.count()
        self.assertEqual(total_links, 0)

    def test_link_resource_definition_workspaces_dynamic_linking_unlinking(self):
        """Test resource definition workspace linking with dynamic updates. When updating a resource definition with different workspace IDs, it verifies that old links are removed and new ones are created."""
        # Create three workspaces in a hierarchy with proper types.
        root_workspace = Workspace.objects.create(name="Root Workspace", tenant=self.tenant, type=Workspace.Types.ROOT)
        default_workspace = Workspace.objects.create(
            name="Default Workspace", tenant=self.tenant, parent=root_workspace, type=Workspace.Types.DEFAULT
        )
        child_workspace = Workspace.objects.create(
            name="Child Workspace", tenant=self.tenant, parent=default_workspace, type=Workspace.Types.STANDARD
        )

        # Verify that workspaces are not linked to any resource definitions initially.
        self.assertEqual(ResourceDefinitionsWorkspaces.objects.count(), 0)

        # Create a resource definition with the three workspaces' IDs.
        resource_definition = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [str(root_workspace.id), str(default_workspace.id), str(child_workspace.id)],
            },
            access=self.access,
            tenant=self.tenant,
        )

        # Verify that the resource definition is now linked to the three workspaces.
        linked_workspaces = ResourceDefinitionsWorkspaces.objects.filter(resource_definition=resource_definition)
        self.assertEqual(linked_workspaces.count(), 3)

        linked_workspace_ids = set(linked_workspaces.values_list("workspace_id", flat=True))
        expected_workspace_ids = {root_workspace.id, default_workspace.id, child_workspace.id}
        self.assertEqual(linked_workspace_ids, expected_workspace_ids)

        # Create one more workspace.
        new_workspace = Workspace.objects.create(
            name="New Workspace", tenant=self.tenant, parent=default_workspace, type=Workspace.Types.STANDARD
        )

        # Update the resource definition with one of the previously created workspaces and the fresh workspace.
        logger = logging.getLogger("management.role.model")
        with self.assertLogs(logger=logger.name, level=logging.INFO) as log_context:
            # The "log_context" disables the "INFO" by resetting the logger's configuration.
            # We override that setting here so that we can capture the log properly.
            logger._cache[logging.INFO] = True

            resource_definition.attributeFilter["value"] = [str(default_workspace.id), str(new_workspace.id)]
            resource_definition.save()

        # Verify that "Link removed" log messages are written for the unlinked workspaces.
        # The first log output corresponds to the "dual writes", so we can skip it.
        # The next two logs should be the "Link removed" messages for root and child workspaces.
        self.assertGreaterEqual(
            len(log_context.output), 4
        )  # At least 4 logs: dual writes + 2 removed links + 1 new link.

        expected_removed_logs = [
            f'[resource_definition_id: "{resource_definition.id}"][tenant_id: "{resource_definition.tenant_id}"][workspace_id: "{root_workspace.id}"] Link removed',
            f'[resource_definition_id: "{resource_definition.id}"][tenant_id: "{resource_definition.tenant_id}"][workspace_id: "{child_workspace.id}"] Link removed',
        ]

        for expected_log in expected_removed_logs:
            self.assertTrue(
                any(expected_log in log_message for log_message in log_context.output),
                f"Expected removed log message not found: {expected_log}",
            )

        # Verify that the "Linked resource definition and workspace" log is issued for the fresh workspace.
        expected_linked_log = f'[resource_definition_id: "{resource_definition.id}"][tenant_id: "{resource_definition.tenant_id}"][workspace_id: {new_workspace.id}] Linked resource definition and workspace'
        self.assertTrue(
            any(expected_linked_log in log_message for log_message in log_context.output),
            f"Expected linked log message not found: {expected_linked_log}",
        )

        # Verify that the two links to this resource definition are present in the database.
        updated_linked_workspaces = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=resource_definition
        )
        self.assertEqual(updated_linked_workspaces.count(), 2)

        updated_linked_workspace_ids = set(updated_linked_workspaces.values_list("workspace_id", flat=True))
        expected_updated_workspace_ids = {default_workspace.id, new_workspace.id}
        self.assertEqual(updated_linked_workspace_ids, expected_updated_workspace_ids)

        # Verify that the previous links have been removed from the database.
        # Check that root and child workspace links no longer exist.
        root_link = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=resource_definition, workspace=root_workspace
        )
        self.assertEqual(root_link.count(), 0)

        child_link = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=resource_definition, workspace=child_workspace
        )
        self.assertEqual(child_link.count(), 0)

        # Verify that default and new workspace links still exist.
        default_link = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=resource_definition, workspace=default_workspace
        )
        self.assertEqual(default_link.count(), 1)

        new_link = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=resource_definition, workspace=new_workspace
        )
        self.assertEqual(new_link.count(), 1)

    def test_link_resource_definition_workspaces_non_existing_workspace_ids(self):
        """Test resource definition workspace linking with non-existing workspace IDs. When a resource definition specifies workspace IDs that don't exist, it verifies that only warning logs are issued."""
        # Generate some non-existing workspace IDs —valid UUID format but not in database—.
        non_existing_workspace_id_1 = str(uuid.uuid4())
        non_existing_workspace_id_2 = str(uuid.uuid4())

        # Create a resource definition with the three workspaces' IDs.
        resource_definition = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [non_existing_workspace_id_1, non_existing_workspace_id_2],
            },
            access=self.access,
            tenant=self.tenant,
        )

        # Save the resource definition in the database.
        logger = logging.getLogger("management.role.model")
        with self.assertLogs(logger=logger.name, level=logging.WARNING) as log_context:
            # The "log_context" disables the "WARNING" by resetting the logger's configuration.
            # We override that setting here so that we can capture the log properly.
            logger._cache[logging.WARNING] = True

            resource_definition.save()

        # Verify that only warning logs are issued for non-existing workspace IDs.
        self.assertEqual(len(log_context.output), 2)  # Exactly 2 warning logs for the 2 non-existing workspace IDs.

        expected_warning_logs = [
            f'[resource_definition_id: "{resource_definition.id}"][tenant_id: "{resource_definition.tenant_id}"][workspace_id: "{non_existing_workspace_id_1}"] RBAC does not have a workspace record for the parsed workspace ID from the resource definition',
            f'[resource_definition_id: "{resource_definition.id}"][tenant_id: "{resource_definition.tenant_id}"][workspace_id: "{non_existing_workspace_id_2}"] RBAC does not have a workspace record for the parsed workspace ID from the resource definition',
        ]

        for expected_log in expected_warning_logs:
            self.assertTrue(
                any(expected_log in log_message for log_message in log_context.output),
                f"Expected warning log message not found: {expected_log}",
            )

        # Verify that no new links have been created —since all workspace IDs were non-existing—.
        total_links = ResourceDefinitionsWorkspaces.objects.count()
        self.assertEqual(total_links, 0)

    def test_link_multiple_resource_definitions_to_different_workspaces(self):
        """Test multiple resource definitions being linked to different sets of workspaces independently."""
        # Create four workspaces in a hierarchy with proper types.
        root_workspace = Workspace.objects.create(name="Root Workspace", tenant=self.tenant, type=Workspace.Types.ROOT)
        default_workspace = Workspace.objects.create(
            name="Default Workspace", tenant=self.tenant, parent=root_workspace, type=Workspace.Types.DEFAULT
        )
        workspace_1 = Workspace.objects.create(
            name="Workspace 1", tenant=self.tenant, parent=default_workspace, type=Workspace.Types.STANDARD
        )
        workspace_2 = Workspace.objects.create(
            name="Workspace 2", tenant=self.tenant, parent=default_workspace, type=Workspace.Types.STANDARD
        )

        # Verify that workspaces are not linked to any resource definitions initially.
        self.assertEqual(ResourceDefinitionsWorkspaces.objects.count(), 0)

        # Create a resource definition and link it to the first two workspaces.
        resource_definition_1 = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [str(root_workspace.id), str(default_workspace.id)],
            },
            access=self.access,
            tenant=self.tenant,
        )

        # Create another resource definition and link it to the last two workspaces.
        resource_definition_2 = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [str(workspace_1.id), str(workspace_2.id)],
            },
            access=self.access,
            tenant=self.tenant,
        )

        # Check that the links were created for the corresponding resource definitions.
        # Verify resource definition 1 links.
        linked_workspaces_1 = ResourceDefinitionsWorkspaces.objects.filter(resource_definition=resource_definition_1)
        self.assertEqual(linked_workspaces_1.count(), 2)

        linked_workspace_ids_1 = set(linked_workspaces_1.values_list("workspace_id", flat=True))
        expected_workspace_ids_1 = {root_workspace.id, default_workspace.id}
        self.assertEqual(linked_workspace_ids_1, expected_workspace_ids_1)

        # Verify resource definition 2 links.
        linked_workspaces_2 = ResourceDefinitionsWorkspaces.objects.filter(resource_definition=resource_definition_2)
        self.assertEqual(linked_workspaces_2.count(), 2)

        linked_workspace_ids_2 = set(linked_workspaces_2.values_list("workspace_id", flat=True))
        expected_workspace_ids_2 = {workspace_1.id, workspace_2.id}
        self.assertEqual(linked_workspace_ids_2, expected_workspace_ids_2)

        # Verify total number of links in the database.
        total_links = ResourceDefinitionsWorkspaces.objects.count()
        self.assertEqual(total_links, 4)  # 2 links for each resource definition.

        # Verify that each workspace is linked to the correct resource definition.
        root_links = ResourceDefinitionsWorkspaces.objects.filter(workspace=root_workspace)
        self.assertEqual(root_links.count(), 1)
        self.assertEqual(root_links.first().resource_definition, resource_definition_1)

        default_links = ResourceDefinitionsWorkspaces.objects.filter(workspace=default_workspace)
        self.assertEqual(default_links.count(), 1)
        self.assertEqual(default_links.first().resource_definition, resource_definition_1)

        workspace_1_links = ResourceDefinitionsWorkspaces.objects.filter(workspace=workspace_1)
        self.assertEqual(workspace_1_links.count(), 1)
        self.assertEqual(workspace_1_links.first().resource_definition, resource_definition_2)

        workspace_2_links = ResourceDefinitionsWorkspaces.objects.filter(workspace=workspace_2)
        self.assertEqual(workspace_2_links.count(), 1)
        self.assertEqual(workspace_2_links.first().resource_definition, resource_definition_2)

    def test_delete_resource_definition_preserves_other_links(self):
        """Test that deleting one resource definition preserves the links of other resource definitions."""
        # Create four workspaces in a hierarchy with proper types.
        root_workspace = Workspace.objects.create(name="Root Workspace", tenant=self.tenant, type=Workspace.Types.ROOT)
        default_workspace = Workspace.objects.create(
            name="Default Workspace", tenant=self.tenant, parent=root_workspace, type=Workspace.Types.DEFAULT
        )
        workspace_1 = Workspace.objects.create(
            name="Workspace 1", tenant=self.tenant, parent=default_workspace, type=Workspace.Types.STANDARD
        )
        workspace_2 = Workspace.objects.create(
            name="Workspace 2", tenant=self.tenant, parent=default_workspace, type=Workspace.Types.STANDARD
        )

        # Verify that workspaces are not linked to any resource definitions initially.
        self.assertEqual(ResourceDefinitionsWorkspaces.objects.count(), 0)

        # Create a resource definition and link it to the first two workspaces.
        resource_definition_1 = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [str(root_workspace.id), str(default_workspace.id)],
            },
            access=self.access,
            tenant=self.tenant,
        )

        # Create another resource definition and link it to the last two workspaces.
        resource_definition_2 = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [str(workspace_1.id), str(workspace_2.id)],
            },
            access=self.access,
            tenant=self.tenant,
        )

        # Verify that both resource definitions are properly linked.
        linked_workspaces_1 = ResourceDefinitionsWorkspaces.objects.filter(resource_definition=resource_definition_1)
        self.assertEqual(linked_workspaces_1.count(), 2)

        linked_workspaces_2 = ResourceDefinitionsWorkspaces.objects.filter(resource_definition=resource_definition_2)
        self.assertEqual(linked_workspaces_2.count(), 2)

        total_links_before_deletion = ResourceDefinitionsWorkspaces.objects.count()
        self.assertEqual(total_links_before_deletion, 4)

        # Remove one of the resource definitions.
        resource_definition_1.delete()

        # Verify that the links between the other resource definition and its workspaces are left intact.
        # Check that resource definition 2 still has its links.
        remaining_linked_workspaces = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=resource_definition_2
        )
        self.assertEqual(remaining_linked_workspaces.count(), 2)

        remaining_workspace_ids = set(remaining_linked_workspaces.values_list("workspace_id", flat=True))
        expected_remaining_workspace_ids = {workspace_1.id, workspace_2.id}
        self.assertEqual(remaining_workspace_ids, expected_remaining_workspace_ids)

        # Verify that the total number of links is now 2 (only resource definition 2 links remain).
        total_links_after_deletion = ResourceDefinitionsWorkspaces.objects.count()
        self.assertEqual(total_links_after_deletion, 2)

        # Verify that workspace_1 and workspace_2 are still linked to resource_definition_2.
        workspace_1_links = ResourceDefinitionsWorkspaces.objects.filter(workspace=workspace_1)
        self.assertEqual(workspace_1_links.count(), 1)
        self.assertEqual(workspace_1_links.first().resource_definition, resource_definition_2)

        workspace_2_links = ResourceDefinitionsWorkspaces.objects.filter(workspace=workspace_2)
        self.assertEqual(workspace_2_links.count(), 1)
        self.assertEqual(workspace_2_links.first().resource_definition, resource_definition_2)

        # Verify that no links remain for the deleted resource definition.
        deleted_resource_definition_links = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition_id=resource_definition_1.id
        )
        self.assertEqual(deleted_resource_definition_links.count(), 0)

        # Verify that root and default workspaces are no longer linked to any resource definition.
        root_links = ResourceDefinitionsWorkspaces.objects.filter(workspace=root_workspace)
        self.assertEqual(root_links.count(), 0)

        default_links = ResourceDefinitionsWorkspaces.objects.filter(workspace=default_workspace)
        self.assertEqual(default_links.count(), 0)

    def test_cascade_delete_works_for_both_resource_definitions_and_workspaces(self):
        """Test that cascade delete works correctly for both resource definitions and workspaces in the join table."""
        # Create a workspace with proper hierarchy and type.
        root_workspace = Workspace.objects.create(name="Root Workspace", tenant=self.tenant, type=Workspace.Types.ROOT)
        default_workspace = Workspace.objects.create(
            name="Default Workspace", tenant=self.tenant, parent=root_workspace, type=Workspace.Types.DEFAULT
        )
        test_workspace = Workspace.objects.create(
            name="Test Workspace", tenant=self.tenant, parent=default_workspace, type=Workspace.Types.STANDARD
        )

        # Verify that no links exist initially.
        self.assertEqual(ResourceDefinitionsWorkspaces.objects.count(), 0)

        # Create a link between a resource definition and a workspace.
        resource_definition = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [str(test_workspace.id)],
            },
            access=self.access,
            tenant=self.tenant,
        )

        # Verify that the link is there.
        link = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=resource_definition, workspace=test_workspace
        )
        self.assertEqual(link.count(), 1)
        self.assertEqual(ResourceDefinitionsWorkspaces.objects.count(), 1)

        # Delete the resource definition.
        resource_definition.delete()

        # Verify that the join table does not have the link anymore.
        remaining_links = ResourceDefinitionsWorkspaces.objects.filter(resource_definition_id=resource_definition.id)
        self.assertEqual(remaining_links.count(), 0)
        self.assertEqual(ResourceDefinitionsWorkspaces.objects.count(), 0)

        # Recreate the resource definition and link it to the same workspace.
        new_resource_definition = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [str(test_workspace.id)],
            },
            access=self.access,
            tenant=self.tenant,
        )

        # Verify again that the link is there.
        new_link = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=new_resource_definition, workspace=test_workspace
        )
        self.assertEqual(new_link.count(), 1)
        self.assertEqual(ResourceDefinitionsWorkspaces.objects.count(), 1)

        # Delete the workspace this time.
        test_workspace.delete()

        # Verify that the link is gone again.
        final_links = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=new_resource_definition, workspace_id=test_workspace.id
        )
        self.assertEqual(final_links.count(), 0)
        self.assertEqual(ResourceDefinitionsWorkspaces.objects.count(), 0)

        # Verify that the resource definition still exists but has no links.
        resource_definition_still_exists = ResourceDefinition.objects.filter(id=new_resource_definition.id)
        self.assertEqual(resource_definition_still_exists.count(), 1)

    def test_resource_definitions_workspaces_unique_constraint_violation(self):
        """Test that attempting to create duplicate ResourceDefinitionsWorkspaces entries violates the unique constraint."""
        # Create a workspace with proper hierarchy and type.
        root_workspace = Workspace.objects.create(name="Root Workspace", tenant=self.tenant, type=Workspace.Types.ROOT)
        default_workspace = Workspace.objects.create(
            name="Default Workspace", tenant=self.tenant, parent=root_workspace, type=Workspace.Types.DEFAULT
        )
        test_workspace = Workspace.objects.create(
            name="Test Workspace", tenant=self.tenant, parent=default_workspace, type=Workspace.Types.STANDARD
        )

        # Create a resource definition.
        resource_definition = ResourceDefinition.objects.create(
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [str(test_workspace.id)],
            },
            access=self.access,
            tenant=self.tenant,
        )

        # Verify that the initial link was created successfully.
        initial_links = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=resource_definition, workspace=test_workspace
        )
        self.assertEqual(initial_links.count(), 1)

        # Attempt to create a duplicate ResourceDefinitionsWorkspaces entry
        # with the same resource_definition, workspace, and tenant. Use a
        # separate transaction to isolate the constraint violation.
        constraint_violated = False
        try:
            with transaction.atomic():
                ResourceDefinitionsWorkspaces.objects.create(
                    resource_definition=resource_definition,
                    workspace=test_workspace,
                    tenant=self.tenant,
                )
        except IntegrityError as e:
            # Verify that the unique constraint violation occurred.
            self.assertIn(
                "unique resource definition and workspace link per tenant",
                str(e).lower(),
                f"Expected unique constraint violation, but got: {e}",
            )
            constraint_violated = True

        # Ensure that the constraint violation actually occurred.
        self.assertTrue(constraint_violated, "Expected IntegrityError to be raised")

        # Verify that only one link still exists (no duplicate was created).
        final_links = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=resource_definition, workspace=test_workspace
        )
        self.assertEqual(final_links.count(), 1)

        # Verify that the total number of ResourceDefinitionsWorkspaces entries is still 1.
        total_links = ResourceDefinitionsWorkspaces.objects.count()
        self.assertEqual(total_links, 1)
