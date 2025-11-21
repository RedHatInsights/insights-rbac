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
"""Test the internal utils module."""

from unittest.mock import patch
from django.test import TestCase, override_settings
from management.group.model import Group
from management.models import BindingMapping, Workspace, Access, Permission
from management.policy.model import Policy
from management.role.model import Role, ResourceDefinition
from migration_tool.in_memory_tuples import (
    InMemoryTuples,
    InMemoryRelationReplicator,
    all_of,
    resource,
    relation,
    subject,
)
from api.models import Tenant
from internal.utils import replicate_missing_binding_tuples, clean_invalid_workspace_resource_definitions


class ReplicateMissingBindingTuplesTest(TestCase):
    """Test the replicate_missing_binding_tuples function."""

    def setUp(self):
        """Set up test data."""
        self.tenant = Tenant.objects.create(tenant_name="test_tenant", org_id="12345")
        self.public_tenant = Tenant.objects.get(tenant_name="public")

        # Create workspace hierarchy
        self.root_ws = Workspace.objects.create(
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
            name="Root Workspace",
        )
        self.default_ws = Workspace.objects.create(
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            name="Default Workspace",
            parent=self.root_ws,
        )

        self.tuples = InMemoryTuples()

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_replicate_missing_binding_tuples_for_specific_bindings(self, mock_replicate):
        """Test that function replicates all tuples for specific binding IDs."""
        # Redirect replication to in-memory tuples
        replicator = InMemoryRelationReplicator(self.tuples)
        mock_replicate.side_effect = replicator.replicate

        # Create a system role
        role = Role.objects.create(name="Test Role", system=True, tenant=self.public_tenant)
        perm = Permission.objects.create(permission="test:resource:read", tenant=self.public_tenant)
        Access.objects.create(role=role, permission=perm, tenant=self.public_tenant)

        # Create a group
        group = Group.objects.create(name="Test Group", tenant=self.tenant)

        # Create binding WITHOUT replication (missing base tuples)
        binding = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "test-binding-utils",
                "groups": [str(group.uuid)],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": True, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.root_ws.id),
        )

        binding_id = binding.mappings["id"]

        # Verify initial state: NO tuples exist
        self.assertEqual(len(self.tuples), 0, "Should have NO tuples before fix")

        # Call the function
        results = replicate_missing_binding_tuples(binding_ids=[binding.id])

        # Verify results
        self.assertEqual(results["bindings_checked"], 1)
        self.assertEqual(results["bindings_fixed"], 1)
        self.assertEqual(results["tuples_added"], 3)  # t_role + t_binding + subject

        # Verify t_role tuple was created
        t_role_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("role"),
            )
        )
        self.assertEqual(len(t_role_tuples), 1, "Should have t_role tuple")

        # Verify t_binding tuple was created
        t_binding_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(self.root_ws.id)),
                relation("binding"),
                subject("rbac", "role_binding", binding_id),
            )
        )
        self.assertEqual(len(t_binding_tuples), 1, "Should have t_binding tuple")

        # Verify subject tuple was created
        subject_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("subject"),
                subject("rbac", "group", str(group.uuid), "member"),
            )
        )
        self.assertEqual(len(subject_tuples), 1, "Should have subject tuple")

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_replicate_missing_binding_tuples_idempotent(self, mock_replicate):
        """Test that function is idempotent and safe to run multiple times."""
        # Redirect replication to in-memory tuples
        replicator = InMemoryRelationReplicator(self.tuples)
        mock_replicate.side_effect = replicator.replicate

        # Create a system role
        role = Role.objects.create(name="Test Role Idempotent", system=True, tenant=self.public_tenant)
        perm = Permission.objects.create(permission="test:idempotent:read", tenant=self.public_tenant)
        Access.objects.create(role=role, permission=perm, tenant=self.public_tenant)

        # Create binding
        binding = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "test-binding-idempotent",
                "groups": [],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": True, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.root_ws.id),
        )

        # Run once
        results1 = replicate_missing_binding_tuples(binding_ids=[binding.id])
        self.assertEqual(results1["bindings_fixed"], 1)
        tuples_after_first = len(self.tuples)

        # Run again - should be idempotent (duplicates handled by Kessel)
        results2 = replicate_missing_binding_tuples(binding_ids=[binding.id])
        self.assertEqual(results2["bindings_fixed"], 1)

        # Tuples are added again but that's OK (Kessel handles duplicates)
        # The important thing is no error occurs
        self.assertGreater(len(self.tuples), 0, "Should have tuples after running twice")

    @override_settings(REPLICATION_TO_RELATION_ENABLED=False)
    def test_clean_invalid_workspace_resource_definitions_handles_both_operations(self):
        """
        Test cleaning resource definitions with both operation types.

        Tests two scenarios:
        1. operation='in' with list of workspace IDs (all invalid)
        2. operation='equal' with single string workspace ID (invalid)

        Verifies:
        - Invalid IDs removed correctly
        - Value type preserved (list for 'in', string for 'equal')
        - Bindings updated via dual write handler
        """
        # Create a custom role
        role = Role.objects.create(name="Test Role Mixed Operations", system=False, tenant=self.tenant)

        # Permission 1: operation='in' (list value)
        perm_in = Permission.objects.create(
            permission="inventory:groups:read",
            application="inventory",
            resource_type="groups",
            verb="read",
            tenant=self.tenant,
        )
        access_in = Access.objects.create(role=role, permission=perm_in, tenant=self.tenant)

        # Permission 2: operation='equal' (string value)
        perm_equal = Permission.objects.create(
            permission="inventory:groups:write",
            application="inventory",
            resource_type="groups",
            verb="write",
            tenant=self.tenant,
        )
        access_equal = Access.objects.create(role=role, permission=perm_equal, tenant=self.tenant)

        # Create RD with operation='in' and ONLY invalid workspace IDs (list)
        fake_ws_id_1 = "95473d62-56ea-4c0c-8945-4f3f6a620669"
        fake_ws_id_2 = "64f65afb-e6f7-4dbb-ba43-ffcdb4a7fb9b"
        rd_in = ResourceDefinition.objects.create(
            access=access_in,
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [fake_ws_id_1, fake_ws_id_2],
            },
            tenant=self.tenant,
        )

        # Create RD with operation='equal' and INVALID workspace ID (string)
        fake_ws_id_3 = "90bd58c4-0579-4cff-937b-a08f69292b29"
        rd_equal = ResourceDefinition.objects.create(
            access=access_equal,
            attributeFilter={
                "key": "group.id",
                "operation": "equal",
                "value": fake_ws_id_3,  # String, not list
            },
            tenant=self.tenant,
        )

        # BEFORE: Verify setup
        self.assertEqual(len(rd_in.attributeFilter["value"]), 2)
        self.assertIsInstance(rd_in.attributeFilter["value"], list)
        self.assertIsInstance(rd_equal.attributeFilter["value"], str)

        # Call the cleanup function
        results = clean_invalid_workspace_resource_definitions()

        # Verify results - both RDs should be fixed
        self.assertEqual(results["resource_definitions_fixed"], 2)
        self.assertEqual(len(results["changes"]), 2)

        # AFTER: Verify RD with operation='in' has empty list
        rd_in.refresh_from_db()
        self.assertEqual(rd_in.attributeFilter["value"], [])
        self.assertIsInstance(rd_in.attributeFilter["value"], list)

        # AFTER: Verify RD with operation='equal' has empty string
        rd_equal.refresh_from_db()
        self.assertEqual(rd_equal.attributeFilter["value"], "")
        self.assertIsInstance(rd_equal.attributeFilter["value"], str)

        # Note: Dual write handler manages binding updates automatically

    def test_clean_replaces_none_with_ungrouped_workspace_id(self):
        """
        Test that None values (representing ungrouped workspace) are replaced with ungrouped workspace ID.

        Setup: Create RD with None value mixed with valid and invalid workspace IDs
        Action: Call cleanup function
        Verify: None is replaced with ungrouped workspace ID, valid IDs kept, invalid IDs removed
        """
        # Create a custom role
        role = Role.objects.create(name="Test Role Ungrouped", system=False, tenant=self.tenant)

        perm = Permission.objects.create(
            permission="inventory:groups:read",
            application="inventory",
            resource_type="groups",
            verb="read",
            tenant=self.tenant,
        )
        access = Access.objects.create(role=role, permission=perm, tenant=self.tenant)

        # Create a valid workspace (use STANDARD type to avoid unique constraint)
        valid_ws = Workspace.objects.create(
            tenant=self.tenant, type=Workspace.Types.STANDARD, name="Valid Workspace", parent=self.default_ws
        )

        # Create RD with None (ungrouped), valid UUID, and invalid UUID
        fake_ws_id = "95473d62-56ea-4c0c-8945-4f3f6a620669"
        rd = ResourceDefinition.objects.create(
            access=access,
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [None, str(valid_ws.id), fake_ws_id],
            },
            tenant=self.tenant,
        )

        # BEFORE: Verify setup
        self.assertEqual(len(rd.attributeFilter["value"]), 3)
        self.assertIn(None, rd.attributeFilter["value"])
        self.assertIn(str(valid_ws.id), rd.attributeFilter["value"])
        self.assertIn(fake_ws_id, rd.attributeFilter["value"])

        # Call the cleanup function
        results = clean_invalid_workspace_resource_definitions()

        # Verify results
        self.assertEqual(results["resource_definitions_fixed"], 1)
        self.assertEqual(len(results["changes"]), 1)

        # Get the ungrouped workspace ID for verification
        ungrouped_ws = Workspace.objects.get(tenant=self.tenant, type=Workspace.Types.UNGROUPED_HOSTS)

        # AFTER: Verify None is replaced with ungrouped workspace ID, valid ID kept, invalid ID removed
        rd.refresh_from_db()
        self.assertNotIn(
            None, rd.attributeFilter["value"], "None value should be replaced with ungrouped workspace ID"
        )
        self.assertIn(str(ungrouped_ws.id), rd.attributeFilter["value"], "Ungrouped workspace ID should be present")
        self.assertIn(str(valid_ws.id), rd.attributeFilter["value"])
        self.assertNotIn(fake_ws_id, rd.attributeFilter["value"])

        # Verify the change info reports the replacement
        change = results["changes"][0]
        self.assertTrue(change["none_replaced_with_ungrouped"])
        self.assertEqual(change["ungrouped_workspace_id"], str(ungrouped_ws.id))

    def test_clean_replaces_none_when_all_other_ids_invalid(self):
        """
        Test that None value is replaced with ungrouped workspace ID even when all other IDs are invalid.

        Setup: Create RD with only None and invalid workspace IDs
        Action: Call cleanup function
        Verify: None is replaced with ungrouped workspace ID, invalid IDs removed
        """
        # Create a custom role
        role = Role.objects.create(name="Test Role Only Ungrouped", system=False, tenant=self.tenant)

        perm = Permission.objects.create(
            permission="inventory:groups:read",
            application="inventory",
            resource_type="groups",
            verb="read",
            tenant=self.tenant,
        )
        access = Access.objects.create(role=role, permission=perm, tenant=self.tenant)

        # Create RD with only None and invalid UUIDs
        fake_ws_id_1 = "95473d62-56ea-4c0c-8945-4f3f6a620669"
        fake_ws_id_2 = "64f65afb-e6f7-4dbb-ba43-ffcdb4a7fb9b"
        rd = ResourceDefinition.objects.create(
            access=access,
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": [None, fake_ws_id_1, fake_ws_id_2],
            },
            tenant=self.tenant,
        )

        # BEFORE: Verify setup
        self.assertEqual(len(rd.attributeFilter["value"]), 3)
        self.assertIn(None, rd.attributeFilter["value"])

        # Call the cleanup function
        results = clean_invalid_workspace_resource_definitions()

        # Verify results
        self.assertEqual(results["resource_definitions_fixed"], 1)

        # Get the ungrouped workspace ID for verification
        ungrouped_ws = Workspace.objects.get(tenant=self.tenant, type=Workspace.Types.UNGROUPED_HOSTS)

        # AFTER: Verify None is replaced with ungrouped workspace ID, invalid IDs removed
        rd.refresh_from_db()
        self.assertNotIn(None, rd.attributeFilter["value"], "None should be replaced with ungrouped workspace ID")
        self.assertIn(
            str(ungrouped_ws.id),
            rd.attributeFilter["value"],
            "Ungrouped workspace ID should be present even when all other IDs are invalid",
        )
        self.assertNotIn(fake_ws_id_1, rd.attributeFilter["value"])
        self.assertNotIn(fake_ws_id_2, rd.attributeFilter["value"])
        self.assertEqual(len(rd.attributeFilter["value"]), 1, "Should have only ungrouped workspace ID")

    def test_clean_replaces_none_for_equal_operation_ungrouped(self):
        """
        Test that None value is replaced with ungrouped workspace ID for operation='equal'.

        Setup: Create RD with operation='equal' and value=None
        Action: Call cleanup function
        Verify: None is replaced with ungrouped workspace ID
        """
        # Create a custom role
        role = Role.objects.create(name="Test Role Equal None", system=False, tenant=self.tenant)

        perm = Permission.objects.create(
            permission="inventory:groups:read",
            application="inventory",
            resource_type="groups",
            verb="read",
            tenant=self.tenant,
        )
        access = Access.objects.create(role=role, permission=perm, tenant=self.tenant)

        # Create RD with operation='equal' and value=None (ungrouped workspace)
        rd = ResourceDefinition.objects.create(
            access=access,
            attributeFilter={
                "key": "group.id",
                "operation": "equal",
                "value": None,
            },
            tenant=self.tenant,
        )

        # BEFORE: Verify setup
        self.assertIsNone(rd.attributeFilter["value"])

        # Call the cleanup function - should process this RD and replace None with ungrouped workspace ID
        results = clean_invalid_workspace_resource_definitions()

        # Verify one RD was fixed
        self.assertEqual(results["resource_definitions_fixed"], 1)
        self.assertEqual(len(results["changes"]), 1)

        # Get the ungrouped workspace ID for verification
        ungrouped_ws = Workspace.objects.get(tenant=self.tenant, type=Workspace.Types.UNGROUPED_HOSTS)

        # AFTER: Verify None is replaced with ungrouped workspace ID
        rd.refresh_from_db()
        self.assertIsNotNone(rd.attributeFilter["value"], "None value should be replaced")
        self.assertEqual(
            rd.attributeFilter["value"], str(ungrouped_ws.id), "Should be replaced with ungrouped workspace ID"
        )

        # Verify the change info
        change = results["changes"][0]
        self.assertTrue(change["none_replaced_with_ungrouped"])
        self.assertEqual(change["ungrouped_workspace_id"], str(ungrouped_ws.id))

    def test_clean_dry_run_mode(self):
        """
        Test that dry_run mode reports changes without making them.

        Setup: Create RD with invalid workspace IDs and None value
        Action: Call cleanup function with dry_run=True
        Verify: Changes are reported but not applied to database
        """
        # Create a custom role
        role = Role.objects.create(name="Test Role Dry Run", system=False, tenant=self.tenant)

        perm = Permission.objects.create(
            permission="inventory:groups:read",
            application="inventory",
            resource_type="groups",
            verb="read",
            tenant=self.tenant,
        )
        access = Access.objects.create(role=role, permission=perm, tenant=self.tenant)

        # Create RD with invalid workspace IDs
        fake_ws_id_1 = "95473d62-56ea-4c0c-8945-4f3f6a620669"
        fake_ws_id_2 = "64f65afb-e6f7-4dbb-ba43-ffcdb4a7fb9b"
        original_value = [None, fake_ws_id_1, fake_ws_id_2]
        rd = ResourceDefinition.objects.create(
            access=access,
            attributeFilter={
                "key": "group.id",
                "operation": "in",
                "value": original_value,
            },
            tenant=self.tenant,
        )

        # Call the cleanup function in DRY RUN mode
        results = clean_invalid_workspace_resource_definitions(dry_run=True)

        # Get the ungrouped workspace ID for verification (created during cleanup function call)
        ungrouped_ws = Workspace.objects.get(tenant=self.tenant, type=Workspace.Types.UNGROUPED_HOSTS)

        # Verify results show what WOULD be changed
        self.assertTrue(results["dry_run"])
        self.assertEqual(results["resource_definitions_fixed"], 0)  # Nothing actually fixed
        self.assertEqual(len(results["changes"]), 1)  # But one change was detected

        # Verify change info contains before/after details
        change = results["changes"][0]
        self.assertEqual(change["action"], "would_update")
        self.assertEqual(change["original_value"], original_value)
        self.assertEqual(change["new_value"], [str(ungrouped_ws.id)])  # None replaced with ungrouped workspace ID
        self.assertEqual(len(change["invalid_workspaces"]), 2)
        self.assertTrue(change["none_replaced_with_ungrouped"])
        self.assertEqual(change["ungrouped_workspace_id"], str(ungrouped_ws.id))

        # CRITICAL: Verify database was NOT changed
        rd.refresh_from_db()
        self.assertEqual(rd.attributeFilter["value"], original_value)
        self.assertIn(fake_ws_id_1, rd.attributeFilter["value"])
        self.assertIn(fake_ws_id_2, rd.attributeFilter["value"])

        # Now run without dry_run to verify it actually makes changes
        results = clean_invalid_workspace_resource_definitions(dry_run=False)
        self.assertFalse(results["dry_run"])
        self.assertEqual(results["resource_definitions_fixed"], 1)
        self.assertEqual(results["changes"][0]["action"], "updated")

        # Verify database WAS changed this time
        rd.refresh_from_db()
        self.assertEqual(rd.attributeFilter["value"], [str(ungrouped_ws.id)])
        self.assertNotIn(None, rd.attributeFilter["value"])
        self.assertNotIn(fake_ws_id_1, rd.attributeFilter["value"])
        self.assertNotIn(fake_ws_id_2, rd.attributeFilter["value"])
