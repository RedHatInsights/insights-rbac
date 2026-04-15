#
# Copyright 2026 Red Hat, Inc.
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
"""Test the parity check tasks module."""

from unittest.mock import patch

from django.test import override_settings
from management.tasks import run_kessel_parity_checks_in_worker
from management.workspace.model import Workspace
from tests.identity_request import IdentityRequest


class ParityCheckTasksTest(IdentityRequest):
    """Test the Kessel parity check tasks."""

    def setUp(self):
        """Set up the parity check task tests."""
        super().setUp()

        # Create workspace hierarchy: root -> default -> child1
        self.root_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.ROOT,
            type=Workspace.Types.ROOT,
            tenant=self.tenant,
            parent=None,
        )
        self.default_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.DEFAULT,
            type=Workspace.Types.DEFAULT,
            tenant=self.tenant,
            parent=self.root_workspace,
        )
        self.child_workspace = Workspace.objects.create(
            name="Child Workspace",
            type=Workspace.Types.STANDARD,
            tenant=self.tenant,
            parent=self.default_workspace,
        )

    @override_settings(PARITY_CHECK_ORG_IDS="")
    def test_parity_check_task_no_org_ids_configured(self):
        """Test parity check task when no org_ids are configured."""
        result = run_kessel_parity_checks_in_worker()

        self.assertEqual(result, {"message": "No org_ids configured"})

    @override_settings(PARITY_CHECK_ORG_IDS="   ,  ,  ")
    def test_parity_check_task_empty_org_ids_list(self):
        """Test parity check task when org_ids list is empty after stripping."""
        result = run_kessel_parity_checks_in_worker()

        self.assertEqual(result, {"message": "No org_ids configured"})

    @override_settings(PARITY_CHECK_ORG_IDS="999999999")
    def test_parity_check_task_tenant_not_found(self):
        """Test parity check task when tenant is not found."""
        result = run_kessel_parity_checks_in_worker()

        self.assertEqual(result["total_tenants"], 0)
        self.assertEqual(result["tenants_not_found"], 1)
        self.assertEqual(result["passed_tenants"], 0)
        self.assertEqual(result["failed_tenants"], 0)

    @override_settings(PARITY_CHECK_ORG_IDS="test_org_id")
    @patch(
        "management.inventory_checker.inventory_api_check.WorkspaceRelationInventoryChecker.check_workspace_descendants"
    )
    def test_parity_check_task_no_workspaces_to_check(self, mock_check_workspace):
        """Test parity check task when there are no workspace pairs to check."""
        # Delete child workspace so only root exists (which is excluded from checks)
        self.child_workspace.delete()
        self.default_workspace.delete()

        # Update tenant org_id to match settings
        self.tenant.org_id = "test_org_id"
        self.tenant.save()

        result = run_kessel_parity_checks_in_worker()

        # Should not call checker since no pairs
        mock_check_workspace.assert_not_called()

        self.assertEqual(result["total_tenants"], 1)
        self.assertEqual(result["total_workspace_pairs_checked"], 0)
        self.assertEqual(result["passed_tenants"], 0)
        self.assertEqual(result["failed_tenants"], 1)
        self.assertEqual(len(result["tenants_checked"]), 1)
        self.assertEqual(result["tenants_checked"][0]["org_id"], "test_org_id")
        self.assertEqual(result["tenants_checked"][0]["workspace_pairs_checked"], 0)
        self.assertFalse(result["tenants_checked"][0]["passed"])

    @override_settings(PARITY_CHECK_ORG_IDS="test_org_id")
    @patch(
        "management.inventory_checker.inventory_api_check.WorkspaceRelationInventoryChecker.check_workspace_descendants"
    )
    def test_parity_check_task_all_checks_pass(self, mock_check_workspace):
        """Test parity check task when all workspace checks pass."""
        # Update tenant org_id to match settings
        self.tenant.org_id = "test_org_id"
        self.tenant.save()

        # Mock the checker to return True (all checks pass)
        mock_check_workspace.return_value = True

        result = run_kessel_parity_checks_in_worker()

        # Should call checker with 2 workspace pairs (default and child, excluding root)
        mock_check_workspace.assert_called_once()
        called_pairs = mock_check_workspace.call_args[0][0]
        self.assertEqual(len(called_pairs), 2)

        # Verify result
        self.assertEqual(result["total_tenants"], 1)
        self.assertEqual(result["total_workspace_pairs_checked"], 2)
        self.assertEqual(result["passed_tenants"], 1)
        self.assertEqual(result["failed_tenants"], 0)
        self.assertEqual(result["tenants_not_found"], 0)
        self.assertEqual(len(result["tenants_checked"]), 1)
        self.assertEqual(result["tenants_checked"][0]["org_id"], "test_org_id")
        self.assertEqual(result["tenants_checked"][0]["workspace_pairs_checked"], 2)
        self.assertTrue(result["tenants_checked"][0]["passed"])

        # Verify timing data is present
        self.assertIn("duration_seconds", result["tenants_checked"][0])
        self.assertIn("timing", result)
        self.assertIn("avg_seconds", result["timing"])
        self.assertIn("p95_seconds", result["timing"])
        self.assertIn("p99_seconds", result["timing"])

    @override_settings(PARITY_CHECK_ORG_IDS="test_org_id")
    @patch(
        "management.inventory_checker.inventory_api_check.WorkspaceRelationInventoryChecker.check_workspace_descendants"
    )
    def test_parity_check_task_checks_fail(self, mock_check_workspace):
        """Test parity check task when workspace checks fail."""
        # Update tenant org_id to match settings
        self.tenant.org_id = "test_org_id"
        self.tenant.save()

        # Mock the checker to return False (checks failed)
        mock_check_workspace.return_value = False

        result = run_kessel_parity_checks_in_worker()

        # Should call checker
        mock_check_workspace.assert_called_once()

        # Verify result
        self.assertEqual(result["total_tenants"], 1)
        self.assertEqual(result["total_workspace_pairs_checked"], 2)
        self.assertEqual(result["passed_tenants"], 0)
        self.assertEqual(result["failed_tenants"], 1)
        self.assertEqual(result["tenants_not_found"], 0)
        self.assertEqual(len(result["tenants_checked"]), 1)
        self.assertEqual(result["tenants_checked"][0]["org_id"], "test_org_id")
        self.assertEqual(result["tenants_checked"][0]["workspace_pairs_checked"], 2)
        self.assertFalse(result["tenants_checked"][0]["passed"])

    @override_settings(PARITY_CHECK_ORG_IDS="test_org_1, test_org_2, 999999")
    @patch(
        "management.inventory_checker.inventory_api_check.WorkspaceRelationInventoryChecker.check_workspace_descendants"
    )
    def test_parity_check_task_multiple_orgs(self, mock_check_workspace):
        """Test parity check task with multiple org_ids (some valid, some not)."""
        # Update tenant org_id to match first in list
        self.tenant.org_id = "test_org_1"
        self.tenant.save()

        # Create second tenant
        from api.models import Tenant

        tenant2 = Tenant.objects.create(
            tenant_name="acct2",
            account_id="54321",
            org_id="test_org_2",
            ready=True,
        )
        root2 = Workspace.objects.create(
            name=Workspace.SpecialNames.ROOT,
            type=Workspace.Types.ROOT,
            tenant=tenant2,
            parent=None,
        )
        default2 = Workspace.objects.create(
            name=Workspace.SpecialNames.DEFAULT,
            type=Workspace.Types.DEFAULT,
            tenant=tenant2,
            parent=root2,
        )

        # Mock the checker to return True for first, False for second
        mock_check_workspace.side_effect = [True, False]

        result = run_kessel_parity_checks_in_worker()

        # Should call checker twice (once for each valid tenant)
        self.assertEqual(mock_check_workspace.call_count, 2)

        # Verify result
        self.assertEqual(result["total_tenants"], 2)
        self.assertEqual(result["total_workspace_pairs_checked"], 3)  # 2 from tenant1, 1 from tenant2
        self.assertEqual(result["passed_tenants"], 1)
        self.assertEqual(result["failed_tenants"], 1)
        self.assertEqual(result["tenants_not_found"], 1)  # Third org_id
        self.assertEqual(len(result["tenants_checked"]), 2)

        # Clean up - delete workspaces in correct order (child before parent), then tenant
        default2.delete()
        root2.delete()
        tenant2.delete()

    @override_settings(PARITY_CHECK_ORG_IDS="test_org_id")
    @patch(
        "management.inventory_checker.inventory_api_check.WorkspaceRelationInventoryChecker.check_workspace_descendants"
    )
    def test_parity_check_task_workspace_pairs_format(self, mock_check_workspace):
        """Test that workspace pairs are formatted correctly as (child_id, parent_id) tuples."""
        # Update tenant org_id
        self.tenant.org_id = "test_org_id"
        self.tenant.save()

        # Mock the checker
        mock_check_workspace.return_value = True

        run_kessel_parity_checks_in_worker()

        # Get the workspace pairs passed to the checker
        called_pairs = mock_check_workspace.call_args[0][0]

        # Verify pairs are tuples of string UUIDs
        for pair in called_pairs:
            self.assertIsInstance(pair, tuple)
            self.assertEqual(len(pair), 2)
            workspace_id, parent_id = pair
            self.assertIsInstance(workspace_id, str)
            self.assertIsInstance(parent_id, str)

        # Verify expected pairs exist (default->root, child->default)
        workspace_ids = [str(self.default_workspace.id), str(self.child_workspace.id)]
        parent_ids = [str(self.root_workspace.id), str(self.default_workspace.id)]

        for workspace_id, parent_id in zip(workspace_ids, parent_ids):
            self.assertIn((workspace_id, parent_id), called_pairs)

    @override_settings(PARITY_CHECK_ORG_IDS="test_org_id")
    @patch(
        "management.inventory_checker.inventory_api_check.WorkspaceRelationInventoryChecker.check_workspace_descendants"
    )
    def test_parity_check_task_handles_checker_exception(self, mock_check_workspace):
        """Test that the task handles exceptions from the checker gracefully."""
        # Update tenant org_id
        self.tenant.org_id = "test_org_id"
        self.tenant.save()

        # Mock the checker to raise an exception (e.g., gRPC network error)
        mock_check_workspace.side_effect = Exception("gRPC connection timeout")

        result = run_kessel_parity_checks_in_worker()

        # Should have attempted to call checker
        mock_check_workspace.assert_called_once()

        # Verify result shows failure but task completed
        self.assertEqual(result["total_tenants"], 1)  # Counted before exception
        self.assertEqual(result["passed_tenants"], 0)
        self.assertEqual(result["failed_tenants"], 1)
        self.assertEqual(len(result["tenants_checked"]), 1)
        self.assertEqual(result["tenants_checked"][0]["org_id"], "test_org_id")
        self.assertEqual(result["tenants_checked"][0]["workspace_pairs_checked"], 0)
        self.assertFalse(result["tenants_checked"][0]["passed"])
        self.assertIn("error", result["tenants_checked"][0])
        self.assertIn("gRPC connection timeout", result["tenants_checked"][0]["error"])
