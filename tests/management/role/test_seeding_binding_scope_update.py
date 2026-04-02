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
"""Tests for system role binding scope updates during seeding."""

from unittest.mock import patch, MagicMock
from django.test import override_settings
from management.group.definer import add_roles, seed_group
from management.group.model import Group
from management.models import BindingMapping, Access, Permission, Workspace
from management.permission.scope_service import Scope
from management.role.definer import (
    seed_roles,
    _determine_old_scope,
    _log_scope_change_and_migrate,
)
from management.role.model import Role
from management.role.v2_model import SeededRoleV2, PlatformRoleV2
from management.tenant_mapping.model import DefaultAccessType
from migration_tool.in_memory_tuples import InMemoryTuples, InMemoryRelationReplicator
from tests.identity_request import IdentityRequest
from tests.v2_util import bootstrap_tenant_for_v2_test

from api.models import Tenant


@override_settings(ATOMIC_RETRY_DISABLED=True, REPLICATION_TO_RELATION_ENABLED=True)
class SystemRoleBindingScopeUpdateTests(IdentityRequest):
    """Test that system role bindings are updated when role scope changes during seeding."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.tuples = InMemoryTuples()
        self.replicator = InMemoryRelationReplicator(self.tuples)

        self.public_tenant = Tenant.objects.get(tenant_name="public")

        # Bootstrap a regular tenant with workspaces
        bootstrap_result = bootstrap_tenant_for_v2_test(self.tenant, tuples=self.tuples)
        self.root_workspace = bootstrap_result.root_workspace
        self.default_workspace = bootstrap_result.default_workspace

        # Create permission in public tenant
        self.permission = Permission.objects.create(
            tenant=self.public_tenant,
            application="inventory",
            resource_type="hosts",
            verb="read",
            permission="inventory:hosts:read",
        )

    @patch("management.role.definer._migrate_bindings_for_scope_change")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_binding_scope_updates_when_role_scope_changes_during_seeding(self, mock_replicate, mock_migrate_bindings):
        """Test that when a system role's scope changes, migration is triggered."""
        # Redirect replicator
        mock_replicate.side_effect = self.replicator.replicate

        # Step 1: Seed with DEFAULT scope initially
        # This will create real system roles from the definition files
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="",
            DEFAULT_SCOPE_PERMISSIONS="inventory:*:*,approval:*:*,notifications:*:*",
        ):
            seed_group()
            seed_roles()

        # Find a system role that has inventory permissions (will be in DEFAULT scope)
        # The "Inventory Groups Administrator" role has inventory:groups:* permissions
        system_role = Role.objects.filter(
            system=True, tenant=self.public_tenant, access__permission__application="inventory"
        ).first()

        self.assertIsNotNone(system_role, "Should find a system role with inventory permissions")

        # Create a group and assign the system role (creates binding)
        group = Group.objects.create(name="Test Group", tenant=self.tenant, system=False)
        add_roles(group, [system_role.uuid], self.tenant)

        # Verify binding was created at DEFAULT scope (default workspace)
        binding_before = BindingMapping.objects.filter(role=system_role).first()
        if binding_before:
            self.assertEqual(binding_before.resource_type_name, "workspace", "Binding should be to a workspace")
            workspace_before = Workspace.objects.get(id=binding_before.resource_id)
            self.assertEqual(
                workspace_before.type, Workspace.Types.DEFAULT, "Binding should initially be at DEFAULT workspace"
            )

        # Reset the mock to clear any calls from initial seeding
        mock_migrate_bindings.reset_mock()

        # Step 2: Change scope to TENANT and re-seed
        # This moves inventory permissions from DEFAULT to TENANT scope
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="inventory:*:*",
            DEFAULT_SCOPE_PERMISSIONS="",
        ):
            # Re-seed with force_update_relationships to apply scope change
            seed_roles(force_update_relationships=True)

        # Verify that the parent role relationship was updated
        system_role.refresh_from_db()

        # Verify that the migration function was called when scope changed
        # It should be called at least once (possibly multiple times if multiple roles changed)
        self.assertGreater(
            mock_migrate_bindings.call_count, 0, "Migration should be called at least once when scope changes"
        )

        # Verify one of the calls was for our system role with correct scope change
        found_correct_call = False
        for call in mock_migrate_bindings.call_args_list:
            if call[0][0].uuid == system_role.uuid:
                found_correct_call = True
                self.assertEqual(call[0][1].name, "DEFAULT", "Old scope should be DEFAULT")
                self.assertEqual(call[0][2].name, "TENANT", "New scope should be TENANT")
                break

        self.assertTrue(
            found_correct_call,
            f"Should find migration call for role {system_role.name} with DEFAULT->TENANT scope change",
        )

    def test_determine_old_scope_returns_none_for_new_role(self):
        """Test that _determine_old_scope returns None when there's no existing V2 role."""
        platform_roles = {}
        result = _determine_old_scope(None, platform_roles)
        self.assertIsNone(result, "Should return None for new role")

    def test_determine_old_scope_returns_none_for_empty_platform_roles(self):
        """Test that _determine_old_scope handles empty platform_roles gracefully."""
        # Create a mock V2 role
        mock_role = MagicMock()
        result = _determine_old_scope(mock_role, {})
        self.assertIsNone(result, "Should return None for empty platform_roles")

    def test_determine_old_scope_detects_scope_from_user_parent(self):
        """Test that _determine_old_scope correctly identifies scope from USER parent."""
        # Create platform roles
        seed_group()
        from management.role.definer import _seed_platform_roles

        platform_roles = _seed_platform_roles()

        # Create a V2 role with DEFAULT USER parent
        v2_role = SeededRoleV2.objects.create(
            name="Test Role",
            description="Test",
            tenant=self.public_tenant,
        )
        default_user_platform = platform_roles[(DefaultAccessType.USER, Scope.DEFAULT)]
        v2_role.parents.add(default_user_platform)

        # Test detection
        detected_scope = _determine_old_scope(v2_role, platform_roles)
        self.assertEqual(detected_scope, Scope.DEFAULT, "Should detect DEFAULT scope from USER parent")

        # Cleanup
        v2_role.delete()

    def test_determine_old_scope_detects_scope_from_admin_parent(self):
        """Test that _determine_old_scope correctly identifies scope from ADMIN parent."""
        # Create platform roles
        seed_group()
        from management.role.definer import _seed_platform_roles

        platform_roles = _seed_platform_roles()

        # Create a V2 role with TENANT ADMIN parent only
        v2_role = SeededRoleV2.objects.create(
            name="Test Admin Role",
            description="Test",
            tenant=self.public_tenant,
        )
        tenant_admin_platform = platform_roles[(DefaultAccessType.ADMIN, Scope.TENANT)]
        v2_role.parents.add(tenant_admin_platform)

        # Test detection
        detected_scope = _determine_old_scope(v2_role, platform_roles)
        self.assertEqual(detected_scope, Scope.TENANT, "Should detect TENANT scope from ADMIN parent")

        # Cleanup
        v2_role.delete()

    @patch("management.role.definer._migrate_bindings_for_scope_change")
    def test_log_scope_change_and_migrate_does_nothing_when_scopes_equal(self, mock_migrate):
        """Test that no migration is triggered when old and new scopes are the same."""
        role = MagicMock()
        _log_scope_change_and_migrate(role, "Test Role", Scope.DEFAULT, Scope.DEFAULT)
        mock_migrate.assert_not_called()

    @patch("management.role.definer._migrate_bindings_for_scope_change")
    def test_log_scope_change_and_migrate_does_nothing_when_old_scope_none(self, mock_migrate):
        """Test that no migration is triggered when old_scope is None (new role)."""
        role = MagicMock()
        _log_scope_change_and_migrate(role, "Test Role", None, Scope.DEFAULT)
        mock_migrate.assert_not_called()

    @patch("management.role.definer._migrate_bindings_for_scope_change")
    def test_log_scope_change_and_migrate_triggers_when_scopes_differ(self, mock_migrate):
        """Test that migration is triggered when scopes differ."""
        role = MagicMock()
        role.name = "Test Role"
        _log_scope_change_and_migrate(role, "Test Role", Scope.DEFAULT, Scope.TENANT)
        mock_migrate.assert_called_once_with(role, Scope.DEFAULT, Scope.TENANT)
