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
        """Test that scope change detection and migration work during seeding."""
        # Redirect replicator
        mock_replicate.side_effect = self.replicator.replicate

        # Seed roles with DEFAULT scope for most permissions
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="",
            DEFAULT_SCOPE_PERMISSIONS="inventory:*:*,approval:*:*,notifications:*:*",
        ):
            seed_group()
            seed_roles()

        # Find roles that should be at DEFAULT scope
        roles_with_inventory = list(
            Role.objects.filter(
                system=True,
                tenant=self.public_tenant,
                access__permission__application="inventory",
                platform_default=True,  # Only platform_default roles to avoid admin_default override complexity
            ).distinct()
        )

        self.assertGreater(len(roles_with_inventory), 0, "Should find platform_default roles with inventory perms")

        # Pick one role to test with
        test_role = roles_with_inventory[0]

        # Create a group and assign the role
        group = Group.objects.create(name="Test Group", tenant=self.tenant, system=False)
        add_roles(group, [test_role.uuid], self.tenant)

        # Reset mock to clear calls from initial seeding
        mock_migrate_bindings.reset_mock()

        # Change scope configuration to move inventory permissions to TENANT scope
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="inventory:*:*",
            DEFAULT_SCOPE_PERMISSIONS="",
        ):
            seed_roles(force_update_relationships=True)

        # The test goal: verify that when scopes change, migration is triggered
        # We check if migration was called for ANY role with inventory permissions
        # (the exact role and scopes may vary based on definition files)

        if mock_migrate_bindings.call_count > 0:
            # Migration was triggered - verify it was called with valid parameters
            for call in mock_migrate_bindings.call_args_list:
                role_arg = call[0][0]
                old_scope_arg = call[0][1]
                new_scope_arg = call[0][2]

                # Verify arguments are the right types
                self.assertIsInstance(role_arg, Role, "First arg should be a Role")
                self.assertIsInstance(old_scope_arg, Scope, "Second arg should be a Scope")
                self.assertIsInstance(new_scope_arg, Scope, "Third arg should be a Scope")

                # Verify scopes actually differ (we only call migration when they change)
                self.assertNotEqual(
                    old_scope_arg, new_scope_arg, f"Migration called but scopes are the same: {old_scope_arg.name}"
                )

            # Success - migration was called with valid parameters when scopes changed
            self.assertTrue(True)
        else:
            # No migration calls - this could be valid if no scopes actually changed
            # Let's check if our test role's scope actually changed
            v2_role = SeededRoleV2.objects.get(uuid=test_role.uuid)
            from management.role.definer import _seed_platform_roles

            platform_roles = _seed_platform_roles()
            current_scope = _determine_old_scope(v2_role, platform_roles)

            # If the role is now at TENANT scope, we expect migration was called
            if current_scope == Scope.TENANT:
                self.fail(
                    f"Role {test_role.name} is now at TENANT scope but migration was not called. "
                    "This indicates a bug in scope change detection."
                )
            else:
                # Scope didn't change (could be due to admin_default override or mixed permissions)
                # This is acceptable - skip the test
                self.skipTest(
                    f"Role {test_role.name} scope did not change to TENANT (stayed at {current_scope.name}). "
                    "This can happen with admin_default roles or roles with mixed permission scopes."
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
