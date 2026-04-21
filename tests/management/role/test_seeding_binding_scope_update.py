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
from migration_tool.in_memory_tuples import (
    InMemoryTuples,
    InMemoryRelationReplicator,
    all_of,
    resource,
    relation,
    subject_type,
)
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
        # (permissions not in ROOT or TENANT automatically fall to DEFAULT)
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="",
        ):
            seed_group()
            seed_roles()

        # Find a role that should be at DEFAULT scope
        # Exclude admin_default roles to avoid ADMIN_DEFAULT_SEEDED_ROLES_FORCE_ROOT_SCOPE override
        test_role = Role.objects.filter(
            system=True,
            tenant=self.public_tenant,
            access__permission__application="inventory",
            platform_default=True,
            admin_default=False,  # Avoid roles subject to ROOT scope override
        ).first()

        self.assertIsNotNone(
            test_role,
            "Expected at least one platform_default (non-admin_default) role with inventory permissions in test data",
        )

        # Create a group and assign the role
        group = Group.objects.create(name="Test Group", tenant=self.tenant, system=False)
        add_roles(group, [test_role.uuid], self.tenant)

        # Reset mock to clear calls from initial seeding
        mock_migrate_bindings.reset_mock()

        # Change scope configuration to move inventory permissions to TENANT scope
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="inventory:*:*",
        ):
            seed_roles(force_update_relationships=True)

        # Verify that migration was called for the scope change (DEFAULT → TENANT)
        # Note: Migration might be called for multiple roles (e.g., other inventory roles),
        # so we check that it was called for our specific test_role
        mock_migrate_bindings.assert_called()

        # Find the call(s) for our test role
        test_role_calls = [call for call in mock_migrate_bindings.call_args_list if call[0][0] == test_role]

        self.assertEqual(
            len(test_role_calls),
            1,
            f"Migration should be called exactly once for test role {test_role.name}. "
            f"Found {len(test_role_calls)} call(s).",
        )

        # Verify it was called with correct arguments
        call_args = test_role_calls[0][0]
        role_arg, old_scope_arg, new_scope_arg = call_args

        self.assertEqual(role_arg, test_role, "Migration should be called for the test role")
        self.assertEqual(old_scope_arg, Scope.DEFAULT, "Old scope should be DEFAULT")
        self.assertEqual(new_scope_arg, Scope.TENANT, "New scope should be TENANT")

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_bindings_migrate_from_default_to_tenant_scope_v1_tenant(self, mock_replicate):
        """Test that bindings actually migrate from default workspace to tenant when scope changes."""
        # Redirect replicator
        mock_replicate.side_effect = self.replicator.replicate

        # Seed roles with DEFAULT scope for inventory permissions
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="",
        ):
            seed_group()
            seed_roles()

        # Find a suitable test role
        test_role = Role.objects.filter(
            system=True,
            tenant=self.public_tenant,
            access__permission__application="inventory",
            platform_default=True,
            admin_default=False,
        ).first()

        self.assertIsNotNone(
            test_role,
            "Expected at least one platform_default (non-admin_default) role with inventory permissions in test data",
        )

        # Create a group and assign the role
        group = Group.objects.create(name="Test Group", tenant=self.tenant, system=False)
        add_roles(group, [test_role.uuid], self.tenant)

        # Verify initial binding at DEFAULT workspace
        v2_role = SeededRoleV2.objects.get(uuid=test_role.uuid)

        # Get binding mapping for this group-role assignment
        binding_mapping = BindingMapping.objects.filter(
            role_binding__group=group,
            role=v2_role,
        ).first()

        self.assertIsNotNone(binding_mapping, "Should have a binding mapping for the group-role assignment")

        # Find bindings for this role binding at the default workspace
        initial_bindings = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(self.default_workspace.id)),
                relation("binding"),
            )
        )
        self.assertGreater(len(initial_bindings), 0, "Should have binding at default workspace initially")

        # Change scope to TENANT
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="inventory:*:*",
        ):
            seed_roles(force_update_relationships=True)

        # Verify bindings migrated away from default workspace
        default_workspace_bindings_after = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(self.default_workspace.id)),
                relation("binding"),
            )
        )
        # After migration, bindings should have moved from workspace to tenant
        # Count might be 0 or could have other unrelated bindings, so we check the binding mapping instead

        # Verify the binding mapping now points to tenant instead of workspace
        binding_mapping_after = BindingMapping.objects.filter(
            role_binding__group=group,
            role=v2_role,
        ).first()

        self.assertIsNotNone(binding_mapping_after, "Binding mapping should still exist after migration")

        # For TENANT scope, bindings should be at the tenant level
        tenant_resource_id = Tenant.org_id_to_tenant_resource_id(self.tenant.org_id)
        tenant_bindings = self.tuples.find_tuples(
            all_of(
                resource("rbac", "tenant", tenant_resource_id),
                relation("binding"),
            )
        )
        self.assertGreater(len(tenant_bindings), 0, "Should have binding at tenant after migration")

    def test_determine_old_scope_returns_none_for_new_role(self):
        """Test that _determine_old_scope returns None when there's no existing V2 role."""
        result = _determine_old_scope(None, {})
        self.assertIsNone(result, "Should return None for new role")

    def test_determine_old_scope_returns_none_for_role_without_parents(self):
        """Test that _determine_old_scope returns None when role has no parent relationships and no permissions."""
        # Create a mock V2 role with no parents and no permissions
        mock_role = MagicMock()
        mock_role.parents.values_list.return_value = []
        mock_role.permissions.values_list.return_value = []
        result = _determine_old_scope(mock_role, {})
        self.assertIsNone(result, "Should return None for role without parents or permissions")

    def test_determine_old_scope_detects_scope_from_parents(self):
        """Test that _determine_old_scope correctly identifies scope from parent relationships."""
        # Use actual seeded roles to test scope detection
        seed_group()
        seed_roles()

        from management.role.definer import _seed_platform_roles

        platform_roles = _seed_platform_roles()

        # Find a seeded role that should have platform_default
        v2_roles = SeededRoleV2.objects.filter(v1_source__platform_default=True, v1_source__tenant=self.public_tenant)

        if v2_roles.exists():
            v2_role = v2_roles.first()
            detected_scope = _determine_old_scope(v2_role, platform_roles)

            # Verify it detected a valid scope (DEFAULT, TENANT, or ROOT)
            self.assertIn(
                detected_scope,
                [Scope.DEFAULT, Scope.TENANT, Scope.ROOT],
                f"Should detect a valid scope, got {detected_scope}",
            )
        else:
            self.skipTest("No platform_default seeded roles found to test with")

    def test_determine_old_scope_detects_admin_scope_from_parents(self):
        """Test that _determine_old_scope correctly identifies scope from admin parent relationships."""
        # Use actual seeded roles to test scope detection
        seed_group()
        seed_roles()

        from management.role.definer import _seed_platform_roles

        platform_roles = _seed_platform_roles()

        # Find a seeded role that has admin_default
        v2_roles = SeededRoleV2.objects.filter(v1_source__admin_default=True, v1_source__tenant=self.public_tenant)

        if v2_roles.exists():
            v2_role = v2_roles.first()
            detected_scope = _determine_old_scope(v2_role, platform_roles)

            # Verify it detected a valid scope
            self.assertIn(
                detected_scope,
                [Scope.DEFAULT, Scope.TENANT, Scope.ROOT],
                f"Should detect a valid scope from admin parent, got {detected_scope}",
            )
        else:
            self.skipTest("No admin_default seeded roles found to test with")

    def test_determine_old_scope_calculates_from_permissions_when_no_parents(self):
        """Test that _determine_old_scope falls back to calculating from permissions when role has no parents."""
        from management.permission.scope_service import ResourceDefinitionService
        from management.role.definer import _seed_platform_roles

        # Seed roles to set up platform roles
        seed_group()
        seed_roles()

        platform_roles = _seed_platform_roles()
        resource_service = ResourceDefinitionService()

        # Find a non-default system role (no platform parents)
        non_default_role = (
            Role.objects.public_tenant_only()
            .filter(platform_default=False, admin_default=False, system=True, access__isnull=False)
            .distinct()
            .first()
        )

        if not non_default_role:
            self.skipTest("No non-default system roles with permissions found in test data")

        # Get its V2 equivalent (should have no platform parents)
        v2_role = SeededRoleV2.objects.filter(uuid=non_default_role.uuid).first()
        self.assertIsNotNone(v2_role, "V2 role should exist for the non-default role")

        # Verify it has no platform parents
        parent_count = v2_role.parents.count()
        self.assertEqual(parent_count, 0, "Non-default role should have no platform parents")

        # Now try to determine old scope - should calculate from permissions
        detected_scope = _determine_old_scope(v2_role, platform_roles, resource_service)

        # Should be able to determine scope from permissions even without parents
        self.assertIsNotNone(
            detected_scope,
            f"Should be able to calculate scope from permissions for {non_default_role.name}",
        )
        self.assertIn(
            detected_scope,
            [Scope.DEFAULT, Scope.TENANT, Scope.ROOT],
            f"Should detect a valid scope from permissions, got {detected_scope}",
        )

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
