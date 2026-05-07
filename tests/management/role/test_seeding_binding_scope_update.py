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
from management.models import Access, Permission, Workspace
from management.permission.scope_service import Scope
from management.role.definer import (
    seed_roles,
    _determine_old_scopes,
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
    subject,
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

        # Bootstrap tenant with workspaces but keep it as V1 (no V2 activation)
        # The scope change migration only applies to V1 tenants
        bootstrap_result = bootstrap_tenant_for_v2_test(self.tenant, tuples=self.tuples)
        self.root_workspace = bootstrap_result.root_workspace
        self.default_workspace = bootstrap_result.default_workspace

        # Deactivate V2 writes to make this a V1 tenant
        # This ensures _determine_old_scopes can find the bindings
        from management.tenant_mapping.model import TenantMapping

        TenantMapping.objects.filter(tenant=self.tenant).update(v2_write_activated_at=None)

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

        # Ensure RoleBinding record exists in database so _determine_old_scopes can find it
        # add_roles() should have created it, but we verify it exists
        from management.role_binding.model import RoleBinding
        from management.role.v2_model import RoleV2

        v2_role = RoleV2.objects.get(v1_source=test_role)
        RoleBinding.objects.get_or_create(
            tenant=self.tenant,
            role=v2_role,
            resource_type="workspace",
            resource_id=str(self.default_workspace.id),
        )

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
        role_arg, old_scopes_arg, new_scope_arg = call_args

        self.assertEqual(role_arg, test_role, "Migration should be called for the test role")
        self.assertEqual(old_scopes_arg, {Scope.DEFAULT}, "Old scopes should be {DEFAULT}")
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

        # Ensure RoleBinding record exists in database so _determine_old_scopes can find it
        # add_roles() should have created it, but we verify it exists
        from management.role_binding.model import RoleBinding
        from management.role.v2_model import RoleV2

        v2_role_obj = RoleV2.objects.get(v1_source=test_role)
        RoleBinding.objects.get_or_create(
            tenant=self.tenant,
            role=v2_role_obj,
            resource_type="workspace",
            resource_id=str(self.default_workspace.id),
        )

        # Verify initial binding at DEFAULT workspace
        v2_role = SeededRoleV2.objects.get(uuid=test_role.uuid)

        # Find bindings for this role at the default workspace
        # We need to filter specifically for bindings related to our group to avoid counting
        # default access bindings (platform_default/admin_default automatic bindings)
        initial_bindings = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(self.default_workspace.id)),
                relation("binding"),
            )
        ).traverse_subject(
            [
                all_of(
                    relation("subject"),
                    subject("rbac", "group", str(group.uuid), "member"),
                )
            ],
            require_full_match=False,
        )
        self.assertGreater(
            len(initial_bindings),
            0,
            f"Should have binding at default workspace for group {group.uuid} initially",
        )

        # Change scope to TENANT
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="inventory:*:*",
        ):
            seed_roles(force_update_relationships=True)

        # For TENANT scope, bindings should be at the tenant level
        tenant_resource_id = Tenant.org_id_to_tenant_resource_id(self.tenant.org_id)
        tenant_bindings = self.tuples.find_tuples(
            all_of(
                resource("rbac", "tenant", tenant_resource_id),
                relation("binding"),
            )
        ).traverse_subject(
            [
                all_of(
                    relation("subject"),
                    subject("rbac", "group", str(group.uuid), "member"),
                )
            ],
            require_full_match=False,
        )
        self.assertGreater(
            len(tenant_bindings),
            0,
            f"Should have binding at tenant for group {group.uuid} after migration",
        )

    def test_determine_old_scopes_returns_empty_for_new_role(self):
        """Test that _determine_old_scopes returns empty set when there's no existing V1 role."""
        result = _determine_old_scopes(None)
        self.assertEqual(result, set(), "Should return empty set for None role")

    def test_determine_old_scopes_returns_empty_for_role_without_bindings(self):
        """Test that _determine_old_scopes returns empty set when role has no bindings in V1 tenants."""
        # Create a role with no bindings
        test_role = Role.objects.create(
            name="Test Role No Bindings",
            tenant=self.public_tenant,
            system=True,
        )
        result = _determine_old_scopes(test_role)
        self.assertEqual(result, set(), "Should return empty set for role without bindings")

    def test_determine_old_scopes_detects_scope_from_bindings(self):
        """Test that _determine_old_scopes correctly identifies scopes from actual bindings."""
        # Seed roles to create bindings
        seed_group()
        seed_roles()

        # Find a seeded role that should have bindings
        v1_role = Role.objects.filter(
            system=True,
            tenant=self.public_tenant,
            platform_default=True,
        ).first()

        if v1_role:
            # Create a group and assign the role to create bindings
            group = Group.objects.create(name="Test Scope Detection", tenant=self.tenant, system=False)
            add_roles(group, [v1_role.uuid], self.tenant)

            detected_scopes = _determine_old_scopes(v1_role)

            # Should have at least one scope detected (the role should have bindings somewhere)
            self.assertGreater(
                len(detected_scopes),
                0,
                f"Should detect at least one scope for role with bindings, got {detected_scopes}",
            )

            # All detected scopes should be valid
            for scope in detected_scopes:
                self.assertIn(
                    scope,
                    [Scope.DEFAULT, Scope.TENANT, Scope.ROOT],
                    f"All scopes should be valid, got {scope}",
                )
        else:
            self.skipTest("No platform_default seeded roles found to test with")

    def test_determine_old_scopes_detects_admin_scope_from_bindings(self):
        """Test that _determine_old_scopes correctly identifies scopes from admin role bindings."""
        # Seed roles to create bindings
        seed_group()
        seed_roles()

        # Find a seeded role that has admin_default
        v1_role = Role.objects.filter(
            system=True,
            admin_default=True,
            tenant=self.public_tenant,
        ).first()

        if v1_role:
            # Create a group and assign the role to create bindings
            group = Group.objects.create(name="Test Admin Scope Detection", tenant=self.tenant, system=False)
            add_roles(group, [v1_role.uuid], self.tenant)

            detected_scopes = _determine_old_scopes(v1_role)

            # Should have at least one scope detected
            self.assertGreater(
                len(detected_scopes),
                0,
                f"Should detect at least one scope for admin role with bindings, got {detected_scopes}",
            )

            # All detected scopes should be valid
            for scope in detected_scopes:
                self.assertIn(
                    scope,
                    [Scope.DEFAULT, Scope.TENANT, Scope.ROOT],
                    f"All scopes should be valid, got {scope}",
                )
        else:
            self.skipTest("No admin_default seeded roles found to test with")

    @patch("management.role.definer._migrate_bindings_for_scope_change")
    def test_log_scope_change_and_migrate_does_nothing_when_scopes_equal(self, mock_migrate):
        """Test that no migration is triggered when old and new scopes are the same."""
        role = MagicMock()
        _log_scope_change_and_migrate(role, "Test Role", {Scope.DEFAULT}, Scope.DEFAULT)
        mock_migrate.assert_not_called()

    @patch("management.role.definer._migrate_bindings_for_scope_change")
    def test_log_scope_change_and_migrate_does_nothing_when_old_scopes_empty(self, mock_migrate):
        """Test that no migration is triggered when old_scopes is empty (no existing bindings)."""
        role = MagicMock()
        _log_scope_change_and_migrate(role, "Test Role", set(), Scope.DEFAULT)
        mock_migrate.assert_not_called()

    @patch("management.role.definer._migrate_bindings_for_scope_change")
    def test_log_scope_change_and_migrate_triggers_when_scopes_differ(self, mock_migrate):
        """Test that migration is triggered when scopes differ."""
        role = MagicMock()
        role.name = "Test Role"
        _log_scope_change_and_migrate(role, "Test Role", {Scope.DEFAULT}, Scope.TENANT)
        mock_migrate.assert_called_once_with(role, {Scope.DEFAULT}, Scope.TENANT)
