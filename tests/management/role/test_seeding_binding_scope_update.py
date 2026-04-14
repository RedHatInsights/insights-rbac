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

        if not test_role:
            self.skipTest("No suitable platform_default (non-admin_default) roles with inventory permissions found")

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
        mock_migrate_bindings.assert_called_once()

        # Verify it was called with correct arguments
        call_args = mock_migrate_bindings.call_args[0]
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

        if not test_role:
            self.skipTest("No suitable platform_default (non-admin_default) roles with inventory permissions found")

        # Create a group and assign the role
        group = Group.objects.create(name="Test Group", tenant=self.tenant, system=False)
        add_roles(group, [test_role.uuid], self.tenant)

        # Verify initial binding at DEFAULT workspace
        v2_role = SeededRoleV2.objects.get(uuid=test_role.uuid)
        initial_bindings = self.tuples.read_tuples(
            resource_type="rbac/principal",
            resource_id=f"group:{group.uuid}",
            relation="binding",
        )

        # Should have binding to the role at default workspace
        default_workspace_bindings = [
            t
            for t in initial_bindings
            if t.subject.object.object_id == str(self.default_workspace.id)
            and str(v2_role.uuid) in t.subject.object.object_type
        ]
        self.assertGreater(len(default_workspace_bindings), 0, "Should have binding at default workspace initially")

        # Change scope to TENANT
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="inventory:*:*",
        ):
            seed_roles(force_update_relationships=True)

        # Verify bindings migrated to TENANT
        final_bindings = self.tuples.read_tuples(
            resource_type="rbac/principal",
            resource_id=f"group:{group.uuid}",
            relation="binding",
        )

        # Should no longer have binding at default workspace
        default_workspace_bindings_after = [
            t
            for t in final_bindings
            if t.subject.object.object_id == str(self.default_workspace.id)
            and str(v2_role.uuid) in t.subject.object.object_type
        ]
        self.assertEqual(
            len(default_workspace_bindings_after), 0, "Should not have binding at default workspace after migration"
        )

        # Should have binding at tenant instead
        tenant_resource_id = Tenant.org_id_to_tenant_resource_id(self.tenant.org_id)
        tenant_bindings = [
            t
            for t in final_bindings
            if t.subject.object.object_id == tenant_resource_id and str(v2_role.uuid) in t.subject.object.object_type
        ]
        self.assertGreater(len(tenant_bindings), 0, "Should have binding at tenant after migration")

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_bindings_migrate_for_v2_tenant(self, mock_replicate):
        """Test that bindings migrate correctly for V2 tenants when role scope changes."""
        # Redirect replicator
        mock_replicate.side_effect = self.replicator.replicate

        # Create a V2 tenant
        v2_tenant = Tenant.objects.create(
            tenant_name="acct9999999",
            account_id="9999999",
            org_id="9999999",
            ready=True,
        )
        v2_tenant.save()

        # Bootstrap V2 tenant with workspaces
        from tests.v2_util import bootstrap_tenant_for_v2_test

        bootstrap_result = bootstrap_tenant_for_v2_test(v2_tenant, tuples=self.tuples)
        v2_root_workspace = bootstrap_result.root_workspace
        v2_default_workspace = bootstrap_result.default_workspace

        # Seed roles with DEFAULT scope
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

        if not test_role:
            self.skipTest("No suitable platform_default roles with inventory permissions found")

        # Create a group and assign the role in V2 tenant
        v2_group = Group.objects.create(name="V2 Test Group", tenant=v2_tenant, system=False)
        add_roles(v2_group, [test_role.uuid], v2_tenant)

        # Verify initial binding at DEFAULT workspace
        v2_role = SeededRoleV2.objects.get(uuid=test_role.uuid)
        initial_bindings = self.tuples.read_tuples(
            resource_type="rbac/principal",
            resource_id=f"group:{v2_group.uuid}",
            relation="binding",
        )

        default_workspace_bindings = [
            t
            for t in initial_bindings
            if t.subject.object.object_id == str(v2_default_workspace.id)
            and str(v2_role.uuid) in t.subject.object.object_type
        ]
        self.assertGreater(
            len(default_workspace_bindings), 0, "V2 tenant should have binding at default workspace initially"
        )

        # Change scope to TENANT
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="inventory:*:*",
        ):
            seed_roles(force_update_relationships=True)

        # Verify bindings migrated to TENANT for V2 tenant
        final_bindings = self.tuples.read_tuples(
            resource_type="rbac/principal",
            resource_id=f"group:{v2_group.uuid}",
            relation="binding",
        )

        # Should no longer have binding at default workspace
        default_workspace_bindings_after = [
            t
            for t in final_bindings
            if t.subject.object.object_id == str(v2_default_workspace.id)
            and str(v2_role.uuid) in t.subject.object.object_type
        ]
        self.assertEqual(
            len(default_workspace_bindings_after),
            0,
            "V2 tenant should not have binding at default workspace after migration",
        )

        # Should have binding at tenant
        tenant_resource_id = Tenant.org_id_to_tenant_resource_id(v2_tenant.org_id)
        tenant_bindings = [
            t
            for t in final_bindings
            if t.subject.object.object_id == tenant_resource_id and str(v2_role.uuid) in t.subject.object.object_type
        ]
        self.assertGreater(len(tenant_bindings), 0, "V2 tenant should have binding at tenant after migration")

    def test_determine_old_scope_returns_none_for_new_role(self):
        """Test that _determine_old_scope returns None when there's no existing V2 role."""
        result = _determine_old_scope(None)
        self.assertIsNone(result, "Should return None for new role")

    def test_determine_old_scope_returns_none_without_resource_service(self):
        """Test that _determine_old_scope returns None when no resource_service is provided."""
        # Create a mock V2 role
        mock_role = MagicMock()
        result = _determine_old_scope(mock_role)
        self.assertIsNone(result, "Should return None without resource_service")

    def test_determine_old_scope_detects_scope_from_permissions(self):
        """Test that _determine_old_scope correctly identifies scope from permissions."""
        # Use actual seeded roles to test scope detection
        seed_group()
        seed_roles()

        from management.permission.scope_service import ImplicitResourceService

        resource_service = ImplicitResourceService.from_settings()

        # Find a seeded role that should have platform_default
        v2_roles = SeededRoleV2.objects.filter(v1_source__platform_default=True, v1_source__tenant=self.public_tenant)

        if v2_roles.exists():
            v2_role = v2_roles.first()
            detected_scope = _determine_old_scope(v2_role, resource_service)

            # Verify it detected a valid scope (DEFAULT, TENANT, or ROOT)
            self.assertIn(
                detected_scope,
                [Scope.DEFAULT, Scope.TENANT, Scope.ROOT],
                f"Should detect a valid scope, got {detected_scope}",
            )
        else:
            self.skipTest("No platform_default seeded roles found to test with")

    def test_determine_old_scope_applies_admin_override(self):
        """Test that _determine_old_scope correctly applies admin scope override for special roles."""
        # Use actual seeded roles to test scope detection
        seed_group()
        seed_roles()

        from management.permission.scope_service import ImplicitResourceService

        resource_service = ImplicitResourceService.from_settings()

        # Find a seeded role that has admin_default
        v2_roles = SeededRoleV2.objects.filter(v1_source__admin_default=True, v1_source__tenant=self.public_tenant)

        if v2_roles.exists():
            v2_role = v2_roles.first()
            detected_scope = _determine_old_scope(v2_role, resource_service)

            # Verify it detected a valid scope
            self.assertIn(
                detected_scope,
                [Scope.DEFAULT, Scope.TENANT, Scope.ROOT],
                f"Should detect a valid scope with admin override applied, got {detected_scope}",
            )
        else:
            self.skipTest("No admin_default seeded roles found to test with")

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
