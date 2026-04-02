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

from unittest.mock import patch
from django.test import override_settings
from management.group.definer import add_roles, seed_group
from management.group.model import Group
from management.models import BindingMapping, Access, Permission, Workspace
from management.permission.scope_service import Scope
from management.role.definer import seed_roles
from management.role.model import Role
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
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="",
            DEFAULT_SCOPE_PERMISSIONS="inventory:*:*",
        ):
            # Create system role
            system_role = Role.objects.create(
                tenant=self.public_tenant,
                name="Test System Role",
                system=True,
                version=1,
            )
            Access.objects.create(role=system_role, permission=self.permission, tenant=self.public_tenant)

            # Seed to create V2 role and set parent
            seed_group()
            seed_roles()

            # Create a group and assign the system role (creates binding)
            group = Group.objects.create(name="Test Group", tenant=self.tenant, system=False)
            add_roles(group, [system_role.uuid], self.tenant)

        # Verify binding was created at DEFAULT scope (default workspace)
        binding_before = BindingMapping.objects.filter(role=system_role).first()
        self.assertIsNotNone(binding_before, "Binding should exist after adding role to group")
        self.assertEqual(binding_before.resource_type_name, "workspace", "Binding should be to a workspace")
        workspace_before = Workspace.objects.get(id=binding_before.resource_id)
        self.assertEqual(
            workspace_before.type, Workspace.Types.DEFAULT, "Binding should initially be at DEFAULT workspace"
        )

        # Step 2: Change scope to TENANT and re-seed
        with self.settings(
            ROOT_SCOPE_PERMISSIONS="",
            TENANT_SCOPE_PERMISSIONS="inventory:*:*",
            DEFAULT_SCOPE_PERMISSIONS="",
        ):
            # Update role version to trigger update
            Role.objects.filter(pk=system_role.pk).update(version=2)

            # Re-seed with force_update_relationships to apply scope change
            seed_roles(force_update_relationships=True)

        # Verify that the parent role relationship was updated (this already works)
        system_role.refresh_from_db()

        # Verify that the migration function was called when scope changed
        mock_migrate_bindings.assert_called_once()

        # Verify it was called with the correct arguments
        call_args = mock_migrate_bindings.call_args
        self.assertEqual(call_args[0][0], system_role, "Should migrate the system role")
        self.assertEqual(call_args[0][1].name, "DEFAULT", "Old scope should be DEFAULT")
        self.assertEqual(call_args[0][2].name, "TENANT", "New scope should be TENANT")
