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
"""Tests for populate_default_role_bindings management command."""
from io import StringIO

from django.core.management import call_command

from api.models import Tenant
from management.group.definer import seed_group
from management.models import RoleBinding, RoleBindingGroup
from management.relation_replicator.noop_replicator import NoopReplicator
from management.role.definer import seed_roles
from management.role.v2_model import PlatformRoleV2
from management.tenant_service.v2 import V2TenantBootstrapService
from tests.management.role.test_dual_write import DualWriteTestCase, RbacFixture


class PopulateDefaultRoleBindingsCommandTest(DualWriteTestCase):
    """Test cases for populate_default_role_bindings command."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        seed_group()
        seed_roles()  # Seed platform roles needed for RoleBindings
        self.bootstrap_service = V2TenantBootstrapService(NoopReplicator())

    def _invoke(self, *args):
        """Invoke the command and return output."""
        out = StringIO()
        call_command("populate_default_role_bindings", *args, stdout=out)
        return out.getvalue()

    def _create_default_groups_for_tenant(self, bootstrapped):
        """Helper method to create default groups for a bootstrapped tenant."""
        from management.models import Group
        from management.tenant_mapping.model import DefaultAccessType

        user_group_uuid = bootstrapped.mapping.group_uuid_for(DefaultAccessType.USER)
        admin_group_uuid = bootstrapped.mapping.group_uuid_for(DefaultAccessType.ADMIN)

        Group.objects.create(
            uuid=user_group_uuid,
            name="Default access",
            tenant=bootstrapped.tenant,
            platform_default=True,
            system=True,
        )
        Group.objects.create(
            uuid=admin_group_uuid,
            name="Default admin access",
            tenant=bootstrapped.tenant,
            admin_default=True,
            system=True,
        )

    def test_dry_run_single_tenant(self):
        """Test dry-run mode with a single tenant."""
        bootstrapped = self.fixture.new_tenant(org_id="12345")

        # Create default groups (required for the command to process the tenant)
        self._create_default_groups_for_tenant(bootstrapped)

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(tenant=bootstrapped.tenant).delete()

        output = self._invoke("--tenant", "12345", "--dry-run")
        self.assertIn("DRY RUN MODE", output)
        self.assertIn("Would process", output)
        self.assertIn("1 tenant(s)", output)

        # Verify no RoleBindings were created
        self.assertEqual(RoleBinding.objects.filter(tenant=bootstrapped.tenant).count(), 0)

    def test_populate_single_tenant(self):
        """Test populating role bindings for a single tenant."""
        bootstrapped = self.fixture.new_tenant(org_id="12345")

        # Create default groups (required for RoleBindingGroups)
        self._create_default_groups_for_tenant(bootstrapped)

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(tenant=bootstrapped.tenant).delete()

        output = self._invoke("--tenant", "12345")
        self.assertIn("Successfully processed", output)
        self.assertIn("1 tenant(s)", output)

        # Verify RoleBindings were created
        # Should have 6 RoleBindings: 3 scopes × 2 access types (USER, ADMIN)
        role_bindings = RoleBinding.objects.filter(tenant=bootstrapped.tenant)
        self.assertEqual(role_bindings.count(), 6)

        # Verify RoleBindingGroups were created
        role_binding_groups = RoleBindingGroup.objects.filter(binding__tenant=bootstrapped.tenant)
        self.assertEqual(role_binding_groups.count(), 6)

    def test_populate_multiple_tenants(self):
        """Test populating role bindings for multiple tenants."""
        bootstrapped1 = self.fixture.new_tenant(org_id="11111")
        bootstrapped2 = self.fixture.new_tenant(org_id="22222")
        bootstrapped3 = self.fixture.new_tenant(org_id="33333")

        # Mark tenants as ready (required for command to process them)
        # Create default groups for each tenant (required for RoleBindingGroups)
        from management.models import Group
        from management.tenant_mapping.model import DefaultAccessType

        for bootstrapped in [bootstrapped1, bootstrapped2, bootstrapped3]:
            bootstrapped.tenant.ready = True
            bootstrapped.tenant.save()

            user_group_uuid = bootstrapped.mapping.group_uuid_for(DefaultAccessType.USER)
            admin_group_uuid = bootstrapped.mapping.group_uuid_for(DefaultAccessType.ADMIN)

            Group.objects.create(
                uuid=user_group_uuid,
                name="Default access",
                tenant=bootstrapped.tenant,
                platform_default=True,
                system=True,
            )
            Group.objects.create(
                uuid=admin_group_uuid,
                name="Default admin access",
                tenant=bootstrapped.tenant,
                admin_default=True,
                system=True,
            )

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(
            tenant__in=[bootstrapped1.tenant, bootstrapped2.tenant, bootstrapped3.tenant]
        ).delete()

        output = self._invoke()
        self.assertIn("Successfully processed", output)

        # Verify RoleBindings were created for all tenants
        for bootstrapped in [bootstrapped1, bootstrapped2, bootstrapped3]:
            role_bindings = RoleBinding.objects.filter(tenant=bootstrapped.tenant)
            self.assertEqual(role_bindings.count(), 6, f"Tenant {bootstrapped.tenant.org_id}")

    def test_skip_unbootstrapped_tenant(self):
        """Test that unbootstrapped tenants are skipped."""
        unbootstrapped = self.fixture.new_unbootstrapped_tenant(org_id="99999")

        output = self._invoke()
        self.assertIn("Skipping", output)
        self.assertIn("99999", output)

        # Verify no RoleBindings were created
        self.assertEqual(RoleBinding.objects.filter(tenant=unbootstrapped).count(), 0)

    def test_tenant_not_found(self):
        """Test error handling when tenant is not found."""
        output = self._invoke("--tenant", "nonexistent")
        self.assertIn("not found", output)

    def test_idempotent_operation(self):
        """Test that running the command multiple times is idempotent."""
        bootstrapped = self.fixture.new_tenant(org_id="12345")

        # Create default groups (required for RoleBindingGroups)
        self._create_default_groups_for_tenant(bootstrapped)

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(tenant=bootstrapped.tenant).delete()

        # Run command first time
        output1 = self._invoke("--tenant", "12345")
        self.assertIn("Successfully processed", output1)
        count1 = RoleBinding.objects.filter(tenant=bootstrapped.tenant).count()

        # Run command second time
        output2 = self._invoke("--tenant", "12345")
        self.assertIn("Successfully processed", output2)
        count2 = RoleBinding.objects.filter(tenant=bootstrapped.tenant).count()

        # Counts should be the same
        self.assertEqual(count1, count2)
        self.assertEqual(count1, 6)

    def test_batch_processing(self):
        """Test that tenants are processed in batches."""
        # Create multiple tenants
        tenants = [self.fixture.new_tenant(org_id=f"batch-{i}") for i in range(60)]

        # Mark tenants as ready (required for command to process them)
        # Create default groups for each tenant (required for RoleBindingGroups)
        from management.models import Group
        from management.tenant_mapping.model import DefaultAccessType

        for bootstrapped in tenants:
            bootstrapped.tenant.ready = True
            bootstrapped.tenant.save()

            user_group_uuid = bootstrapped.mapping.group_uuid_for(DefaultAccessType.USER)
            admin_group_uuid = bootstrapped.mapping.group_uuid_for(DefaultAccessType.ADMIN)

            Group.objects.create(
                uuid=user_group_uuid,
                name="Default access",
                tenant=bootstrapped.tenant,
                platform_default=True,
                system=True,
            )
            Group.objects.create(
                uuid=admin_group_uuid,
                name="Default admin access",
                tenant=bootstrapped.tenant,
                admin_default=True,
                system=True,
            )

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(tenant__in=[t.tenant for t in tenants]).delete()

        output = self._invoke()
        self.assertIn("batch", output.lower())
        self.assertIn("Successfully processed", output)

        # Verify all tenants were processed
        for bootstrapped in tenants:
            role_bindings = RoleBinding.objects.filter(tenant=bootstrapped.tenant)
            self.assertEqual(role_bindings.count(), 6)


class BulkCreateDefaultRoleBindingsTest(DualWriteTestCase):
    """Test cases for _bulk_create_default_role_bindings method."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        seed_group()
        seed_roles()  # Seed platform roles needed for RoleBindings
        self.bootstrap_service = V2TenantBootstrapService(NoopReplicator())

    def _create_default_groups_for_tenant(self, bootstrapped):
        """Helper method to create default groups for a bootstrapped tenant."""
        from management.models import Group
        from management.tenant_mapping.model import DefaultAccessType

        user_group_uuid = bootstrapped.mapping.group_uuid_for(DefaultAccessType.USER)
        admin_group_uuid = bootstrapped.mapping.group_uuid_for(DefaultAccessType.ADMIN)

        Group.objects.create(
            uuid=user_group_uuid,
            name="Default access",
            tenant=bootstrapped.tenant,
            platform_default=True,
            system=True,
        )
        Group.objects.create(
            uuid=admin_group_uuid,
            name="Default admin access",
            tenant=bootstrapped.tenant,
            admin_default=True,
            system=True,
        )

    def test_bulk_create_single_tenant(self):
        """Test bulk creation for a single tenant."""
        bootstrapped = self.fixture.new_tenant(org_id="12345")

        # Create the default groups that are referenced in TenantMapping
        self._create_default_groups_for_tenant(bootstrapped)

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(tenant=bootstrapped.tenant).delete()

        # Call bulk method
        self.bootstrap_service._bulk_create_default_role_bindings([(bootstrapped.tenant, bootstrapped.mapping)])

        # Verify RoleBindings were created
        role_bindings = RoleBinding.objects.filter(tenant=bootstrapped.tenant)
        self.assertEqual(role_bindings.count(), 6)

        # Verify RoleBindingGroups were created
        role_binding_groups = RoleBindingGroup.objects.filter(binding__tenant=bootstrapped.tenant)
        self.assertEqual(role_binding_groups.count(), 6)

    def test_bulk_create_multiple_tenants(self):
        """Test bulk creation for multiple tenants."""
        bootstrapped1 = self.fixture.new_tenant(org_id="11111")
        bootstrapped2 = self.fixture.new_tenant(org_id="22222")
        bootstrapped3 = self.fixture.new_tenant(org_id="33333")

        # Create the default groups for all tenants
        for bootstrapped in [bootstrapped1, bootstrapped2, bootstrapped3]:
            self._create_default_groups_for_tenant(bootstrapped)

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(
            tenant__in=[bootstrapped1.tenant, bootstrapped2.tenant, bootstrapped3.tenant]
        ).delete()

        # Call bulk method
        tenants_with_mappings = [
            (bootstrapped1.tenant, bootstrapped1.mapping),
            (bootstrapped2.tenant, bootstrapped2.mapping),
            (bootstrapped3.tenant, bootstrapped3.mapping),
        ]
        self.bootstrap_service._bulk_create_default_role_bindings(tenants_with_mappings)

        # Verify RoleBindings were created for all tenants
        for bootstrapped in [bootstrapped1, bootstrapped2, bootstrapped3]:
            role_bindings = RoleBinding.objects.filter(tenant=bootstrapped.tenant)
            self.assertEqual(role_bindings.count(), 6, f"Tenant {bootstrapped.tenant.org_id}")

    def test_bulk_create_empty_list(self):
        """Test bulk creation with empty list."""
        # Should not raise an error
        self.bootstrap_service._bulk_create_default_role_bindings([])

        # Verify no RoleBindings were created
        self.assertEqual(RoleBinding.objects.count(), 0)

    def test_bulk_create_skips_missing_workspaces(self):
        """Test that tenants with missing workspaces are skipped."""
        bootstrapped = self.fixture.new_tenant(org_id="12345")

        # Delete workspaces (children first due to PROTECT foreign key)
        from management.models import Workspace

        # Delete default workspace first (child), then root workspace (parent)
        Workspace.objects.filter(tenant=bootstrapped.tenant, type=Workspace.Types.DEFAULT).delete()
        Workspace.objects.filter(tenant=bootstrapped.tenant, type=Workspace.Types.ROOT).delete()

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(tenant=bootstrapped.tenant).delete()

        # Call bulk method - should skip tenant with missing workspaces
        self.bootstrap_service._bulk_create_default_role_bindings([(bootstrapped.tenant, bootstrapped.mapping)])

        # Verify no RoleBindings were created
        self.assertEqual(RoleBinding.objects.filter(tenant=bootstrapped.tenant).count(), 0)

    def test_bulk_create_skips_missing_groups(self):
        """Test that tenants with missing groups are skipped."""
        bootstrapped = self.fixture.new_tenant(org_id="12345")

        # Delete groups
        from management.models import Group

        Group.objects.filter(tenant=bootstrapped.tenant).delete()

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(tenant=bootstrapped.tenant).delete()

        # Call bulk method - should skip tenant with missing groups
        self.bootstrap_service._bulk_create_default_role_bindings([(bootstrapped.tenant, bootstrapped.mapping)])

        # Verify no RoleBindings were created
        self.assertEqual(RoleBinding.objects.filter(tenant=bootstrapped.tenant).count(), 0)

    def test_bulk_create_updates_existing_bindings(self):
        """Test that existing RoleBindings are updated."""
        bootstrapped = self.fixture.new_tenant(org_id="12345")

        # Create default groups (required for bulk method to process the tenant)
        self._create_default_groups_for_tenant(bootstrapped)

        # Create a RoleBinding manually with wrong resource_id
        from management.permission.scope_service import Scope
        from management.tenant_mapping.model import DefaultAccessType

        mapping = bootstrapped.mapping
        role_binding_uuid = mapping.default_role_binding_uuid_for(DefaultAccessType.USER, Scope.DEFAULT)
        platform_role = PlatformRoleV2.objects.first()

        existing_binding = RoleBinding.objects.create(
            uuid=role_binding_uuid,
            tenant=bootstrapped.tenant,
            role=platform_role,
            resource_type="workspace",
            resource_id=str(bootstrapped.tenant.id),  # Wrong resource_id
        )

        # Call bulk method
        self.bootstrap_service._bulk_create_default_role_bindings([(bootstrapped.tenant, bootstrapped.mapping)])

        # Verify the binding was updated
        existing_binding.refresh_from_db()
        # The resource_id should be updated to the correct default workspace ID
        from management.models import Workspace

        default_workspace = Workspace.objects.default(tenant=bootstrapped.tenant)
        self.assertEqual(existing_binding.resource_id, str(default_workspace.id))

    def test_bulk_create_idempotent(self):
        """Test that bulk creation is idempotent."""
        bootstrapped = self.fixture.new_tenant(org_id="12345")

        # Create default groups (required for RoleBindingGroups)
        self._create_default_groups_for_tenant(bootstrapped)

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(tenant=bootstrapped.tenant).delete()

        # Call bulk method first time
        self.bootstrap_service._bulk_create_default_role_bindings([(bootstrapped.tenant, bootstrapped.mapping)])
        count1 = RoleBinding.objects.filter(tenant=bootstrapped.tenant).count()

        # Call bulk method second time
        self.bootstrap_service._bulk_create_default_role_bindings([(bootstrapped.tenant, bootstrapped.mapping)])
        count2 = RoleBinding.objects.filter(tenant=bootstrapped.tenant).count()

        # Counts should be the same
        self.assertEqual(count1, count2)
        self.assertEqual(count1, 6)

    def test_bulk_create_all_scopes(self):
        """Test that RoleBindings are created for all scopes."""
        bootstrapped = self.fixture.new_tenant(org_id="12345")

        # Create default groups (required for RoleBindingGroups)
        self._create_default_groups_for_tenant(bootstrapped)

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(tenant=bootstrapped.tenant).delete()

        # Call bulk method
        self.bootstrap_service._bulk_create_default_role_bindings([(bootstrapped.tenant, bootstrapped.mapping)])

        # Verify RoleBindings exist for all scopes
        from management.permission.scope_service import Scope
        from management.tenant_mapping.model import DefaultAccessType

        role_bindings = RoleBinding.objects.filter(tenant=bootstrapped.tenant)
        binding_uuids = {str(binding.uuid) for binding in role_bindings}

        for access_type in DefaultAccessType:
            for scope in Scope:
                expected_uuid = bootstrapped.mapping.default_role_binding_uuid_for(access_type, scope)
                self.assertIn(
                    str(expected_uuid),
                    binding_uuids,
                    f"Missing RoleBinding for access_type={access_type.value}, scope={scope.name}",
                )

    def test_bulk_create_all_access_types(self):
        """Test that RoleBindings are created for both USER and ADMIN access types."""
        bootstrapped = self.fixture.new_tenant(org_id="12345")

        # Create the default groups that are referenced in TenantMapping
        # These groups need to exist for RoleBindingGroups to be created
        self._create_default_groups_for_tenant(bootstrapped)

        from management.tenant_mapping.model import DefaultAccessType

        user_group_uuid = bootstrapped.mapping.group_uuid_for(DefaultAccessType.USER)
        admin_group_uuid = bootstrapped.mapping.group_uuid_for(DefaultAccessType.ADMIN)

        # Verify workspaces exist (required for bulk method)
        from management.models import Workspace

        root_workspace = Workspace.objects.filter(tenant=bootstrapped.tenant, type=Workspace.Types.ROOT).first()
        default_workspace = Workspace.objects.filter(tenant=bootstrapped.tenant, type=Workspace.Types.DEFAULT).first()
        self.assertIsNotNone(root_workspace, "Root workspace should exist")
        self.assertIsNotNone(default_workspace, "Default workspace should exist")

        # Delete any existing RoleBindings
        RoleBinding.objects.filter(tenant=bootstrapped.tenant).delete()

        # Call bulk method
        self.bootstrap_service._bulk_create_default_role_bindings([(bootstrapped.tenant, bootstrapped.mapping)])

        # Verify RoleBindings were created (6 total: 3 scopes × 2 access types)
        role_bindings = RoleBinding.objects.filter(tenant=bootstrapped.tenant)
        self.assertEqual(role_bindings.count(), 6)

        # Verify RoleBindingGroups exist for both access types (if groups exist)
        user_group_bindings = RoleBindingGroup.objects.filter(
            binding__tenant=bootstrapped.tenant, group__uuid=user_group_uuid
        )
        admin_group_bindings = RoleBindingGroup.objects.filter(
            binding__tenant=bootstrapped.tenant, group__uuid=admin_group_uuid
        )

        # If groups exist, RoleBindingGroups should be created
        # Note: This test verifies the groups are found and linked correctly
        self.assertEqual(user_group_bindings.count(), 3, "Should have 3 bindings for USER group")
        self.assertEqual(admin_group_bindings.count(), 3, "Should have 3 bindings for ADMIN group")
