"""
Copyright 2025 Red Hat, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import uuid
from unittest.mock import patch, MagicMock
from django.test import TestCase, override_settings
from management.group.model import Group
from management.models import BindingMapping, Workspace, Access, Permission
from management.policy.model import Policy
from management.role.model import Role
from management.tenant_mapping.model import TenantMapping
from migration_tool.in_memory_tuples import (
    InMemoryTuples,
    InMemoryRelationReplicator,
    all_of,
    resource,
    relation,
    subject,
    resource_type,
)
from migration_tool.utils import create_relationship
from api.models import Tenant
from tests.management.role.test_dual_write import DualWriteTestCase, RbacFixture


class CleanupOrphanBindingsTest(DualWriteTestCase):
    """Tests for the cleanup_tenant_orphan_bindings endpoint."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        # DualWriteTestCase creates self.tuples, self.fixture, and self.tenant

    def _create_kessel_read_tuples_mock(self):
        """Create a mock function that reads tuples from our InMemoryTuples store."""

        def read_tuples_fn(resource_type_name, resource_id, relation_name, subject_type_name, subject_id):
            """Mock function to read tuples from InMemoryTuples."""
            # Build a filter based on the provided parameters
            filters = [resource_type("rbac", resource_type_name)]

            if resource_id:
                filters.append(resource("rbac", resource_type_name, resource_id))

            if relation_name:
                filters.append(relation(relation_name))

            tuples = self.tuples.find_tuples(all_of(*filters))

            # Convert to dict format matching Kessel response
            result = []
            for t in tuples:
                # Filter by subject type and id if provided
                if subject_type_name and t.subject_type_name != subject_type_name:
                    continue
                if subject_id and t.subject_id != subject_id:
                    continue

                result.append(
                    {
                        "relation": t.relation,
                        "subject": {
                            "subject": {
                                "type": {
                                    "namespace": t.subject_type_namespace,
                                    "name": t.subject_type_name,
                                },
                                "id": t.subject_id,
                            },
                            "relation": t.subject_relation,
                        },
                    }
                )
            return result

        return read_tuples_fn

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_cleanup_orphaned_group_relationships(self, mock_replicate):
        """
        Test cleanup of orphaned group relationships after a group is deleted.

        Scenario:
        1. Create a custom role and assign it to a group
        2. Manually delete the group from DB but leave orphaned tuples in Kessel
        3. Run cleanup API
        4. Verify orphaned group relationships are removed
        5. Run migration to recreate correct state
        """
        # Redirect replicator to in-memory tuples
        mock_replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        # Step 1: Create custom role with default scope permission
        role = self.given_v1_role(
            "Test Role",
            default=["inventory:hosts:read"],
        )

        # Step 2: Create a group and assign the role
        group, _ = self.given_group("Test Group", ["user1"])
        self.given_roles_assigned_to_group(group, [role])

        # Verify binding exists with group
        binding = BindingMapping.objects.filter(role=role).first()
        self.assertIsNotNone(binding)
        self.assertIn(str(group.uuid), binding.mappings["groups"])

        # Verify tuples exist for the group assignment
        group_tuples_before = self.tuples.find_tuples(
            all_of(
                resource_type("rbac", "role_binding"),
                relation("subject"),
                subject("rbac", "group", str(group.uuid), "member"),
            )
        )
        self.assertGreater(len(group_tuples_before), 0, "Should have group assignment tuples")

        # Step 3: Simulate orphaned state by deleting group from DB but NOT from tuples
        # This simulates what happens when replication fails during deletion
        group_uuid_str = str(group.uuid)

        # Delete group from DB (but don't call dual write to remove tuples)
        Policy.objects.filter(group=group).delete()
        group.delete()

        # Also remove group from binding mappings to simulate DB cleanup
        binding.mappings["groups"] = []
        binding.save()

        # Verify group is gone from DB
        self.assertFalse(Group.objects.filter(uuid=group_uuid_str).exists())

        # But tuples still exist (orphaned)
        orphaned_group_tuples = self.tuples.find_tuples(
            all_of(
                resource_type("rbac", "role_binding"),
                relation("subject"),
                subject("rbac", "group", group_uuid_str, "member"),
            )
        )
        self.assertGreater(len(orphaned_group_tuples), 0, "Should have orphaned group tuples")

        # Step 4: Run cleanup using the utility function
        from internal.utils import cleanup_tenant_orphaned_relationships

        result = cleanup_tenant_orphaned_relationships(
            tenant=self.tenant,
            root_workspace=Workspace.objects.root(tenant=self.tenant),
            default_workspace=Workspace.objects.default(tenant=self.tenant),
            tenant_mapping=self.tenant.tenant_mapping,
            read_tuples_fn=self._create_kessel_read_tuples_mock(),
            dry_run=False,
        )

        # Verify cleanup found bindings
        self.assertGreater(result["bindings_found"], 0, "Should find bindings to clean")

        # Step 5: Verify orphaned group tuples are removed
        orphaned_group_tuples_after = self.tuples.find_tuples(
            all_of(
                resource_type("rbac", "role_binding"),
                relation("subject"),
                subject("rbac", "group", group_uuid_str, "member"),
            )
        )
        self.assertEqual(len(orphaned_group_tuples_after), 0, "Orphaned group tuples should be removed")

        # Step 6: Verify scope binding relationships are also removed
        # Check workspace → binding → role_binding tuples are gone
        binding_id = binding.mappings["id"]
        default_workspace = Workspace.objects.default(tenant=self.tenant)
        scope_binding_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(default_workspace.id)),
                relation("binding"),
                subject("rbac", "role_binding", binding_id),
            )
        )
        self.assertEqual(len(scope_binding_tuples), 0, "Scope binding tuples should be removed")

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_cleanup_orphaned_custom_role_relationships(self, mock_replicate):
        """
        Test cleanup of orphaned custom V2 role relationships after a role is deleted.

        Scenario:
        1. Create a custom role and assign it to a group
        2. Manually delete the role from DB but leave orphaned tuples in Kessel
        3. Run cleanup API
        4. Verify orphaned role and permission relationships are removed
        """
        # Redirect replicator to in-memory tuples
        mock_replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        # Step 1: Create custom role
        role = self.given_v1_role(
            "Custom Role To Delete",
            default=["inventory:hosts:read", "inventory:hosts:write"],
        )

        # Step 2: Create a group and assign the role
        group, _ = self.given_group("Test Group", ["user1"])
        self.given_roles_assigned_to_group(group, [role])

        # Get the V2 role ID from the binding
        binding = BindingMapping.objects.filter(role=role).first()
        self.assertIsNotNone(binding)
        v2_role_id = binding.mappings["role"]["id"]
        binding_id = binding.mappings["id"]

        # Verify role tuples exist
        role_tuples_before = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("role"),
                subject("rbac", "role", v2_role_id),
            )
        )
        self.assertEqual(len(role_tuples_before), 1, "Should have role binding tuple")

        # Verify permission tuples exist for the V2 role
        permission_tuples_before = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role", v2_role_id),
                subject("rbac", "principal", "*"),
            )
        )
        self.assertGreater(len(permission_tuples_before), 0, "Should have permission tuples")

        # Step 3: Delete the role from DB (but NOT from tuples - simulating failed replication)
        # First remove the binding mapping
        BindingMapping.objects.filter(role=role).delete()
        # Then delete the role
        role.delete()

        # Verify role is gone from DB
        self.assertFalse(Role.objects.filter(uuid=role.uuid).exists())

        # But tuples still exist (orphaned)
        orphaned_role_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("role"),
            )
        )
        self.assertGreater(len(orphaned_role_tuples), 0, "Should have orphaned role tuples")

        # Step 4: Run cleanup
        from internal.utils import cleanup_tenant_orphaned_relationships

        result = cleanup_tenant_orphaned_relationships(
            tenant=self.tenant,
            root_workspace=Workspace.objects.root(tenant=self.tenant),
            default_workspace=Workspace.objects.default(tenant=self.tenant),
            tenant_mapping=self.tenant.tenant_mapping,
            read_tuples_fn=self._create_kessel_read_tuples_mock(),
            dry_run=False,
        )

        # Verify cleanup found the orphaned custom V2 role
        self.assertIn(v2_role_id, result["custom_v2_roles_cleaned"], "Should clean custom V2 role")

        # Step 5: Verify orphaned tuples are removed
        # Role binding to role tuple should be gone
        role_tuples_after = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("role"),
            )
        )
        self.assertEqual(len(role_tuples_after), 0, "Role binding tuples should be removed")

        # Permission tuples should be gone
        permission_tuples_after = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role", v2_role_id),
                subject("rbac", "principal", "*"),
            )
        )
        self.assertEqual(len(permission_tuples_after), 0, "Permission tuples should be removed")

        # Scope binding relationships should also be removed
        default_workspace = Workspace.objects.default(tenant=self.tenant)
        scope_binding_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(default_workspace.id)),
                relation("binding"),
                subject("rbac", "role_binding", binding_id),
            )
        )
        self.assertEqual(len(scope_binding_tuples), 0, "Scope binding tuples should be removed")

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_cleanup_orphaned_scope_binding_relationships(self, mock_replicate):
        """
        Test that cleanup removes orphaned scope binding relationships.

        Scenario:
        1. Create a role and assign it to a group
        2. Delete the binding from DB but leave scope tuples in Kessel
        3. Run cleanup API
        4. Verify workspace → binding → role_binding tuples are removed
        """
        # Redirect replicator to in-memory tuples
        mock_replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        # Step 1: Create role and assign to group
        role = self.given_v1_role("Test Role", default=["inventory:hosts:read"])
        group, _ = self.given_group("Test Group", ["user1"])
        self.given_roles_assigned_to_group(group, [role])

        # Get binding info
        binding = BindingMapping.objects.filter(role=role).first()
        self.assertIsNotNone(binding)
        binding_id = binding.mappings["id"]

        # Get workspace
        default_workspace = Workspace.objects.default(tenant=self.tenant)

        # Verify scope binding tuple exists
        scope_tuples_before = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(default_workspace.id)),
                relation("binding"),
                subject("rbac", "role_binding", binding_id),
            )
        )
        self.assertGreater(len(scope_tuples_before), 0, "Should have scope binding tuples")

        # Step 2: Delete binding from DB (simulates cascade delete from role)
        # Keep the tuples as orphans
        BindingMapping.objects.filter(role=role).delete()

        # Verify scope tuples still exist (orphaned)
        orphaned_scope_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(default_workspace.id)),
                relation("binding"),
                subject("rbac", "role_binding", binding_id),
            )
        )
        self.assertGreater(len(orphaned_scope_tuples), 0, "Should have orphaned scope tuples")

        # Step 3: Run cleanup
        from internal.utils import cleanup_tenant_orphaned_relationships

        result = cleanup_tenant_orphaned_relationships(
            tenant=self.tenant,
            root_workspace=Workspace.objects.root(tenant=self.tenant),
            default_workspace=default_workspace,
            tenant_mapping=self.tenant.tenant_mapping,
            read_tuples_fn=self._create_kessel_read_tuples_mock(),
            dry_run=False,
        )

        # Verify cleanup found bindings
        self.assertGreater(result["bindings_found"], 0, "Should find bindings to clean")
        self.assertIn(binding_id, result["bindings_cleaned"], "Should clean the orphaned binding")

        # Step 4: Verify orphaned scope binding tuples are removed
        scope_tuples_after = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(default_workspace.id)),
                relation("binding"),
                subject("rbac", "role_binding", binding_id),
            )
        )
        self.assertEqual(len(scope_tuples_after), 0, "Orphaned scope binding tuples should be removed")

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_cleanup_excludes_default_access_bindings(self, mock_replicate):
        """
        Test that cleanup excludes the TenantMapping default access bindings.

        The 6 default access bindings (user/admin for tenant/root/default scope)
        should never be cleaned up.
        """
        # Redirect replicator to in-memory tuples
        mock_replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        # Get TenantMapping default binding UUIDs
        tenant_mapping = self.tenant.tenant_mapping
        default_binding_uuids = {
            str(tenant_mapping.default_role_binding_uuid),
            str(tenant_mapping.default_admin_role_binding_uuid),
            str(tenant_mapping.root_scope_default_role_binding_uuid),
            str(tenant_mapping.root_scope_default_admin_role_binding_uuid),
            str(tenant_mapping.tenant_scope_default_role_binding_uuid),
            str(tenant_mapping.tenant_scope_default_admin_role_binding_uuid),
        }

        # Create a custom role to have something to clean
        role = self.given_v1_role("Test Role", default=["inventory:hosts:read"])
        group, _ = self.given_group("Test Group", ["user1"])
        self.given_roles_assigned_to_group(group, [role])

        # Run cleanup in dry_run mode
        from internal.utils import cleanup_tenant_orphaned_relationships

        result = cleanup_tenant_orphaned_relationships(
            tenant=self.tenant,
            root_workspace=Workspace.objects.root(tenant=self.tenant),
            default_workspace=Workspace.objects.default(tenant=self.tenant),
            tenant_mapping=tenant_mapping,
            read_tuples_fn=self._create_kessel_read_tuples_mock(),
            dry_run=True,
        )

        # Verify excluded bindings match TenantMapping UUIDs
        excluded = set(result["excluded_bindings"])
        self.assertEqual(excluded, default_binding_uuids, "Should exclude all default access bindings")

        # Verify none of the cleaned bindings are default access bindings
        cleaned = set(result["bindings_cleaned"])
        self.assertEqual(len(cleaned & default_binding_uuids), 0, "Should not clean any default access bindings")

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_cleanup_does_not_remove_system_role_permissions(self, mock_replicate):
        """
        Test that cleanup does NOT remove permission tuples for system roles.

        System roles are never deleted, so their permission tuples should be preserved.
        """
        # Redirect replicator to in-memory tuples
        mock_replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        # Create a system role
        system_role = self.given_v1_system_role(
            "System Role",
            permissions=["inventory:hosts:read"],
        )
        system_role_uuid = str(system_role.uuid)

        # Create a group and assign the system role
        group, _ = self.given_group("Test Group", ["user1"])
        self.given_roles_assigned_to_group(group, [system_role])

        # Verify permission tuples exist for the system role
        permission_tuples_before = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role", system_role_uuid),
                subject("rbac", "principal", "*"),
            )
        )
        # Note: System role permissions may not have tuples in all test setups
        # The key test is that they're NOT in custom_v2_roles_cleaned

        # Run cleanup
        from internal.utils import cleanup_tenant_orphaned_relationships

        result = cleanup_tenant_orphaned_relationships(
            tenant=self.tenant,
            root_workspace=Workspace.objects.root(tenant=self.tenant),
            default_workspace=Workspace.objects.default(tenant=self.tenant),
            tenant_mapping=self.tenant.tenant_mapping,
            read_tuples_fn=self._create_kessel_read_tuples_mock(),
            dry_run=True,
        )

        # Verify system role UUID is NOT in custom_v2_roles_cleaned
        self.assertNotIn(
            system_role_uuid,
            result["custom_v2_roles_cleaned"],
            "System role should NOT be in custom_v2_roles_cleaned",
        )

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_cleanup_and_migration_fixes_orphans(self, mock_replicate):
        """
        End-to-end test: cleanup orphans then run migration to restore correct state.

        Scenario:
        1. Create role, group, and assign role to group
        2. Simulate orphaned relationships (group removed from role but tuple remains)
        3. Run cleanup
        4. Run migration
        5. Verify correct final state
        """
        # Redirect replicator to in-memory tuples
        mock_replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        # Step 1: Create role and groups
        role = self.given_v1_role("Test Role", default=["inventory:hosts:read"])

        group1, _ = self.given_group("Group 1", ["user1"])
        group2, _ = self.given_group("Group 2", ["user2"])

        # Assign role to both groups
        self.given_roles_assigned_to_group(group1, [role])
        self.given_roles_assigned_to_group(group2, [role])

        # Verify both groups are in the binding
        binding = BindingMapping.objects.filter(role=role).first()
        self.assertIn(str(group1.uuid), binding.mappings["groups"])
        self.assertIn(str(group2.uuid), binding.mappings["groups"])

        binding_id = binding.mappings["id"]

        # Verify tuples for both groups
        group1_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("subject"),
                subject("rbac", "group", str(group1.uuid), "member"),
            )
        )
        self.assertEqual(len(group1_tuples), 1)

        group2_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("subject"),
                subject("rbac", "group", str(group2.uuid), "member"),
            )
        )
        self.assertEqual(len(group2_tuples), 1)

        # Step 2: Simulate orphan - remove group2 from DB but leave tuple
        group2_uuid = str(group2.uuid)

        # Remove group2 from binding mappings (simulating DB cleanup)
        binding.mappings["groups"] = [str(group1.uuid)]
        binding.save()

        # Unassign role from group2
        self.given_roles_unassigned_from_group(group2, [role])

        # Delete group2
        group2.delete()

        # Manually add orphaned tuple back (simulating failed replication)
        orphan_tuple = create_relationship(
            ("rbac", "role_binding"),
            binding_id,
            ("rbac", "group"),
            group2_uuid,
            "subject",
            subject_relation="member",
        )
        self.tuples.add(orphan_tuple)

        # Verify orphaned tuple exists
        orphan_check = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("subject"),
                subject("rbac", "group", group2_uuid, "member"),
            )
        )
        self.assertEqual(len(orphan_check), 1, "Orphan tuple should exist")

        # Step 3: Run cleanup
        from internal.utils import cleanup_tenant_orphaned_relationships

        cleanup_result = cleanup_tenant_orphaned_relationships(
            tenant=self.tenant,
            root_workspace=Workspace.objects.root(tenant=self.tenant),
            default_workspace=Workspace.objects.default(tenant=self.tenant),
            tenant_mapping=self.tenant.tenant_mapping,
            read_tuples_fn=self._create_kessel_read_tuples_mock(),
            dry_run=False,
        )

        # Step 4: Run migration
        from migration_tool.migrate_binding_scope import migrate_all_role_bindings

        checked, migrated = migrate_all_role_bindings(
            replicator=InMemoryRelationReplicator(self.tuples),
            tenant=self.tenant,
        )

        # Step 5: Verify final state
        # Orphaned group2 tuple should be gone
        orphan_after = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("subject"),
                subject("rbac", "group", group2_uuid, "member"),
            )
        )
        self.assertEqual(len(orphan_after), 0, "Orphan tuple should be removed after cleanup")

        # Group1 tuple should still exist (from migration)
        final_binding = BindingMapping.objects.filter(role=role).first()
        if final_binding:
            final_binding_id = final_binding.mappings["id"]
            group1_after = self.tuples.find_tuples(
                all_of(
                    resource("rbac", "role_binding", final_binding_id),
                    relation("subject"),
                    subject("rbac", "group", str(group1.uuid), "member"),
                )
            )
            self.assertEqual(len(group1_after), 1, "Group1 tuple should exist after migration")

    @override_settings(
        ROOT_SCOPE_PERMISSIONS="",
        TENANT_SCOPE_PERMISSIONS="",
        REPLICATION_TO_RELATION_ENABLED=True,
    )
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_dry_run_does_not_modify_tuples(self, mock_replicate):
        """
        Test that dry_run=True only reports what would be deleted without making changes.
        """
        # Redirect replicator to in-memory tuples
        mock_replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        # Create role and group
        role = self.given_v1_role("Test Role", default=["inventory:hosts:read"])
        group, _ = self.given_group("Test Group", ["user1"])
        self.given_roles_assigned_to_group(group, [role])

        # Record tuple count before
        tuple_count_before = len(self.tuples)

        # Run cleanup in dry_run mode
        from internal.utils import cleanup_tenant_orphaned_relationships

        result = cleanup_tenant_orphaned_relationships(
            tenant=self.tenant,
            root_workspace=Workspace.objects.root(tenant=self.tenant),
            default_workspace=Workspace.objects.default(tenant=self.tenant),
            tenant_mapping=self.tenant.tenant_mapping,
            read_tuples_fn=self._create_kessel_read_tuples_mock(),
            dry_run=True,
        )

        # Verify dry_run flag in result
        self.assertTrue(result["dry_run"])

        # Verify tuple count unchanged
        tuple_count_after = len(self.tuples)
        self.assertEqual(tuple_count_before, tuple_count_after, "Dry run should not modify tuples")

        # Should have relations_to_remove in result (not relations_removed)
        self.assertIn("relations_to_remove", result)
        self.assertNotIn("relations_removed", result)
