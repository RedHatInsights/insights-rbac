from unittest.mock import patch

from django.core.management import call_command

from management.relation_replicator.noop_replicator import NoopReplicator
from management.tenant_mapping.model import TenantMapping
from management.tenant_service import V2TenantBootstrapService
from migration_tool.in_memory_tuples import InMemoryRelationReplicator, all_of, resource, relation, subject
from migration_tool.migrate_binding_scope import migrate_all_role_bindings
from tests.management.role.test_dual_write import DualWriteTestCase

from django.test.utils import override_settings

from tests.v2_util import assert_v2_roles_consistent, make_read_tuples_mock


@override_settings(
    V2_BOOTSTRAP_TENANT=True,
    REPLICATON_TO_RELATION_ENABLED=True,
)
class TestRemoveOrphanRelations(DualWriteTestCase):
    @patch("internal.migrations.remove_orphan_relations.iterate_tuples_from_kessel")
    def _do_fix_orphans(self, iterate_mock):
        iterate_mock.side_effect = make_read_tuples_mock(self.tuples)
        call_command("fix_orphan_relations", "--all")

    def _expect_v2_consistent(self):
        assert_v2_roles_consistent(test=self, tuples=self.tuples)

    def setUp(self):
        super().setUp()

        # The orphan removal script requires a proper workspace hierarchy.
        V2TenantBootstrapService(replicator=InMemoryRelationReplicator(self.tuples)).bootstrap_tenant(
            self.tenant, force=True
        )

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_fix_incorrect_scope_binding(self, replicate):
        replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        role = self.given_v1_system_role("system role", ["rbac:roles:read"])
        g, _ = self.given_group("group", ["u1"])

        self.given_roles_assigned_to_group(g, [role])

        # Everything is normal so far, so relations should be consistent.
        self._expect_v2_consistent()

        # It is incorrect to run the scope migration with a noop replicator.
        #
        # For system role bindings with a single subject, the role binding will be deleted, and a new role binding will
        # be created (with a new UUID), but this will not be replicated.
        #
        # See RHCLOUD-44659.
        migrate_all_role_bindings(replicator=NoopReplicator(), tenant=self.tenant)

        # Relations show now be inconsistent.
        with self.assertRaises(AssertionError):
            self._expect_v2_consistent()

        # This should remove the orphan relations and re-replicate all existing relations.
        self._do_fix_orphans()

        # After running the command, relations should now be consistent.
        self._expect_v2_consistent()

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_custom_default_group_access(self, replicate):
        replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        self.given_custom_default_group(replicator=NoopReplicator())
        self._expect_v2_consistent()

        tenant_mapping: TenantMapping = self.tenant.tenant_mapping

        def assert_user_count(count: int):
            self.assertEqual(
                count,
                self.tuples.count_tuples(
                    all_of(
                        resource("rbac", "workspace", self.default_workspace()),
                        relation("binding"),
                        subject("rbac", "role_binding", str(tenant_mapping.default_role_binding_uuid)),
                    )
                ),
            )

        def assert_admin_count(count: int):
            self.assertEqual(
                count,
                self.tuples.count_tuples(
                    all_of(
                        resource("rbac", "workspace", self.default_workspace()),
                        relation("binding"),
                        subject("rbac", "role_binding", str(tenant_mapping.default_admin_role_binding_uuid)),
                    )
                ),
            )

        # We expect the admin role bindings to still be bound to the appropriate resources.
        assert_admin_count(1)

        # Since creating the custom default group was a no-op, the default user access binding should still be bound.
        assert_user_count(1)

        self._do_fix_orphans()

        # Running the migration should not affect the admin access binding.
        assert_admin_count(1)

        # The orphaned user access binding should have been removed.
        assert_user_count(0)
