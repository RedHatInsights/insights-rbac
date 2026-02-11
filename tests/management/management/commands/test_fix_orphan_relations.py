from unittest.mock import patch

from django.core.management import call_command

from management.relation_replicator.noop_replicator import NoopReplicator
from management.tenant_service import V2TenantBootstrapService
from migration_tool.in_memory_tuples import InMemoryRelationReplicator
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
