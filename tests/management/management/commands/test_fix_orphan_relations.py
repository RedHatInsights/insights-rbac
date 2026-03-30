import itertools
import uuid
from typing import Optional
from unittest.mock import patch

from django.core.management import call_command

from api.models import Tenant
from management.group.platform import GlobalPolicyIdService
from management.permission.scope_service import Scope
from management.relation_replicator.noop_replicator import NoopReplicator
from management.role.definer import seed_roles
from management.role.model import BindingMapping
from management.role.platform import platform_v2_role_uuid_for
from management.role_binding.service import RoleBindingService, CreateBindingRequest
from management.tenant_mapping.model import TenantMapping, DefaultAccessType
from management.tenant_mapping.v2_activation import ensure_v2_write_activated
from management.tenant_service import V2TenantBootstrapService
from migration_tool.in_memory_tuples import (
    InMemoryRelationReplicator,
    all_of,
    resource,
    relation,
    subject,
    resource_type,
)
from migration_tool.migrate_binding_scope import migrate_all_role_bindings
from migration_tool.models import V2role, V2rolebinding
from tests.management.role.test_dual_write import DualWriteTestCase

from django.test.utils import override_settings

from tests.util import assert_v1_v2_tuples_fully_consistent
from tests.v2_util import make_read_tuples_mock, bootstrap_tenant_for_v2_test


@override_settings(
    V2_BOOTSTRAP_TENANT=True,
    REPLICATION_TO_RELATION_ENABLED=True,
)
@override_settings(ATOMIC_RETRY_DISABLED=True)
class TestRemoveOrphanRelations(DualWriteTestCase):

    def _do_fix_orphans(self, args: Optional[list[str]] = None):
        if args is None:
            args = ["--all"]

        with patch("internal.migrations.remove_orphan_relations.iterate_tuples_from_kessel") as iterate_mock:
            iterate_mock.side_effect = make_read_tuples_mock(self.tuples)
            call_command("fix_orphan_relations", *args)

    def _expect_v2_consistent(self):
        assert_v1_v2_tuples_fully_consistent(test=self, tuples=self.tuples)

    def setUp(self):
        super().setUp()

        # The orphan removal script requires a proper workspace hierarchy.
        bootstrap_tenant_for_v2_test(self.tenant, tuples=self.tuples)

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

        # Check that a binding for the role still exists, but that it is not the one that exists in the database.

        self.expect_1_role_binding_to_workspace(
            self.default_workspace(), for_v2_roles=[str(role.uuid)], for_groups=[str(g.uuid)]
        )

        binding = BindingMapping.objects.filter(role=role).get()

        self.assertEqual(
            0,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", self.default_workspace()),
                    subject("rbac", "role_binding", binding.mappings["id"]),
                    relation("binding"),
                )
            ),
        )

        # Relations should now be inconsistent.
        with self.assertRaises(AssertionError):
            self._expect_v2_consistent()

        # This should remove the orphan relations and re-replicate all existing relations.
        self._do_fix_orphans()

        # After running the command, relations should now be consistent.
        self._expect_v2_consistent()

        # There should still be one role binding for the role, but now it should be the one that exists in the database.

        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", self.default_workspace()),
                    subject("rbac", "role_binding", binding.mappings["id"]),
                    relation("binding"),
                )
            ),
        )

        self.expect_1_role_binding_to_workspace(
            self.default_workspace(), for_v2_roles=[str(role.uuid)], for_groups=[str(g.uuid)]
        )

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

        # We expect the default admin access binding to be bound to the default workspace.
        assert_admin_count(1)

        # Since creating the custom default group was a no-op, the default user access binding should still be bound
        # to the default workspace.
        assert_user_count(1)

        self._do_fix_orphans()

        # Running the migration should not affect the default admin access binding.
        assert_admin_count(1)

        # The default user access binding should no longer be bound to the default workspace.
        assert_user_count(0)

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_limit(self, replicate):
        replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        # Ensure we know exactly what tenants exist.
        Tenant.objects.exclude(tenant_name="public").exclude(pk=self.tenant.pk).delete()

        t1 = self.test_tenant
        t2 = (
            V2TenantBootstrapService(InMemoryRelationReplicator(self.tuples))
            .new_bootstrapped_tenant(org_id="t2")
            .tenant
        )

        def create_orphan(tenant: Tenant):
            self.switch_tenant(tenant)
            self.given_custom_default_group(replicator=NoopReplicator())

        def has_default_binding(tenant: Tenant):
            self.switch_tenant(tenant)
            return (
                self.tuples.count_tuples(
                    all_of(
                        resource("rbac", "workspace", self.default_workspace()),
                        relation("binding"),
                        subject("rbac", "role_binding", str(tenant.tenant_mapping.default_role_binding_uuid)),
                    )
                )
                == 1
            )

        # The tenants should start with the correct default binding relations.
        self.assertTrue(has_default_binding(t1))
        self.assertTrue(has_default_binding(t2))

        # Orphan the default workspace -> default binding relations.
        create_orphan(t1)
        create_orphan(t2)

        # The default workspace -> default binding relations should not have been affected (i.e. they should now be
        # orphans).
        self.assertTrue(has_default_binding(t1))
        self.assertTrue(has_default_binding(t2))

        self._do_fix_orphans(["--tenant-limit=1"])

        # After running with --tenant-limit=1, exactly one tenant should have been fixed (but we don't necessarily know
        # which one).
        self.assertEqual(has_default_binding(t1) + has_default_binding(t2), 1)

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_reused_platform_default_role(self, replicate):
        replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        seed_roles()
        g, _ = self.given_group("test group", ["p1"])

        initial_tuples = set(self.tuples)

        orphaned_binding = V2rolebinding(
            id=str(uuid.uuid4()),
            resource=self.default_workspace_resource(),
            role=V2role.for_system_role(
                id=str(
                    platform_v2_role_uuid_for(
                        DefaultAccessType.USER, Scope.DEFAULT, policy_service=GlobalPolicyIdService()
                    )
                )
            ),
            groups=[str(g.uuid)],
        )

        self.tuples.write(add=orphaned_binding.as_tuples(), remove=[])
        self.assertGreater(len(self.tuples), len(initial_tuples))

        # Test removing an orphaned role binding that references a V2 platform role. (This caused an error in a prior
        # version.)
        self._do_fix_orphans()

        # We should successfully be back where we started (with the orphan binding removed).
        self.assertEqual(set(self.tuples), initial_tuples)

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_preserve_v2(self, replicate):
        replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        system_role = self.given_v1_system_role("system role", ["rbac:*:*"])
        group, _ = self.given_group("group", ["p1"])
        service = RoleBindingService(tenant=self.tenant, replicator=InMemoryRelationReplicator(self.tuples))

        ensure_v2_write_activated(self.tenant)

        service.batch_create(
            [
                CreateBindingRequest(
                    role_id=str(system_role.uuid),
                    resource_type="workspace",
                    resource_id=self.default_workspace(),
                    subject_type="group",
                    subject_id=str(group.uuid),
                )
            ]
        )

        # Check that the role binding we just created exists.
        self.expect_1_role_binding_to_workspace(
            self.default_workspace(), for_v2_roles=[str(system_role.uuid)], for_groups=[str(group.uuid)]
        )

        # Using the V2 interface should not have created a BindingMapping.
        self.assertEqual(BindingMapping.objects.count(), 0)

        self._do_fix_orphans()

        # We should not have removed the role binding, despite there not being a BindingMapping for it.
        self.expect_1_role_binding_to_workspace(
            self.default_workspace(), for_v2_roles=[str(system_role.uuid)], for_groups=[str(group.uuid)]
        )

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @override_settings(ROOT_SCOPE_PERMISSIONS="", TENANT_SCOPE_PERMISSIONS="")
    def test_v2_role_binding_deleted(self, replicate):
        replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        target_role = self.given_v1_system_role("target role", ["rbac:*:*"])
        alternate_role = self.given_v1_system_role("alternate role", ["rbac:*:*"])
        group, _ = self.given_group("group", ["p1"])

        self.given_roles_assigned_to_group(group, [target_role])

        # We are going to test the scenario where, for a given role binding X, a BindingMapping model exists for X,
        # and X exists in Kessel, but no RoleBinding model exists for X.
        #
        # This could happen in the following scenario:
        # * A role binding X is created for a V1 tenant (also creating BindingMapping and RoleBinding models).
        # * The tenant is converted to V2.
        # * X is deleted (deleting the RoleBinding model but not the BindingMapping model).
        # * The removal of X has not yet replicated to Kessel.
        # * The migration runs, finding X in Kessel and a BindingMapping model for X, but no RoleBinding model.
        #
        # To replicate this scenario in a test, we will simply drop the replication event for its removal with
        # NoopReplicator.

        service = RoleBindingService(tenant=self.tenant, replicator=NoopReplicator())
        ensure_v2_write_activated(self.tenant)

        def assert_role_bindings(v1_count: int, v2_count: int, tuples_count: int):
            self.assertEqual(v1_count, BindingMapping.objects.filter(role=target_role).count())

            self.assertEqual(
                v2_count,
                len(
                    {
                        b.binding
                        for b in itertools.chain.from_iterable(
                            [
                                s.role_binding_entries.all()
                                for s in service.get_role_bindings_by_subject(
                                    {
                                        "resource_type": "workspace",
                                        "resource_id": self.default_workspace(),
                                        "subject_type": "group",
                                        "subject_id": str(group.uuid),
                                    }
                                )
                            ]
                        )
                        if b.binding.role.v1_source == target_role
                    }
                ),
            )

            self.expect_role_bindings_to_workspace(
                num=tuples_count,
                workspace=self.default_workspace(),
                for_v2_roles=[str(target_role.uuid)],
                for_groups=[str(group.uuid)],
            )

        assert_role_bindings(v1_count=1, v2_count=1, tuples_count=1)

        # We can't simply remove the role because RoleBindingService does not currently permit updating to an empty set
        # of roles (see RHCLOUD-46139).
        service.update_role_bindings_for_subject(
            resource_type="workspace",
            resource_id=self.default_workspace(),
            subject_type="group",
            subject_id=str(group.uuid),
            role_ids=[str(alternate_role.uuid)],
        )

        assert_role_bindings(v1_count=1, v2_count=0, tuples_count=1)

        self._do_fix_orphans()

        # We should have removed the tuples for the orphaned role binding.
        assert_role_bindings(v1_count=1, v2_count=0, tuples_count=0)

        # We should also have replicated the dropped role binding for the new role.
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource_type("rbac", "role_binding"),
                    relation("role"),
                    subject("rbac", "role", str(alternate_role.uuid)),
                )
            ),
        )
