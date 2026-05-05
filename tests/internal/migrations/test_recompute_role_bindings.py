from django.db import transaction

from internal.migrations.recompute_role_bindings import recompute_tenant_role_bindings
from management.role.model import BindingMapping
from management.role.v2_model import CustomRoleV2
from management.role_binding.model import RoleBinding
from migration_tool.in_memory_tuples import InMemoryRelationReplicator
from tests.management.role.test_dual_write import DualWriteTestCase
from django.test import override_settings

from tests.util import assert_v1_v2_tuples_fully_consistent


@override_settings(ATOMIC_RETRY_DISABLED=True, TENANT_SCOPE_PERMISSIONS="", ROOT_SCOPE_PERMISSIONS="")
class RecomputeRoleBindingsTest(DualWriteTestCase):
    def _do_test_recompute(self, delete_custom: bool, delete_v2: bool):
        system_role = self.given_v1_system_role("system role", ["rbac:*:*"])
        custom_role = self.given_v1_role("custom role", default=["rbac:*:*"])

        group, _ = self.given_group("group", ["p1"])

        def assert_assignments():
            self.assertEqual(1, BindingMapping.objects.filter(role=system_role).count())
            self.assertEqual(1, BindingMapping.objects.filter(role=custom_role).count())

            self.assertEqual(1, RoleBinding.objects.filter(role__v1_source=system_role).count())
            self.assertEqual(1, RoleBinding.objects.filter(role__v1_source=custom_role).count())

            self.expect_1_role_binding_to_workspace(
                self.default_workspace(),
                for_v2_roles=[str(system_role.uuid)],
                for_groups=[
                    str(group.uuid),
                ],
            )

            self.expect_1_role_binding_to_workspace(
                self.default_workspace(),
                for_v2_roles=[str(CustomRoleV2.objects.get(v1_source=custom_role).uuid)],
                for_groups=[str(group.uuid)],
            )

        self.given_roles_assigned_to_group(group, [system_role, custom_role])
        assert_assignments()

        target_role = custom_role if delete_custom else system_role

        if delete_v2:
            _, deleted_counts = RoleBinding.objects.filter(role__v1_source=target_role).delete()
            self.assertEqual(deleted_counts["management.RoleBinding"], 1)
        else:
            _, deleted_counts = BindingMapping.objects.filter(role=target_role).delete()
            self.assertEqual(deleted_counts["management.BindingMapping"], 1)

        recompute_tenant_role_bindings(tenant=self.tenant, replicator=InMemoryRelationReplicator(self.tuples))

        assert_assignments()
        assert_v1_v2_tuples_fully_consistent(test=self, tuples=self.tuples)

    def test_recompute_system_missing_v1(self):
        self._do_test_recompute(delete_custom=False, delete_v2=False)

    def test_recompute_custom_missing_v1(self):
        self._do_test_recompute(delete_custom=True, delete_v2=False)

    def test_recompute_system_missing_v2(self):
        self._do_test_recompute(delete_custom=False, delete_v2=True)

    def test_recompute_custom_missing_v2(self):
        self._do_test_recompute(delete_custom=True, delete_v2=True)
