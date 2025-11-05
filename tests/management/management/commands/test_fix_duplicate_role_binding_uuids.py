"""Tests for fix_duplicate_role_binding_uuids management command."""

import uuid
from io import StringIO
from typing import Iterable
from unittest.mock import patch

from django.conf import settings
from django.core.management import call_command

from management.tenant_mapping.model import TenantMapping
from management.workspace.model import Workspace
from migration_tool.in_memory_tuples import (
    all_of,
    resource,
    relation,
    subject,
    InMemoryRelationReplicator,
)
from tests.management.role.test_dual_write import DualWriteTestCase


class TestFixDuplicateRoleBindingUUIDs(DualWriteTestCase):
    """Test the fix_duplicate_role_binding_uuids management command."""

    def _call_command(self, *args, **kwargs):
        """Helper to call the management command and capture output."""
        out = StringIO()
        err = StringIO()
        call_command("fix_duplicate_role_binding_uuids", *args, stdout=out, stderr=err, **kwargs)
        return out.getvalue(), err.getvalue()

    def _set_duplicate_uuids(self, mappings: Iterable[TenantMapping]) -> dict[str, uuid.UUID]:
        """
        Simulate the bug from migration 0070 by setting the same UUID for all mappings.

        Returns a dict of the duplicate UUIDs that were set.
        """
        duplicate_uuids = {
            "root_scope_default_role_binding_uuid": uuid.uuid4(),
            "root_scope_default_admin_role_binding_uuid": uuid.uuid4(),
            "tenant_scope_default_admin_role_binding_uuid": uuid.uuid4(),
            "tenant_scope_default_role_binding_uuid": uuid.uuid4(),
        }

        for mapping in mappings:
            for field_name, duplicate_uuid in duplicate_uuids.items():
                setattr(mapping, field_name, duplicate_uuid)

            mapping.save()

        return duplicate_uuids

    def test_batch_processing(self):
        """Test that batch processing works correctly."""
        # Create more tenants to test batching
        for i in range(10):
            self.fixture.new_tenant(org_id=f"batch-test-org-{i}")

        # Set stage duplicate UUID for all tenants
        duplicated = uuid.uuid4()
        for mapping in TenantMapping.objects.all():
            mapping.root_scope_default_role_binding_uuid = duplicated
            mapping.save()

        # Run with small batch size
        out, err = self._call_command("--batch-size", "3")

        # Should process in multiple batches
        self.assertIn("Processing batch", err)
        self.assertIn("Successfully updated", err)

        # All should have unique UUIDs
        total_mappings = TenantMapping.objects.count()
        for field_name in [
            "root_scope_default_role_binding_uuid",
            "root_scope_default_admin_role_binding_uuid",
            "tenant_scope_default_admin_role_binding_uuid",
            "tenant_scope_default_role_binding_uuid",
        ]:
            values = list(TenantMapping.objects.values_list(field_name, flat=True))
            self.assertEqual(
                len(set(values)),
                total_mappings,
                f"All {field_name} values should be unique",
            )

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_bootstrap_relations(self, replicate):
        replicate.side_effect = InMemoryRelationReplicator(self.tuples).replicate

        tenants = [self.fixture.new_tenant(org_id=f"test-org-{i}").tenant for i in range(10)]
        self.tuples.clear()

        def assert_duplicated_bindings(uuids: dict[str, uuid.UUID], num: int):
            for tenant in tenants:
                root_id = str(Workspace.objects.root(tenant=tenant).id)
                tenant_id = tenant.tenant_resource_id()

                self.assertEqual(
                    num,
                    self.tuples.count_tuples(
                        all_of(
                            resource("rbac", "workspace", root_id),
                            relation("binding"),
                            subject("rbac", "role_binding", uuids["root_scope_default_role_binding_uuid"]),
                        )
                    ),
                )

                self.assertEqual(
                    num,
                    self.tuples.count_tuples(
                        all_of(
                            resource("rbac", "workspace", root_id),
                            relation("binding"),
                            subject("rbac", "role_binding", uuids["root_scope_default_admin_role_binding_uuid"]),
                        )
                    ),
                )

                self.assertEqual(
                    num,
                    self.tuples.count_tuples(
                        all_of(
                            resource("rbac", "tenant", tenant_id),
                            relation("binding"),
                            subject("rbac", "role_binding", uuids["tenant_scope_default_role_binding_uuid"]),
                        )
                    ),
                )

                self.assertEqual(
                    num,
                    self.tuples.count_tuples(
                        all_of(
                            resource("rbac", "tenant", tenant_id),
                            relation("binding"),
                            subject("rbac", "role_binding", uuids["tenant_scope_default_admin_role_binding_uuid"]),
                        )
                    ),
                )

        # Replicate the situation after the broken migration, where each existing tenant wsa given the same role
        # binding IDs, then they were all forcibly re-bootstrapped.
        uuids = self._set_duplicate_uuids([t.tenant_mapping for t in tenants])
        call_command("bootstrap_tenants", "--force", *[f"--org-id={t.org_id}" for t in tenants])

        # After forcibly bootstrapping the tenants, we expect that each resource will be bound to the
        # appropriate duplicated binding UUID.
        assert_duplicated_bindings(uuids, 1)

        self._call_command("--replicate-removal")

        # The duplicated bindings should have been removed.
        assert_duplicated_bindings(uuids, 0)

        call_command("bootstrap_tenants", "--force", *[f"--org-id={t.org_id}" for t in tenants])

        # Re-bootstrapping should not somehow restore any duplicated bindings.
        assert_duplicated_bindings(uuids, 0)

        # Re-bootstrapping should restore each tenant's normal default access tuples.
        for tenant in tenants:
            root = Workspace.objects.root(tenant=tenant)

            self.expect_1_role_binding_to_workspace(
                workspace=str(root.id),
                for_v2_roles=[settings.SYSTEM_DEFAULT_ROOT_WORKSPACE_ROLE_UUID],
                for_groups=[str(tenant.tenant_mapping.default_group_uuid)],
            )

            self.expect_1_role_binding_to_workspace(
                workspace=str(root.id),
                for_v2_roles=[settings.SYSTEM_ADMIN_ROOT_WORKSPACE_ROLE_UUID],
                for_groups=[str(tenant.tenant_mapping.default_admin_group_uuid)],
            )

            self.expect_1_role_binding_to_tenant(
                org_id=tenant.org_id,
                for_v2_roles=[settings.SYSTEM_DEFAULT_TENANT_ROLE_UUID],
                for_groups=[str(tenant.tenant_mapping.default_group_uuid)],
            )

            self.expect_1_role_binding_to_tenant(
                org_id=tenant.org_id,
                for_v2_roles=[settings.SYSTEM_ADMIN_TENANT_ROLE_UUID],
                for_groups=[str(tenant.tenant_mapping.default_admin_group_uuid)],
            )
