"""Tests for fix_duplicate_role_binding_uuids management command."""

import uuid
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase, override_settings

from management.tenant_mapping.model import TenantMapping
from tests.management.role.test_dual_write import RbacFixture


class TestFixDuplicateRoleBindingUUIDs(TestCase):
    """Test the fix_duplicate_role_binding_uuids management command."""

    def setUp(self):
        """Set up test fixtures."""
        self.fixture = RbacFixture()
        # Create multiple tenants with TenantMapping
        self.tenants = [self.fixture.new_tenant(org_id=f"test-org-{i}") for i in range(5)]
        self.mappings = [tenant.mapping for tenant in self.tenants]

    def _call_command(self, *args, **kwargs):
        """Helper to call the management command and capture output."""
        out = StringIO()
        err = StringIO()
        call_command("fix_duplicate_role_binding_uuids", *args, stdout=out, stderr=err, **kwargs)
        return out.getvalue(), err.getvalue()

    def _set_duplicate_uuids(self):
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

        for mapping in self.mappings:
            for field_name, duplicate_uuid in duplicate_uuids.items():
                setattr(mapping, field_name, duplicate_uuid)
            mapping.save()

        return duplicate_uuids

    @override_settings(ENV_NAME="stage")
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
