from django.test import TestCase

from api.models import Tenant
from management.tenant_service.v2 import (
    lock_tenant_for_bootstrap,
    try_lock_tenants_for_bootstrap,
    TenantNotBootstrappedError,
)
from tests.management.role.test_dual_write import RbacFixture


class V2TenantBootstrapTests(TestCase):
    fixture: RbacFixture

    def setUp(self):
        self.fixture = RbacFixture()

    def test_try_lock_tenants(self):
        """Test that try_lock_tenants_for_bootstrap returns the correct values."""
        unbootstrapped_tenant = self.fixture.new_unbootstrapped_tenant("23456")

        bootstrapped_tenant_data = self.fixture.new_tenant("22345")
        bootstrapped_tenant = bootstrapped_tenant_data.tenant

        custom_group_tenant_data = self.fixture.new_tenant("34567")
        custom_group_tenant = custom_group_tenant_data.tenant
        custom_group = self.fixture.custom_default_group(custom_group_tenant)

        locks = try_lock_tenants_for_bootstrap([unbootstrapped_tenant, bootstrapped_tenant, custom_group_tenant])

        self.assertIsNone(locks[unbootstrapped_tenant])

        self.assertIsNotNone(locks[bootstrapped_tenant])
        self.assertEqual(bootstrapped_tenant_data.mapping, locks[bootstrapped_tenant].tenant_mapping)
        self.assertIsNone(locks[bootstrapped_tenant].custom_default_group)

        self.assertIsNotNone(locks[custom_group_tenant])
        self.assertEqual(custom_group_tenant_data.mapping, locks[custom_group_tenant].tenant_mapping)
        self.assertEqual(custom_group, locks[custom_group_tenant].custom_default_group)

    def test_try_lock_public(self):
        """Test that try_lock_tenants_for_bootstrap refuses to lock the public tenant."""
        self.assertRaises(ValueError, try_lock_tenants_for_bootstrap, [self.fixture.public_tenant])

    def test_try_lock_new(self):
        """Test that try_lock_tenants_for_bootstrap refuses to lock an unsaved tenant."""
        self.assertRaises(ValueError, try_lock_tenants_for_bootstrap, [Tenant()])

    def test_lock_tenant(self):
        """Test that lock_tenant_for_bootstrap fails to lock an unbootstrapped tenant."""
        unbootstrapped = self.fixture.new_unbootstrapped_tenant("12345")
        self.assertRaises(TenantNotBootstrappedError, lock_tenant_for_bootstrap, unbootstrapped)
