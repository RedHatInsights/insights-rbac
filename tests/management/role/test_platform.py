from unittest import TestCase

from api.models import Tenant
from management.group.definer import seed_group
from management.models import Group
from management.role.platform import GlobalPolicyIdCache, DefaultGroupNotAvailableError
from uuid import UUID


class GlobalPolicyIdCacheTests(TestCase):
    policy_cache: GlobalPolicyIdCache
    platform_default: Group
    admin_default: Group

    def setUp(self):
        self.policy_cache = GlobalPolicyIdCache()
        self.platform_default, self.admin_default = seed_group()

    def test_get_platform_default(self):
        """Test that platform_default_policy_uuid returns the expected UUID."""
        # It should not matter whether the admin default group exists.
        self.admin_default.delete()

        expected_id = self.platform_default.policies.get().uuid

        try:
            actual_id = self.policy_cache.platform_default_policy_uuid()
            self.assertIsInstance(actual_id, UUID)
            self.assertEqual(expected_id, actual_id)
        except DefaultGroupNotAvailableError as e:
            self.fail(f"Expected to be able to retrieve group, but got: {e}")

    def test_get_admin_default(self):
        """Test that admin_default_policy_uuid returns the expected UUID."""
        # It should not matter whether the platform default group exists.
        self.platform_default.delete()

        expected_id = self.admin_default.policies.get().uuid

        try:
            actual_id = self.policy_cache.admin_default_policy_uuid()
            self.assertIsInstance(actual_id, UUID)
            self.assertEqual(expected_id, actual_id)
        except DefaultGroupNotAvailableError as e:
            self.fail(f"Expected to be able to retrieve group, but got: {e}")

    def test_platform_nonexistent(self):
        """Test that platform_default_policy_uuid throws when a platform default group does not exist."""
        self.platform_default.delete()

        with self.assertRaises(DefaultGroupNotAvailableError):
            self.policy_cache.platform_default_policy_uuid()

    def test_admin_nonexistent(self):
        """Test that platform_default_policy_uuid throws when an admin default group does not exist."""
        self.admin_default.delete()

        with self.assertRaises(DefaultGroupNotAvailableError):
            self.policy_cache.admin_default_policy_uuid()

    def test_platform_cached(self):
        """Test that platform_default_policy_uuid caches its return value."""
        original = self.policy_cache.platform_default_policy_uuid()

        self.platform_default.delete()
        self.assertEqual(original, self.policy_cache.platform_default_policy_uuid())

    def test_admin_cached(self):
        """Test that admin_default_policy_uuid caches its return value."""
        original = self.policy_cache.admin_default_policy_uuid()

        self.admin_default.delete()
        self.assertEqual(original, self.policy_cache.admin_default_policy_uuid())
