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
from django.test import TestCase
from management.group.definer import seed_group
from management.models import Group
from management.group.platform import GlobalPolicyIdService, DefaultGroupNotAvailableError
from uuid import UUID


class GlobalPolicyIdServiceTests(TestCase):
    policy_service: GlobalPolicyIdService
    platform_default: Group
    admin_default: Group

    def setUp(self):
        self.policy_service = GlobalPolicyIdService()
        self.platform_default, self.admin_default = seed_group()

    def test_get_platform_default(self):
        """Test that platform_default_policy_uuid returns the expected UUID."""
        # It should not matter whether the admin default group exists.
        self.admin_default.delete()

        expected_id = self.platform_default.policies.get().uuid

        try:
            actual_id = self.policy_service.platform_default_policy_uuid()
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
            actual_id = self.policy_service.admin_default_policy_uuid()
            self.assertIsInstance(actual_id, UUID)
            self.assertEqual(expected_id, actual_id)
        except DefaultGroupNotAvailableError as e:
            self.fail(f"Expected to be able to retrieve group, but got: {e}")

    def test_platform_nonexistent(self):
        """Test that platform_default_policy_uuid throws when a platform default group does not exist."""
        self.platform_default.delete()

        with self.assertRaises(DefaultGroupNotAvailableError):
            self.policy_service.platform_default_policy_uuid()

    def test_admin_nonexistent(self):
        """Test that platform_default_policy_uuid throws when an admin default group does not exist."""
        self.admin_default.delete()

        with self.assertRaises(DefaultGroupNotAvailableError):
            self.policy_service.admin_default_policy_uuid()

    def test_platform_cached(self):
        """Test that platform_default_policy_uuid caches its return value."""
        original = self.policy_service.platform_default_policy_uuid()

        self.platform_default.delete()
        self.assertEqual(original, self.policy_service.platform_default_policy_uuid())

    def test_admin_cached(self):
        """Test that admin_default_policy_uuid caches its return value."""
        original = self.policy_service.admin_default_policy_uuid()

        self.admin_default.delete()
        self.assertEqual(original, self.policy_service.admin_default_policy_uuid())

    def test_shared(self):
        """Test the cache used in shared() is appropriately reused and cleared."""
        shared = GlobalPolicyIdService.shared()

        # Two values from shared() without an intervening clear_shared() should be equal to each other.
        self.assertEqual(shared, GlobalPolicyIdService.shared())

        original_platform = shared.platform_default_policy_uuid()
        original_admin = shared.admin_default_policy_uuid()

        self.platform_default.delete()
        self.admin_default.delete()

        shared = GlobalPolicyIdService.shared()

        # The new instance from shared() should use the same cache, even after the underlying groups are deleted.
        self.assertEqual(original_platform, shared.platform_default_policy_uuid())
        self.assertEqual(original_admin, shared.admin_default_policy_uuid())

        GlobalPolicyIdService.clear_shared()
        after_clear = GlobalPolicyIdService.shared()

        self.assertNotEqual(shared, after_clear)

        # The new instance should not share the previous instance's cache.
        self.assertRaises(DefaultGroupNotAvailableError, after_clear.platform_default_policy_uuid)
        self.assertRaises(DefaultGroupNotAvailableError, after_clear.admin_default_policy_uuid)
