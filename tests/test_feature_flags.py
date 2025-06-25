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
"""Test the feature flags module."""
from django.test import TestCase
from feature_flags import FEATURE_FLAGS


class FeatureFlagsTest(TestCase):
    """Tests feature flags functions."""

    def test_feature_flags_client(self):
        """Test that we can initialize feature flags with defaults."""
        client = FEATURE_FLAGS.client
        FEATURE_FLAGS.initialize()
        self.assertEqual(client.unleash_url, "http://localhost:4242/api")
        self.assertEqual(client.unleash_app_name, "rbac")
        self.assertEqual(FEATURE_FLAGS.is_enabled("foo"), False)

    def test_feature_flags_client_not_initialized(self):
        """Test that we can still check flags without a client."""
        client = FEATURE_FLAGS.client = None
        self.assertEqual(client, None)
        self.assertEqual(FEATURE_FLAGS.is_enabled("foo"), False)

    def test_feature_flags_client_not_initialized_custom_fallback(self):
        """Test that we can still check flags without a client but a custom fallback."""
        client = FEATURE_FLAGS.client = None
        self.assertEqual(client, None)
        self.assertEqual(FEATURE_FLAGS.is_enabled("foo", fallback_function=self._truthy_fallback), True)

    def _truthy_fallback(self, feature_name, context):
        return True
