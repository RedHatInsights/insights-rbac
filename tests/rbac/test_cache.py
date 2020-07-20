#
# Copyright 2020 Red Hat, Inc.
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
"""Test the caching system."""

from unittest.mock import patch

from django.db import connection
from django.test import TestCase

from management.models import Access, Group, Policy, Principal, ResourceDefinition, Role
from api.models import Tenant


class AccessCacheTest(TestCase):
    def setUp(self):
        """Set up AccessCache tests."""
        super().setUp()
        self.tenant = Tenant.objects.create(schema_name="acct12345")
        connection.set_schema("acct12345")
        self.principal_a = Principal.objects.create(username="principal_a")
        self.principal_b = Principal.objects.create(username="principal_b")
        self.group_a = Group.objects.create(name="group_a", platform_default=True)
        self.group_b = Group.objects.create(name="group_b")
        self.policy_a = Policy.objects.create(name="policy_a")
        self.policy_b = Policy.objects.create(name="policy_b")
        self.role_a = Role.objects.create(name="role_a")
        self.role_b = Role.objects.create(name="role_b")

    def tearDown(self):
        connection.set_schema_to_public()

    @patch("management.group.model.AccessCache.delete_policy")
    def test_group_cache_add_remove_signals(self, cache):
        """Test signals attached to Groups"""
        cache.reset_mock()

        # If a Principal is added to a group
        self.group_a.principals.add(self.principal_a)

        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)

        cache.reset_mock()
        # If a Group is added to a Principal
        self.principal_b.group.add(self.group_a)
        cache.asset_called_once()
        cache.asset_called_once_with(self.principal_b.uuid)

        cache.reset_mock()
        # If a Principal is removed from a group
        self.group_a.principals.remove(self.principal_a)
        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)

        cache.reset_mock()
        # If a Group is removed from a Principal
        self.principal_b.group.remove(self.group_a)
        cache.asset_called_once()
        cache.asset_called_once_with(self.principal_b.uuid)

    @patch("management.group.model.AccessCache.delete_policy")
    def test_group_cache_clear_signals(self, cache):
        # If all groups are removed from a Principal
        self.group_a.principals.add(self.principal_a, self.principal_b)
        cache.reset_mock()
        self.principal_a.group.clear()
        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)

        cache.reset_mock()
        # If all Principals are removed from a Group
        self.group_a.principals.clear()
        cache.asset_called_once()
        cache.asset_called_once_with(self.principal_b.uuid)

    @patch("management.group.model.AccessCache.delete_policy")
    def test_group_cache_delete_group_signal(self, cache):
        self.group_a.principals.add(self.principal_a)
        cache.reset_mock()
        self.group_a.delete()
        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)

    @patch("management.policy.model.AccessCache.delete_all_policies_for_tenant")
    @patch("management.policy.model.AccessCache.delete_policy")
    def test_policy_cache_group_signals(self, cache_delete, cache_delete_all):
        """Test signals attached to Groups"""
        self.group_a.principals.add(self.principal_a)
        self.group_b.principals.add(self.principal_b)
        cache_delete.reset_mock()

        # If a policy has its group set
        self.policy_a.group = self.group_a
        self.policy_a.save()
        cache_delete_all.asset_called_once()

        cache_delete.reset_mock()
        # If a policy has its group changed
        self.policy_a.group = self.group_b
        self.policy_a.save()
        cache_delete.asset_called_once()
        cache_delete.asset_called_once_with(self.principal_b.uuid)

        cache_delete.reset_mock()
        # If a policy is deleted
        self.policy_a.delete()
        cache_delete.assert_called_once()
        cache_delete.assert_called_once_with(self.principal_b.uuid)

    @patch("management.policy.model.AccessCache.delete_all_policies_for_tenant")
    @patch("management.policy.model.AccessCache.delete_policy")
    def test_policy_cache_add_remove_roles_signals(self, cache_delete, cache_delete_all):
        """Test signals attached to Policy/Roles"""
        self.group_b.principals.add(self.principal_b)
        self.policy_a.group = self.group_a
        self.policy_a.save()
        self.policy_b.group = self.group_b
        self.policy_b.save()
        cache_delete.reset_mock()

        # If a Role is added to a platform default group's Policy
        self.policy_a.roles.add(self.role_a)
        self.policy_a.save()
        cache_delete_all.asset_called_once()

        cache_delete.reset_mock()
        # If a Policy is added to a Role
        self.role_b.policies.add(self.policy_a)
        cache_delete.asset_called_once()
        cache_delete.asset_called_once_with(self.principal_b.uuid)

        cache_delete.reset_mock()
        # If a Role is removed from a platform default group's Policy
        self.policy_a.roles.remove(self.role_a)
        self.policy_a.save()
        cache_delete_all.asset_called_once()

        cache_delete.reset_mock()
        # If a Role is removed from a Policy
        self.policy_b.roles.remove(self.role_b)
        cache_delete.assert_called_once()
        cache_delete.assert_called_once_with(self.principal_b.uuid)

        cache_delete.reset_mock()
        # If a Policy is removed from a Role
        self.role_b.policies.remove(self.policy_b)
        cache_delete.asset_called_once()
        cache_delete.asset_called_once_with(self.principal_b.uuid)

    @patch("management.policy.model.AccessCache.delete_policy")
    def test_policy_cache_clear_signals(self, cache):
        self.group_a.principals.add(self.principal_a)
        self.group_b.principals.add(self.principal_b)
        self.policy_a.group = self.group_a
        self.policy_a.save()
        self.policy_b.group = self.group_b
        self.policy_b.save()
        self.policy_a.roles.add(self.role_a)
        self.policy_b.roles.add(self.role_b)
        cache.reset_mock()

        # If all policies are removed from a role
        self.role_a.policies.clear()
        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)

        cache.reset_mock()
        # If all Roles are removed from a Policy
        self.policy_b.roles.clear()
        cache.asset_called_once()
        cache.asset_called_once_with(self.principal_b.uuid)

    @patch("management.role.model.AccessCache.delete_policy")
    def test_policy_cache_change_delete_roles_signals(self, cache):
        self.group_a.principals.add(self.principal_a)
        self.group_b.principals.add(self.principal_b)
        self.policy_a.group = self.group_a
        self.policy_a.save()
        self.policy_b.group = self.group_b
        self.policy_b.save()
        self.policy_a.roles.add(self.role_a)
        self.policy_b.roles.add(self.role_b)
        cache.reset_mock()

        # If a role is changed
        self.role_a.version += 1
        self.role_a.save()
        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)

        cache.reset_mock()
        # If Access is added
        self.access_a = Access.objects.create(perm="foo:*:*", role=self.role_a)
        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)

        cache.reset_mock()
        # If ResourceDefinition is added
        self.rd_a = ResourceDefinition.objects.create(access=self.access_a)
        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)

        cache.reset_mock()
        # If ResourceDefinition is destroyed
        self.rd_a.delete()
        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)

        cache.reset_mock()
        # If Access is destroyed
        self.access_a.delete()
        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)

        cache.reset_mock()
        # If Role is destroyed
        self.role_a.delete()
        cache.assert_called_once()
        cache.assert_called_once_with(self.principal_a.uuid)
