#
# Copyright 2019 Red Hat, Inc.
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
"""Test the Management queryset helpers."""
from unittest.mock import Mock

from django.db import connection
from django.db.models.aggregates import Count
from django.test import TestCase
from django.urls import reverse
from management.group.model import Group
from management.policy.model import Policy
from management.principal.model import Principal
from management.role.model import Role
from management.querysets import (PRINCIPAL_SCOPE,
                                  SCOPE_KEY,
                                  get_group_queryset,
                                  get_policy_queryset,
                                  get_role_queryset)
from rest_framework import serializers

from api.models import Tenant, User


class QuerySetTest(TestCase):
    """Test the Management queryset helper functions."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.tenant = Tenant.objects.get(schema_name='test')
        except:
            cls.tenant = Tenant(schema_name='test')
            cls.tenant.save(verbosity=0)

        connection.set_tenant(cls.tenant)

    @classmethod
    def tearDownClass(cls):
        connection.set_schema_to_public()
        cls.tenant.delete()

    def _create_groups(self):
        """Setup groups for tests."""
        Group.objects.create(name='group1')
        Group.objects.create(name='group2')
        Group.objects.create(name='group3')
        Group.objects.create(name='group4')
        Group.objects.create(name='group5')

    def _create_roles(self):
        """Setup roles for tests."""
        Role.objects.create(name='role1')
        Role.objects.create(name='role2')
        Role.objects.create(name='role3')
        Role.objects.create(name='role4')
        Role.objects.create(name='role5')

    def _create_policies(self):
        """Setup policies for tests."""
        Policy.objects.create(name='policy1')
        Policy.objects.create(name='policy2')
        Policy.objects.create(name='policy3')
        Policy.objects.create(name='policy4')
        Policy.objects.create(name='policy5')

    def test_get_group_queryset_admin(self):
        """Test get_group_queryset as an admin."""
        self._create_groups()
        user = Mock(spec=User, admin=True)
        req = Mock(user=user, query_params={})
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_user_group_queryset_admin(self):
        """Test get_group_queryset as an admin."""
        self._create_groups()
        principal = Principal.objects.create(username='test_user')
        group = Group.objects.first()
        group.principals.add(principal)
        identity_header = {
            'decoded': {
                'identity': {
                    'user': {
                        'username': 'test_user'
                    }
                }
            }
        }

        user = Mock(spec=User, admin=True, identity_header=identity_header)
        req = Mock(user=user, query_params={'username': 'test_user'})
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_group_queryset_get_users_own_groups(self):
        """Test get_group_queryset to get a users own groups."""
        self._create_groups()
        principal = Principal.objects.create(username='test_user')
        group = Group.objects.first()
        group.principals.add(principal)
        identity_header = {
            'decoded': {
                'identity': {
                    'user': {
                        'username': 'test_user'
                    }
                }
            }
        }
        user = Mock(spec=User, admin=False, identity_header=identity_header)
        req = Mock(user=user, method='GET', query_params={'username': 'test_user'}, path=reverse('group-list'))
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_group_queryset_get_users_other_users_groups(self):
        """Test get_group_queryset to get a users other users groups."""
        self._create_groups()
        principal = Principal.objects.create(username='test_user')
        group = Group.objects.first()
        group.principals.add(principal)
        identity_header = {
            'decoded': {
                'identity': {
                    'user': {
                        'username': 'test_user'
                    }
                }
            }
        }
        user = Mock(spec=User, admin=False, identity_header=identity_header)
        req = Mock(user=user, method='GET', query_params={'username': 'test_user2'})
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_role_queryset_admin(self):
        """Test get_role_queryset as an admin."""
        self._create_roles()
        user = Mock(spec=User, admin=True)
        req = Mock(user=user, query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 5)
        self.assertIsNotNone(queryset.last().accessCount)

    def test_get_role_queryset_get_all(self):
        """Test get_role_queryset as a user with all access."""
        self._create_roles()
        access = {
            'role': {
                'read': ['*']
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='GET', query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_role_queryset_get_some(self):
        """Test get_role_queryset as a user with one role access."""
        self._create_roles()
        access = {
            'role': {
                'read': [Role.objects.first().uuid]
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='GET', query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_role_queryset_get_none(self):
        """Test get_role_queryset as a user with no access."""
        self._create_roles()
        access = {
            'role': {
                'read': []
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='GET', query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_role_queryset_post_all(self):
        """Test get_role_queryset as a user with all access."""
        self._create_roles()
        access = {
            'role': {
                'write': ['*']
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='PUT', query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_role_queryset_put_some(self):
        """Test get_role_queryset as a user with one role access."""
        self._create_roles()
        access = {
            'role': {
                'write': [Role.objects.first().uuid]
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='PUT', query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_role_queryset_put_none(self):
        """Test get_role_queryset as a user with no access."""
        self._create_roles()
        access = {
            'role': {
                'write': []
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='PUT', query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_policy_queryset_admin(self):
        """Test get_policy_queryset as an admin."""
        self._create_policies()
        user = Mock(spec=User, admin=True)
        req = Mock(user=user, query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_policy_queryset_get_all(self):
        """Test get_policy_queryset as a user with all access."""
        self._create_policies()
        access = {
            'policy': {
                'read': ['*']
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='GET', query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_policy_queryset_get_some(self):
        """Test get_policy_queryset as a user with one role access."""
        self._create_policies()
        access = {
            'policy': {
                'read': [Policy.objects.first().uuid]
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='GET', query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_policy_queryset_get_none(self):
        """Test get_policy_queryset as a user with no access."""
        self._create_policies()
        access = {
            'policy': {
                'read': []
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='GET', query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_policy_queryset_post_all(self):
        """Test get_policy_queryset as a user with all access."""
        self._create_policies()
        access = {
            'policy': {
                'write': ['*']
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='PUT', query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_policy_queryset_put_some(self):
        """Test get_policy_queryset as a user with one role access."""
        self._create_policies()
        access = {
            'policy': {
                'write': [Policy.objects.first().uuid]
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='PUT', query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_policy_queryset_put_none(self):
        """Test get_policy_queryset as a user with no access."""
        self._create_policies()
        access = {
            'policy': {
                'write': []
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='PUT', query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_policy_queryset_scope_put_none(self):
        """Test get_policy_queryset for a principal scope with put."""
        self._create_policies()
        access = {
            'policy': {
                'write': []
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='PUT', query_params={SCOPE_KEY: PRINCIPAL_SCOPE})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_policy_queryset_bad_scope(self):
        """Test get_policy_queryset with a bad scope."""
        self._create_policies()
        access = {
            'policy': {
                'read': ['*']
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='GET', query_params={SCOPE_KEY: 'bad'})
        with self.assertRaises(serializers.ValidationError):
            get_policy_queryset(req)
