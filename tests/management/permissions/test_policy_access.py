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
"""Tests for Policy Access Permissions."""

from unittest.mock import Mock

from django.test import TestCase

from api.models import User
from management.permissions.policy_access import PolicyAccessPermission


class PolicyAccessPermissionTest(TestCase):
    """Test the policy access permission."""

    def test_has_perm_admin(self):
        """Test that an admin user can execute."""
        user = Mock(spec=User, admin=True)
        req = Mock(user=user)
        accessPerm = PolicyAccessPermission()
        result = accessPerm.has_permission(request=req, view=None)
        self.assertTrue(result)

    def test_no_perm_not_admin_get(self):
        """Test that a user with no access cannot execute a GET."""
        access = {
            'group': {
                'read': [],
                'write': []
            },
            'role': {
                'read': [],
                'write': []
            },
            'policy': {
                'read': [],
                'write': []
            }
        }
        user = Mock(spec=User, admin=False, access=access,)
        req = Mock(user=user, method='GET')
        accessPerm = PolicyAccessPermission()
        result = accessPerm.has_permission(request=req, view=None)
        self.assertFalse(result)

    def test_no_perm_not_admin_post(self):
        """Test that a user with no access cannot execute a POST."""
        access = {
            'group': {
                'read': [],
                'write': []
            },
            'role': {
                'read': [],
                'write': []
            },
            'policy': {
                'read': [],
                'write': []
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='POST')
        accessPerm = PolicyAccessPermission()
        result = accessPerm.has_permission(request=req, view=None)
        self.assertFalse(result)

    def test_has_perm_not_admin_post(self):
        """Test that a user with read access cannot execute a POST."""
        access = {
            'group': {
                'read': [],
                'write': []
            },
            'role': {
                'read': [],
                'write': []
            },
            'policy': {
                'read': ['*'],
                'write': []
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='POST')
        accessPerm = PolicyAccessPermission()
        result = accessPerm.has_permission(request=req, view=None)
        self.assertFalse(result)

    def test_has_perm_not_admin_post_success(self):
        """Test that a user with read access can execute a POST."""
        access = {
            'group': {
                'read': [],
                'write': []
            },
            'role': {
                'read': [],
                'write': []
            },
            'policy': {
                'read': ['*'],
                'write': ['*']
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='POST')
        accessPerm = PolicyAccessPermission()
        result = accessPerm.has_permission(request=req, view=None)
        self.assertTrue(result)

    def test_has_perm_not_admin_get(self):
        """Test that a user with read access can execute a GET."""
        access = {
            'group': {
                'read': [],
                'write': []
            },
            'role': {
                'read': [],
                'write': []
            },
            'policy': {
                'read': ['*'],
                'write': []
            }
        }
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method='GET', query_params={})
        accessPerm = PolicyAccessPermission()
        result = accessPerm.has_permission(request=req, view=None)
        self.assertTrue(result)
