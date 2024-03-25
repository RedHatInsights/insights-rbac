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
"""Tests for Group Access Permissions."""

from unittest.mock import Mock

from django.test import TestCase

from api.models import User
from management.permissions.group_access import GroupAccessPermission


class GroupAccessPermissionTest(TestCase):
    """Test the group access permission."""

    def setUp(self):
        self.mocked_view = Mock()
        self.mocked_view.action = "mocked-action"
        self.mocked_view.basename = "mocked-view"

    def test_has_perm_admin(self):
        """Test that an admin user can execute."""
        user = Mock(spec=User, admin=True)
        req = Mock(user=user)
        accessPerm = GroupAccessPermission()
        result = accessPerm.has_permission(request=req, view=self.mocked_view)
        self.assertTrue(result)

    def test_no_perm_not_admin_get(self):
        """Test that a user with no access cannot execute a GET."""
        access = {
            "group": {"read": [], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }
        user = Mock(spec=User, admin=False, access=access, identity_header={})
        req = Mock(user=user, method="GET")
        accessPerm = GroupAccessPermission()
        result = accessPerm.has_permission(request=req, view=self.mocked_view)
        self.assertFalse(result)

    def test_no_perm_not_admin_post(self):
        """Test that a user with no access cannot execute a POST."""
        access = {
            "group": {"read": [], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }
        user = Mock(spec=User, admin=False, access=access, identity_header={})
        req = Mock(user=user, method="POST")
        accessPerm = GroupAccessPermission()
        result = accessPerm.has_permission(request=req, view=self.mocked_view)
        self.assertFalse(result)

    def test_has_perm_not_admin_post(self):
        """Test that a user with read access cannot execute a POST."""
        access = {
            "group": {"read": ["*"], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }
        user = Mock(spec=User, admin=False, access=access, identity_header={})
        req = Mock(user=user, method="POST")
        accessPerm = GroupAccessPermission()
        result = accessPerm.has_permission(request=req, view=self.mocked_view)
        self.assertFalse(result)

    def test_has_perm_not_admin_post_success(self):
        """Test that a user with read access can execute a POST."""
        access = {
            "group": {"read": ["*"], "write": ["*"]},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }
        user = Mock(spec=User, admin=False, access=access, identity_header={})
        req = Mock(user=user, method="POST")
        accessPerm = GroupAccessPermission()
        result = accessPerm.has_permission(request=req, view=self.mocked_view)
        self.assertTrue(result)

    def test_has_perm_not_admin_get(self):
        """Test that a user with read access can execute a GET."""
        access = {
            "group": {"read": ["*"], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }
        user = Mock(spec=User, admin=False, access=access, identity_header={})
        req = Mock(user=user, method="GET", query_params={})
        accessPerm = GroupAccessPermission()
        result = accessPerm.has_permission(request=req, view=self.mocked_view)
        self.assertTrue(result)

    def test_no_perm_not_admin_get_own_groups(self):
        """Test that a user without access can obtain the list of groups they are a member of."""
        access = {
            "group": {"read": [], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }
        identity_header = {"decoded": {"identity": {"user": {"username": "test_user"}}}}
        user = Mock(spec=User, admin=False, access=access, username="test_user")
        req = Mock(user=user, method="GET", query_params={"username": "test_user"})
        accessPerm = GroupAccessPermission()
        result = accessPerm.has_permission(request=req, view=self.mocked_view)
        self.assertTrue(result)

    def test_no_perm_not_admin_get_others_groups(self):
        """Test that a user cannot obtain the list of groups another user is a member of."""
        access = {
            "group": {"read": [], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }
        identity_header = {"identity": {"user": {"username": "test_user"}}}
        user = Mock(spec=User, admin=False, access=access, username="test_user")
        req = Mock(user=user, method="GET", query_params={"username": "test_user2"})
        accessPerm = GroupAccessPermission()
        result = accessPerm.has_permission(request=req, view=self.mocked_view)
        self.assertFalse(result)

    def test_perm_not_admin_user_admin_role_modify_principals(self):
        """Test that a user with a User Administrator Role can manage the principals of a group."""
        # Mock the user's access.
        access = {
            "group": {"read": ["*"], "write": ["*"]},
            "principal": {"read": ["*"], "write": ["*"]},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }

        # Mock the request.
        user = Mock(spec=User, admin=False, access=access, username="test_user")

        for method in ["DELETE", "POST"]:
            request = Mock(user=user, method=method)

            # Mock the view to make it seem like we are about to manage principals from the group.
            mocked_view = Mock()
            mocked_view.action = "principals"
            mocked_view.basename = "group"

            # Call the function under test.
            group_access_permission = GroupAccessPermission()

            self.assertTrue(
                group_access_permission.has_permission(request=request, view=mocked_view),
                f"a user with a User Administrator role should be able to manage principals using method '{method}'",
            )

    def test_perm_not_admin_no_group_write_not_allowed_modify_principals(self):
        """Test that a user which does not have "write" permissions for a group cannot manage principals."""
        # Mock the user's access.
        access = {
            "group": {"read": ["*"], "write": []},
            "principal": {"read": ["*"], "write": ["*"]},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }

        # Mock the request.
        user = Mock(spec=User, admin=False, access=access, username="test_user")

        for method in ["DELETE", "POST"]:
            request = Mock(user=user, method="POST")

            # Mock the view to make it seem like we are about to manage principals from the group.
            mocked_view = Mock()
            mocked_view.action = "principals"
            mocked_view.basename = "group"

            # Call the function under test.
            group_access_permission = GroupAccessPermission()

            self.assertFalse(
                group_access_permission.has_permission(request=request, view=mocked_view),
                f"a user without group \"write\" permissions should not be allowed to manage principals using method '{method}'",
            )

    def test_perm_not_admin_no_principal_write_not_allowed_modify_principals(self):
        """Test that a user which does not have "write" permissions for a principal cannot manage principals."""
        # Mock the user's access.
        access = {
            "group": {"read": ["*"], "write": ["*"]},
            "principal": {"read": ["*"], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }

        # Mock the request.
        user = Mock(spec=User, admin=False, access=access, username="test_user")
        for method in ["DELETE", "POST"]:
            request = Mock(user=user, method="POST")

            # Mock the view to make it seem like we are about to manage principals from the group.
            mocked_view = Mock()
            mocked_view.action = "principals"
            mocked_view.basename = "group"

            # Call the function under test.
            group_access_permission = GroupAccessPermission()

            self.assertFalse(
                group_access_permission.has_permission(request=request, view=mocked_view),
                f'a user without principal "write" permissions should not be allowed to manage principals using method'
                f" '{method}'",
            )
