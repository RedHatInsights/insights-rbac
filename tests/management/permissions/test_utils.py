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
"""Tests for Access Permission Utilities."""

from unittest.mock import Mock

from django.test import TestCase

from api.models import User
from management.permissions.utils import PRINCIPAL_SCOPE, SCOPE_KEY, is_scope_principal


class AccessPermissionUtilitiesTest(TestCase):
    """Test the access permission utilities."""

    def test_has_scoped_principal_get(self):
        """Test that a user can execute if query param scope=principal is present for GET."""
        user = Mock(spec=User)
        req = Mock(user=user, method='GET', query_params={SCOPE_KEY: PRINCIPAL_SCOPE})
        result = is_scope_principal(request=req)
        self.assertTrue(result)

    def test_has_scoped_principal_post(self):
        """Test that a user cannot execute if query param scope=principal is present for POST."""
        user = Mock(spec=User)
        req = Mock(user=user, method='POST', query_params={SCOPE_KEY: PRINCIPAL_SCOPE})
        result = is_scope_principal(request=req)
        self.assertFalse(result)

    def test_has_scoped_not_principal_get(self):
        """Test that a user cannot execute if query param scope!=principal is present for GET."""
        user = Mock(spec=User)
        req = Mock(user=user, method='GET', query_params={SCOPE_KEY: 'bad'})
        result = is_scope_principal(request=req)
        self.assertFalse(result)
