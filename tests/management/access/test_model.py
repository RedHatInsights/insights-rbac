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
"""Test the group model."""
from django.test import TestCase
from tenant_schemas.utils import tenant_context

# from unittest.mock import Mock

from management.models import Access
from tests.identity_request import IdentityRequest


class AccessModelTests(IdentityRequest):
    """Test the access model."""

    def setUp(self):
        """Set up the access model tests."""
        super().setUp()

        with tenant_context(self.tenant):
            self.access = Access.objects.create(permission="app:*:*")

    def tearDown(self):
        """Tear down access model tests."""
        with tenant_context(self.tenant):
            Access.objects.all().delete()

    def test_permission_application(self):
        """Test we get back the application name of the permission."""
        with tenant_context(self.tenant):
            self.assertEqual(self.access.permission_application(), "app")

    def test_split_permission(self):
        """Test we split the permission."""
        with tenant_context(self.tenant):
            self.assertEqual(self.access.split_permission(), ["app", "*", "*"])
