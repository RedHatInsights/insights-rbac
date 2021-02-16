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
"""Test the principal model."""
from django.test import TestCase
from tenant_schemas.utils import tenant_context
from unittest.mock import Mock

from management.models import Principal
from tests.identity_request import IdentityRequest


class PrincipalModelTests(IdentityRequest):
    """Test the principal model."""

    def tearDown(self):
        """Tear down principal model tests."""
        with tenant_context(self.tenant):
            Principal.objects.all().delete()

    def test_principal_creation(self):
        """Test that we can create principal correctly."""
        with tenant_context(self.tenant):
            # Default value for cross_account is False.
            principalA = Principal.objects.create(username="principalA")
            self.assertEqual(principalA.username, "principalA")
            self.assertEqual(principalA.cross_account, False)

            # Explicitly set cross_account.
            principalB = Principal.objects.create(username="principalB", cross_account=True)
            self.assertEqual(principalB.username, "principalB")
            self.assertEqual(principalB.cross_account, True)
