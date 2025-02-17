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
from management.models import Principal
from tests.identity_request import IdentityRequest


class PrincipalModelTests(IdentityRequest):
    """Test the principal model."""

    def tearDown(self):
        """Tear down principal model tests."""
        Principal.objects.all().delete()

    def test_principal_creation(self):
        """Test that we can create principal correctly."""
        # Default value for cross_account is False.
        principalA = Principal.objects.create(username="principalA", tenant=self.tenant)
        self.assertEqual(principalA.username, "principala")
        self.assertEqual(principalA.cross_account, False)

        # Explicitly set cross_account.
        principalB = Principal.objects.create(username="principalB", cross_account=True, tenant=self.tenant)
        self.assertEqual(principalB.username, "principalb")
        self.assertEqual(principalB.cross_account, True)
