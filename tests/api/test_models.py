#
# Copyright 2024 Red Hat, Inc.
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
"""Test cases for api models."""

from django.test import TestCase

from api.models import Tenant


class TenantModelTests(TestCase):
    """Test the Tenant model."""

    def setUp(self):
        """Set up the tenant model tests."""
        super().setUp()
        self.tenant = Tenant.objects.create(tenant_name="acct1234", org_id="1234")
        self.public_tenant = Tenant.objects.get_public_tenant()

    def tearDown(self):
        """Tear down tenant model tests."""
        Tenant.objects.all().delete()

    def test_get_public_tenant(self):
        """Test the tenant model manager method to get the public tenant."""
        self.assertCountEqual(Tenant.objects.all(), [self.public_tenant, self.tenant])
        self.assertEqual(Tenant.objects.get_public_tenant(), self.public_tenant)
