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

from django.test import TestCase

from management.tenant_mapping.model import DefaultAccessType, TenantMapping
from tests.management.role.test_dual_write import RbacFixture


class TenantMappingTests(TestCase):
    fixture: RbacFixture
    tenant_mapping: TenantMapping

    def setUp(self):
        self.fixture = RbacFixture()
        self.tenant_mapping = self.fixture.new_tenant(org_id="test-tenant").mapping

    def test_group_uuid_for(self):
        self.assertEqual(
            self.tenant_mapping.default_group_uuid,
            self.tenant_mapping.group_uuid_for(DefaultAccessType.USER),
        )

        self.assertEqual(
            self.tenant_mapping.default_admin_group_uuid,
            self.tenant_mapping.group_uuid_for(DefaultAccessType.ADMIN),
        )
