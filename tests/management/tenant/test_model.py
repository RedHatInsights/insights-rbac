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
"""Test cases for Tenant bootstrapping logic."""

from django.test import TestCase
from api.models import User
from management.group.definer import seed_group, set_system_flag_before_update
from management.tenant.model import V2TenantBootstrapService
from migration_tool.in_memory_tuples import (
    InMemoryRelationReplicator,
    InMemoryTuples,
    all_of,
    relation,
    resource,
    subject,
)
from tests.management.role.test_dual_write import RbacFixture


class V2TenantBootstrapServiceTest(TestCase):
    """Test cases for Tenant bootstrapping logic."""

    service: V2TenantBootstrapService
    tuples: InMemoryTuples
    fixture: RbacFixture

    def setUp(self):
        self.tuples = InMemoryTuples()
        self.service = V2TenantBootstrapService(InMemoryRelationReplicator(self.tuples))
        self.fixture = RbacFixture(self.service)
        self.default_group, self.admin_group = seed_group()

    def test_removes_user_from_admin_group_when_no_longer_admin(self):
        bootstrapped = self.fixture.new_tenant(org_id="o1")

        user = User()
        user.user_id = "u1"
        user.org_id = "o1"
        user.admin = True
        user.is_active = True

        self.service.update_user(user)
        user.admin = False
        self.service.update_user(user)

        self.assertEqual(
            0,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", bootstrapped.mapping.default_admin_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", "localhost:u1"),
                )
            ),
        )

        # But is still a regular user
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", bootstrapped.mapping.default_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", "localhost:u1"),
                )
            ),
        )

    def test_adds_user_to_admin_group_when_becoming_admin(self):
        bootstrapped = self.fixture.new_tenant(org_id="o1")

        user = User()
        user.user_id = "u1"
        user.org_id = "o1"
        user.admin = False
        user.is_active = True

        self.service.update_user(user)

        self.assertEqual(
            0,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", bootstrapped.mapping.default_admin_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", "localhost:u1"),
                )
            ),
        )

        # But is a regular user
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", bootstrapped.mapping.default_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", "localhost:u1"),
                )
            ),
        )

        user.admin = True
        self.service.update_user(user)

        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", bootstrapped.mapping.default_admin_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", "localhost:u1"),
                )
            ),
        )

        # And is still a regular user
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", bootstrapped.mapping.default_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", "localhost:u1"),
                )
            ),
        )

    def test_does_not_add_default_access_when_already_customized(self):
        tenant = self.fixture.new_unbootstrapped_tenant(org_id="o1")
        self.fixture.custom_default_group(tenant)

        user = User()
        user.user_id = "u1"
        user.org_id = "o1"
        user.admin = False
        user.is_active = True

        bootstrapped = self.service.update_user(user)
        default_ws = self.fixture.default_workspace(tenant)

        self.assertEqual(
            0,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default_ws.uuid),
                    relation("binding"),
                    subject("rbac", "role_binding", bootstrapped.mapping.default_user_role_binding_uuid),
                )
            ),
        )

    def test_adds_default_access_when_not_customized(self):
        tenant = self.fixture.new_unbootstrapped_tenant(org_id="o1")

        user = User()
        user.user_id = "u1"
        user.org_id = "o1"
        user.admin = False
        user.is_active = True

        bootstrapped = self.service.update_user(user)
        default_ws = self.fixture.default_workspace(tenant)

        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default_ws.uuid),
                    relation("binding"),
                    subject("rbac", "role_binding", bootstrapped.mapping.default_user_role_binding_uuid),
                )
            ),
        )
