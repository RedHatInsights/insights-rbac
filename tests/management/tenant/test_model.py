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
from management.group.definer import seed_group
from management.group.model import Group
from management.policy.model import Policy
from management.tenant_mapping.model import TenantMapping
from management.tenant_service.v2 import V2TenantBootstrapService
from management.workspace.model import Workspace
from migration_tool.in_memory_tuples import (
    InMemoryRelationReplicator,
    InMemoryTuples,
    all_of,
    relation,
    resource,
    subject,
)
from tests.management.role.test_dual_write import RbacFixture

from api.models import Tenant, User


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

    def test_prevents_bootstrapping_public_tenant(self):
        with self.assertRaises(ValueError):
            self.service.bootstrap_tenant(self.fixture.public_tenant)

    def test_relates_workspace_tenant_platform_hierarchy(self):
        bootstrapped = self.fixture.new_tenant(org_id="o1")
        root = self.fixture.root_workspace(bootstrapped.tenant)
        default = self.fixture.default_workspace(bootstrapped.tenant)

        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default.uuid),
                    relation("parent"),
                    subject("rbac", "workspace", root.uuid),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", root.uuid),
                    relation("parent"),
                    subject("rbac", "tenant", "localhost/o1"),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "tenant", "localhost/o1"),
                    relation("platform"),
                    subject("rbac", "platform", "stage"),
                )
            ),
        )

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
                    subject("rbac", "principal", "localhost/u1"),
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
                    subject("rbac", "principal", "localhost/u1"),
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
                    subject("rbac", "principal", "localhost/u1"),
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
                    subject("rbac", "principal", "localhost/u1"),
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
                    subject("rbac", "principal", "localhost/u1"),
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
                    subject("rbac", "principal", "localhost/u1"),
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
                    subject("rbac", "role_binding", bootstrapped.mapping.default_role_binding_uuid),
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
                    subject("rbac", "role_binding", bootstrapped.mapping.default_role_binding_uuid),
                )
            ),
        )

    def test_bulk_adding_updating_users(self):
        bootstrapped = self.fixture.new_tenant(org_id="o1")
        self.tuples.clear()

        users = []
        for user_id, org_id, admin in [("u1", "o1", True), ("u2", "o2", False)]:
            user = User()
            user.user_id = user_id
            user.org_id = org_id
            user.admin = admin
            user.is_active = True
            users.append(user)

        self.service.update_users(users)

        self.assertEquals(12, self.tuples.count_tuples())

        # Assert user updated for first user with existing tenant
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", bootstrapped.mapping.default_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", "localhost/u1"),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", bootstrapped.mapping.default_admin_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", "localhost/u1"),
                )
            ),
        )

        # And also bootstraps the second tenant
        tenant = Tenant.objects.get(org_id="o2")
        self.assertIsNotNone(tenant)
        mapping = TenantMapping.objects.get(tenant=tenant)
        self.assertIsNotNone(mapping)
        workspaces = list(Workspace.objects.filter(tenant=tenant))
        self.assertEqual(len(workspaces), 2)
        default = Workspace.objects.get(type=Workspace.Types.DEFAULT, tenant=tenant)
        self.assertIsNotNone(default)
        root = Workspace.objects.get(type=Workspace.Types.ROOT, tenant=tenant)
        self.assertIsNotNone(root)

        platform_default_policy = Policy.objects.get(group=Group.objects.get(platform_default=True))
        admin_default_policy = Policy.objects.get(group=Group.objects.get(admin_default=True))

        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", mapping.default_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", "localhost/u2"),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default.uuid),
                    relation("parent"),
                    subject("rbac", "workspace", root.uuid),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", root.uuid),
                    relation("parent"),
                    subject("rbac", "tenant", "localhost/o2"),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default.uuid),
                    relation("binding"),
                    subject("rbac", "role_binding", mapping.default_role_binding_uuid),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "tenant", "localhost/o2"),
                    relation("platform"),
                    subject("rbac", "platform", "stage"),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", mapping.default_role_binding_uuid),
                    relation("subject"),
                    subject("rbac", "group", mapping.default_group_uuid, "member"),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", mapping.default_role_binding_uuid),
                    relation("role"),
                    subject("rbac", "role", platform_default_policy.uuid),
                )
            ),
        )

        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default.uuid),
                    relation("binding"),
                    subject("rbac", "role_binding", mapping.default_admin_role_binding_uuid),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", mapping.default_admin_role_binding_uuid),
                    relation("subject"),
                    subject("rbac", "group", mapping.default_admin_group_uuid, "member"),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", mapping.default_admin_role_binding_uuid),
                    relation("role"),
                    subject("rbac", "role", admin_default_policy.uuid),
                )
            ),
        )
