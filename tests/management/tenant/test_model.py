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

from typing import Optional, Tuple
from django.test import TestCase
from management.group.definer import seed_group
from management.group.model import Group
from management.policy.model import Policy
from management.principal.model import Principal
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
        self.fixture.new_system_role("System Role", ["app1:foo:read"], platform_default=True)
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
                    resource("rbac", "workspace", default.id),
                    relation("parent"),
                    subject("rbac", "workspace", root.id),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", root.id),
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

    def test_will_add_default_access_when_already_customized(self):
        """Test just to confirm behavior but this is not a valid state and this scenario should never happen."""
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
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default_ws.id),
                    relation("binding"),
                    subject("rbac", "role_binding", bootstrapped.mapping.default_role_binding_uuid),
                )
            ),
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", bootstrapped.mapping.default_role_binding_uuid),
                    relation("subject"),
                    subject("rbac", "group", bootstrapped.mapping.default_group_uuid, "member"),
                )
            ),
        )
        self.assertNotEqual(
            tenant.tenant_mapping.default_group_uuid, Group.objects.get(tenant=tenant, platform_default=True).uuid
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
                    resource("rbac", "workspace", default_ws.id),
                    relation("binding"),
                    subject("rbac", "role_binding", bootstrapped.mapping.default_role_binding_uuid),
                )
            ),
        )

    def test_bulk_adding_updating_users(self):
        bootstrapped = self.fixture.new_tenant(org_id="o1")
        self.tuples.clear()

        # Set up another org with custom default group but not bootstrapped
        o3_tenant = self.fixture.new_unbootstrapped_tenant(org_id="o3")
        o3_custom_group = self.fixture.custom_default_group(o3_tenant)

        self.fixture.new_unbootstrapped_tenant(org_id="o4")

        users = []
        for user_id, username, org_id, admin in [
            ("u1", "username1", "o1", True),
            ("u2", "username2", "o2", False),
            ("u3", "username3", "o2", True),
            ("u4", "username4", "o1", False),
            ("u5", "username5", "o3", False),
            ("u6", "username6", "o4", False),
        ]:
            user = User()
            user.user_id = user_id
            user.username = username
            user.org_id = org_id
            user.admin = admin
            user.is_active = True
            users.append(user)

        self.service.import_bulk_users(users)

        # Admins get 2, otherwise 1
        num_group_membership_tuples = 2 + 1 + 2 + 1 + 1 + 1
        # o1 is already bootstrapped, should get 0
        # existing unbootstrapped custom group tenants get 6
        # new or otherwise unbootstrapped tenants get 9
        num_tenant_bootstrapping_tuples = 0 + 9 + 6 + 9

        self.assertEquals(num_group_membership_tuples + num_tenant_bootstrapping_tuples, self.tuples.count_tuples())

        # Assert user updated for first user with existing tenant
        self.assertAddedToDefaultGroup("localhost/u1", bootstrapped.mapping, and_admin_group=True)  # 2
        # Assert user updated for other user with existing tenant who is not an admin
        self.assertAddedToDefaultGroup("localhost/u4", bootstrapped.mapping)  # 1

        # And also bootstraps the second tenant only once
        # And adds users to default group
        _, mapping, _, _ = self.assertTenantBootstrapped("o2", existing=False)  # 9
        self.assertAddedToDefaultGroup("localhost/u2", mapping)  # 1
        self.assertAddedToDefaultGroup("localhost/u3", mapping, and_admin_group=True)  # 2

        # Bootstraps third tenant but uses existing custom group
        _, mapping, _, _ = self.assertTenantBootstrapped("o3", with_custom_default_group=o3_custom_group)  # 6
        self.assertAddedToDefaultGroup("localhost/u5", mapping)  # 1

        # Bootstraps fourth tenant with new default group
        _, mapping, _, _ = self.assertTenantBootstrapped("o4", existing=True)  # 9
        self.assertAddedToDefaultGroup("localhost/u6", mapping)  # 1

    def test_bulk_import_updates_user_ids_on_principals_but_does_not_add_principals(self):
        bootstrapped = self.fixture.new_tenant(org_id="o1")
        self.tuples.clear()

        # Set up another org with custom default group but not bootstrapped
        o3_tenant = self.fixture.new_unbootstrapped_tenant(org_id="o3")
        self.fixture.custom_default_group(o3_tenant)

        o4_tenant = self.fixture.new_unbootstrapped_tenant(org_id="o4")

        # Existing bootstrapped tenant with existing user with id
        Principal.objects.create(username="username1", tenant=bootstrapped.tenant, user_id="u1")
        # Another user without an id
        Principal.objects.create(username="username4", tenant=bootstrapped.tenant)

        Principal.objects.create(username="username5", tenant=o3_tenant)
        Principal.objects.create(username="username6", tenant=o4_tenant, user_id="u6")

        users = []
        for user_id, username, org_id, admin in [
            ("u1", "username1", "o1", True),  # Already bootstrapped tenant, existing user with ID
            ("u2", "username2", "o2", False),  # New tenant, so new user, shouldn't get created
            ("u3", "username3", "o2", True),  # New tenant, so new user, shouldn't get created
            ("u4", "username4", "o1", False),  # Already bootstrapped tenant, existing user without ID
            ("u5", "username5", "o3", False),  # Unbootstrapped tenant, existing user without ID
            ("u6", "username6", "o4", False),  # Unbootstrapped tenant, existing user with ID
        ]:
            user = User()
            user.user_id = user_id
            user.username = username
            user.org_id = org_id
            user.admin = admin
            user.is_active = True
            users.append(user)

        self.service.import_bulk_users(users)

        # Assert each principal has the right user ID
        self.assertEqual("u1", Principal.objects.get(username="username1").user_id)
        self.assertEqual("u4", Principal.objects.get(username="username4").user_id)
        self.assertEqual("u5", Principal.objects.get(username="username5").user_id)
        self.assertEqual("u6", Principal.objects.get(username="username6").user_id)

        # Assert no extra principals created
        self.assertEqual(4, Principal.objects.count())

    def assertAddedToDefaultGroup(self, user_id: str, tenant_mapping: TenantMapping, and_admin_group: bool = False):
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", tenant_mapping.default_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", user_id),
                )
            ),
        )
        self.assertEqual(
            1 if and_admin_group else 0,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "group", tenant_mapping.default_admin_group_uuid),
                    relation("member"),
                    subject("rbac", "principal", user_id),
                )
            ),
        )

    def assertTenantBootstrapped(
        self, org_id: str, with_custom_default_group: Optional[Group] = None, existing: bool = False
    ) -> Tuple[Tenant, TenantMapping, Workspace, Workspace]:
        tenant = Tenant.objects.get(org_id=org_id)
        mapping = TenantMapping.objects.get(tenant=tenant)
        workspaces = list(Workspace.objects.filter(tenant=tenant))
        self.assertEqual(len(workspaces), 2)
        default = Workspace.objects.get(type=Workspace.Types.DEFAULT, tenant=tenant)
        root = Workspace.objects.get(type=Workspace.Types.ROOT, tenant=tenant)

        platform_default_policy = Policy.objects.get(
            group=Group.objects.get(platform_default=True, tenant=self.fixture.public_tenant)
        )
        admin_default_policy = Policy.objects.get(
            group=Group.objects.get(admin_default=True, tenant=self.fixture.public_tenant)
        )
        custom_default_group = with_custom_default_group

        # If custom default group, must be existing
        if existing or custom_default_group:
            self.assertTrue(tenant.ready, f"Expected existing tenant {org_id} to be ready")
        else:
            self.assertFalse(tenant.ready, f"Expected new tenant {org_id} to not be ready")

        self.assertEqual(
            default.parent_id,
            root.id,
            f"Expected default workspace to be child of root workspace for tenant {org_id}",
        )

        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default.id),
                    relation("parent"),
                    subject("rbac", "workspace", root.id),
                )
            ),
            f"Expected default workspace to be child of root workspace for tenant {org_id}",
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", root.id),
                    relation("parent"),
                    subject("rbac", "tenant", f"localhost/{org_id}"),
                )
            ),
            f"Expected root workspace to be child of tenant for tenant {org_id}",
        )
        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "tenant", f"localhost/{org_id}"),
                    relation("platform"),
                    subject("rbac", "platform", "stage"),
                )
            ),
            f"Expected tenant {org_id} to have platform",
        )

        self.assertEqual(
            1 if custom_default_group is None else 0,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default.id),
                    relation("binding"),
                    subject("rbac", "role_binding", mapping.default_role_binding_uuid),
                )
            ),
            f"Expected default workspace to have platform default role binding for tenant {org_id}",
        )
        self.assertEqual(
            1 if custom_default_group is None else 0,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", mapping.default_role_binding_uuid),
                    relation("subject"),
                    subject("rbac", "group", mapping.default_group_uuid, "member"),
                )
            ),
            f"Expected default role binding to have default group as subject for tenant {org_id}",
        )
        self.assertEqual(
            1 if custom_default_group is None else 0,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", mapping.default_role_binding_uuid),
                    relation("role"),
                    subject("rbac", "role", platform_default_policy.uuid),
                )
            ),
            f"Expected default role binding to have platform default role for tenant {org_id}",
        )

        if custom_default_group is not None:
            # We expect the migrator will take care of this.
            self.assertEqual(
                0,
                self.tuples.count_tuples(
                    all_of(
                        relation("subject"),
                        subject("rbac", "group", custom_default_group.uuid, "member"),
                    )
                ),
                f"Expected no relations to custom default group (leave to migrator) for tenant {org_id}",
            )

        self.assertEqual(
            1,
            self.tuples.count_tuples(
                all_of(
                    resource("rbac", "workspace", default.id),
                    relation("binding"),
                    subject("rbac", "role_binding", mapping.default_admin_role_binding_uuid),
                )
            ),
            f"Expected default workspace to have admin default role binding for tenant {org_id}",
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
            f"Expected admin default role binding to have admin default group as subject for tenant {org_id}",
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
            f"Expected admin default role binding to have admin default role for tenant {org_id}",
        )
        return tenant, mapping, root, default
