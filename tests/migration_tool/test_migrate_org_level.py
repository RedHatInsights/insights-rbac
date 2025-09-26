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
from typing import Optional
from unittest.mock import patch
from uuid import UUID

from django.conf import settings
from django.test import TestCase
from django.test.utils import override_settings

from management.group.definer import seed_group
from management.group.platform import GlobalPolicyIdService
from management.models import Role
from management.permission.scope_service import ImplicitResourceService
from management.relation_replicator.relation_replicator import RelationReplicator
from management.role.definer import seed_roles
from migration_tool.in_memory_tuples import (
    InMemoryTuples,
    InMemoryRelationReplicator,
    all_of,
    resource,
    relation,
    subject,
)
from migration_tool.migrate_org_level import migrate_seeded_to_org_level
from rbac.settings import TENANT_SCOPE_PERMISSIONS
from tests.management.role.test_dual_write import RbacFixture


def _role_resource(role_uuid: str | UUID):
    return resource("rbac", "role", str(role_uuid))


def _role_subject(role_uuid: str | UUID):
    return subject("rbac", "role", str(role_uuid))


def _child_predicate(parent_uuid: str | UUID, child_uuid: str | UUID):
    return all_of(
        _role_resource(parent_uuid),
        relation("child"),
        _role_subject(child_uuid),
    )


class MigrateOrgLevelTests(TestCase):
    tuples: InMemoryTuples
    replicator: RelationReplicator
    fixture: RbacFixture

    resource_service: ImplicitResourceService

    default_platform_default_uuid: UUID
    default_admin_default_uuid: UUID
    root_platform_default_uuid: UUID
    root_admin_default_uuid: UUID
    tenant_platform_default_uuid: UUID
    tenant_admin_default_uuid: UUID

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        seed_group()
        policy_cache = GlobalPolicyIdService()

        cls.default_platform_default_uuid = policy_cache.platform_default_policy_uuid()
        cls.default_admin_default_uuid = policy_cache.admin_default_policy_uuid()
        cls.root_platform_default_uuid = UUID(settings.SYSTEM_DEFAULT_ROOT_WORKSPACE_ROLE_UUID)
        cls.root_admin_default_uuid = UUID(settings.SYSTEM_ADMIN_ROOT_WORKSPACE_ROLE_UUID)
        cls.tenant_platform_default_uuid = UUID(settings.SYSTEM_DEFAULT_TENANT_ROLE_UUID)
        cls.tenant_admin_default_uuid = UUID(settings.SYSTEM_ADMIN_TENANT_ROLE_UUID)

    def setUp(self):
        super().setUp()

        self.resource_service = ImplicitResourceService(
            root_scope_permissions=["root:*:*"],
            tenant_scope_permissions=["tenant:*:*"],
        )

        self.tuples = InMemoryTuples()
        self.replicator = InMemoryRelationReplicator(self.tuples)
        self.fixture = RbacFixture()

        Role.objects.all().delete()

    def _do_migrate(self, resource_service: Optional[ImplicitResourceService] = None):
        migrate_seeded_to_org_level(
            replicator=self.replicator,
            resource_service=resource_service if resource_service is not None else self.resource_service,
        )

    def _assert_child(self, parent_uuid: str | UUID, child_uuid: str | UUID):
        self.assertEqual(
            1,
            len(self.tuples.find_tuples(_child_predicate(parent_uuid=parent_uuid, child_uuid=child_uuid))),
            f"Expected child relation to be present: parent={str(parent_uuid)}, child={str(child_uuid)}",
        )

    def _assert_not_child(self, parent_uuid: str | UUID, child_uuid: str | UUID):
        self.assertEqual(
            0,
            len(self.tuples.find_tuples(_child_predicate(parent_uuid=parent_uuid, child_uuid=child_uuid))),
            f"Expected child relation to be absent: parent={str(parent_uuid)}, child={str(child_uuid)}",
        )

    def test_migrate_default_scope(self):
        """Test that migrating roles with default scope creates relations with the default workspace platform roles."""
        platform_role = self.fixture.new_system_role(
            name="platform", permissions=["default:resource:verb"], platform_default=True
        )

        admin_role = self.fixture.new_system_role(
            name="admin", permissions=["default:resource:verb"], admin_default=True
        )

        self._do_migrate()

        self._assert_child(parent_uuid=self.default_platform_default_uuid, child_uuid=platform_role.uuid)
        self._assert_child(parent_uuid=self.default_admin_default_uuid, child_uuid=admin_role.uuid)

        self.assertEqual(2, len(self.tuples))

    def test_migrate_root_scope(self):
        """Test that migrating roles with root scope creates relations with the root scope platform roles."""
        platform_role = self.fixture.new_system_role(
            name="platform",
            permissions=["root:resource:verb"],
            platform_default=True,
        )

        admin_role = self.fixture.new_system_role(
            name="admin",
            permissions=["root:resource:verb"],
            admin_default=True,
        )

        self._do_migrate()

        self._assert_child(parent_uuid=self.root_platform_default_uuid, child_uuid=platform_role.uuid)
        self._assert_child(parent_uuid=self.root_admin_default_uuid, child_uuid=admin_role.uuid)

        self.assertEqual(2, len(self.tuples))

    def test_migrate_tenant_scope(self):
        """Test that migrating roles with tenant scope creates relations with the tenant scope platform roles."""
        platform_role = self.fixture.new_system_role(
            name="platform",
            permissions=["tenant:resource:verb"],
            platform_default=True,
        )

        admin_role = self.fixture.new_system_role(
            name="admin",
            permissions=["tenant:resource:verb"],
            admin_default=True,
        )

        self._do_migrate()

        self._assert_child(parent_uuid=self.tenant_platform_default_uuid, child_uuid=platform_role.uuid)
        self._assert_child(parent_uuid=self.tenant_admin_default_uuid, child_uuid=admin_role.uuid)

        self.assertEqual(2, len(self.tuples))

    def test_migrate_non_default(self):
        """Test that migrating a role that is neither platform- nor admin-default creates no relations."""
        self.fixture.new_system_role(
            name="some role",
            permissions=["tenant:resource:verb"],
        )

        self._do_migrate()

        # No tuples should have been created, since the role is not a default of any kind.
        self.assertEqual(0, len(self.tuples))

    def test_migrate_dual_default(self):
        """Test that migrating a role that is both platform- and admin-default uses both platform roles."""
        role = self.fixture.new_system_role(
            name="some role",
            permissions=["tenant:resource:verb"],
            platform_default=True,
            admin_default=True,
        )

        self._do_migrate()

        self._assert_child(parent_uuid=self.tenant_platform_default_uuid, child_uuid=role.uuid)
        self._assert_child(parent_uuid=self.tenant_admin_default_uuid, child_uuid=role.uuid)

        self.assertEqual(2, len(self.tuples))

    def test_migrate_mixed_scope(self):
        """Test that migrating roles with permissions that have differing scopes works correctly."""
        tenant_role = self.fixture.new_system_role(
            name="tenant role",
            permissions=["tenant:resource:verb", "app:resource:verb"],
            platform_default=True,
        )

        root_role = self.fixture.new_system_role(
            name="admin role",
            permissions=["root:resource:verb", "default:resource:verb"],
            admin_default=True,
        )

        self._do_migrate()

        self._assert_child(parent_uuid=self.tenant_platform_default_uuid, child_uuid=tenant_role.uuid)
        self._assert_child(parent_uuid=self.root_admin_default_uuid, child_uuid=root_role.uuid)

        self.assertEqual(2, len(self.tuples))

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_remove_existing_relations(self, outbox_replicate):
        """Test that migrating roles with non-default scope appropriately removes existing relations."""
        # seed_roles doesn't let us customize the replicator it uses, so we have to patch the replicator it does use.
        outbox_replicate.side_effect = self.replicator.replicate
        seed_roles()

        initial_count = len(self.tuples)

        # Note that default_role and root_role are platform_default, while tenant_role is admin_default.
        default_role = Role.objects.public_tenant_only().get(name="Notifications viewer")
        root_role = Role.objects.public_tenant_only().get(name="Approval Approver")
        tenant_role = Role.objects.public_tenant_only().get(name="Inventory Groups Administrator")

        # Assert that seed_role creates relations in the default scope.
        self._assert_child(parent_uuid=self.default_platform_default_uuid, child_uuid=default_role.uuid)
        self._assert_child(parent_uuid=self.default_platform_default_uuid, child_uuid=root_role.uuid)
        self._assert_child(parent_uuid=self.default_admin_default_uuid, child_uuid=tenant_role.uuid)

        # This configuration assigns root_role to root workspace scope and tenant_role to tenant scope.
        self._do_migrate(
            resource_service=ImplicitResourceService(
                root_scope_permissions=["approval:actions:create"],
                tenant_scope_permissions=["inventory:*:*"],
            )
        )

        # Assert that relations for non-default-scope roles were removed.
        self._assert_not_child(parent_uuid=self.default_platform_default_uuid, child_uuid=root_role.uuid)
        self._assert_not_child(parent_uuid=self.default_admin_default_uuid, child_uuid=tenant_role.uuid)

        # Assert that we end up with the correct relations.
        self._assert_child(parent_uuid=self.default_platform_default_uuid, child_uuid=default_role.uuid)
        self._assert_child(parent_uuid=self.root_platform_default_uuid, child_uuid=root_role.uuid)
        self._assert_child(parent_uuid=self.tenant_admin_default_uuid, child_uuid=tenant_role.uuid)

        final_count = len(self.tuples)
        self.assertEqual(initial_count, final_count, "Expected overall number of tuples not to change.")

    @override_settings(
        REPLICATION_TO_RELATION_ENABLED=True,
        ROOT_SCOPE_PERMISSIONS="app:*:*",
        TENANT_SCOPE_PERMISSIONS="another_app:*:*",
    )
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_defaults(self, outbox_replicate):
        """Test that the correct defaults are used when None arguments are passed."""
        outbox_replicate.side_effect = self.replicator.replicate

        root_role = self.fixture.new_system_role(
            name="root role",
            permissions=["app:resource:verb"],
            platform_default=True,
        )

        tenant_role = self.fixture.new_system_role(
            name="tenant role",
            permissions=["another_app:resource:verb"],
            admin_default=True,
        )

        migrate_seeded_to_org_level(replicator=None, resource_service=None)

        self._assert_child(parent_uuid=self.root_platform_default_uuid, child_uuid=root_role.uuid)
        self._assert_child(parent_uuid=self.tenant_admin_default_uuid, child_uuid=tenant_role.uuid)

        self.assertEqual(2, len(self.tuples))
