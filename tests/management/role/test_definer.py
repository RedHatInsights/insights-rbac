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
"""Test the role definer."""
from django.conf import settings
from unittest.mock import ANY, call, patch, mock_open
from management.role.definer import seed_roles, seed_permissions
from api.models import Tenant
from tests.core.test_kafka import copy_call_args
from tests.identity_request import IdentityRequest
from management.models import Access, ExtRoleRelation, Permission, ResourceDefinition, Role
from management.relation_replicator.relation_replicator import ReplicationEvent, ReplicationEventType


class RoleDefinerTests(IdentityRequest):
    """Test the role definer functions."""

    def setUp(self):
        """Set up the role definer tests."""
        super().setUp()
        self.public_tenant = Tenant.objects.get(tenant_name="public")

    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_role_create(self, send_kafka_message):
        kafka_mock = copy_call_args(send_kafka_message)
        """Test that we can run a role seeding update."""
        with self.settings(NOTIFICATIONS_RH_ENABLED=True, NOTIFICATIONS_ENABLED=True):
            self.try_seed_roles()

            roles = Role.objects.filter(platform_default=True)

            org_id = self.customer_data["org_id"]

            self.assertTrue(len(roles))
            self.assertFalse(Role.objects.get(name="User Access administrator").platform_default)

            kafka_mock.assert_any_call(
                settings.NOTIFICATIONS_TOPIC,
                {
                    "bundle": "console",
                    "application": "rbac",
                    "event_type": "rh-new-role-available",
                    "timestamp": ANY,
                    "events": [
                        {
                            "metadata": {},
                            "payload": {
                                "name": roles.first().name,
                                "username": "Red Hat",
                                "uuid": str(roles.first().uuid),
                            },
                        }
                    ],
                    "org_id": org_id,
                },
                ANY,
            )

    def test_role_update(self):
        """Test that role seeding update will re-create the roles."""
        self.try_seed_roles()

        # delete all the roles and re-create roles again when seed_roles is called
        Role.objects.all().delete()
        roles = Role.objects.filter(platform_default=True)
        self.assertFalse(len(roles))

        seed_roles()
        roles = Role.objects.filter(platform_default=True)
        self.assertTrue(len(roles))

        for access in Access.objects.all():
            self.assertEqual(access.tenant, self.public_tenant)
            for rd in ResourceDefinition.objects.filter(access=access):
                self.assertEqual(rd.tenant, self.public_tenant)

    def test_role_update_version_diff(self):
        """Test that role seeding updates attribute when version is changed."""
        self.try_seed_roles()

        # set the version to zero, so it would update attribute when seed_roles is called
        roles = Role.objects.filter(platform_default=True).update(version=0, platform_default=False)
        self.assertFalse(len(Role.objects.filter(platform_default=True)))

        seed_roles()
        roles = Role.objects.filter(platform_default=True)
        self.assertTrue(len(roles))

    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_role_update_platform_default_role(self, send_kafka_message):
        """Test that role seeding updates send out notification."""
        kafka_mock = copy_call_args(send_kafka_message)
        self.try_seed_roles()

        # Update non platform default role
        non_platform_role_to_update = Role.objects.get(name="User Access administrator")
        non_platform_role_to_update.version = 0
        access = non_platform_role_to_update.access.first()
        access.permission = Permission.objects.get(permission="rbac:principal:read")
        non_platform_role_to_update.save()
        access.save()

        # Update platform default role
        platform_role_to_update = Role.objects.get(name="User Access principal viewer")
        platform_role_to_update.version = 0
        access = platform_role_to_update.access.first()
        access.permission = Permission.objects.get(permission="rbac:*:*")
        platform_role_to_update.save()
        access.save()

        org_id = self.customer_data["org_id"]

        with self.settings(NOTIFICATIONS_RH_ENABLED=True, NOTIFICATIONS_ENABLED=True):
            seed_roles()

            platform_role_to_update.refresh_from_db()
            non_platform_role_to_update.refresh_from_db()
            self.assertEqual(non_platform_role_to_update.access.first().permission.permission, "rbac:*:*")
            self.assertEqual(platform_role_to_update.access.first().permission.permission, "rbac:principal:read")

            notification_messages = [
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "rh-non-platform-default-role-updated",
                        "timestamp": ANY,
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "name": non_platform_role_to_update.name,
                                    "username": "Red Hat",
                                    "uuid": str(non_platform_role_to_update.uuid),
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "rh-platform-default-role-updated",
                        "timestamp": ANY,
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "name": platform_role_to_update.name,
                                    "username": "Red Hat",
                                    "uuid": str(platform_role_to_update.uuid),
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
            ]
            kafka_mock.assert_has_calls(notification_messages, any_order=True)

    def try_seed_roles(self):
        """Try to seed roles"""
        try:
            seed_roles()
        except Exception:
            self.fail(msg="seed_roles encountered an exception")

        # External role relations are seeded
        ext_relations = ExtRoleRelation.objects.all()
        self.assertNotEqual(len(ext_relations), 0)
        for relation in ext_relations:
            self.assertIsNotNone(relation.role)

        # Update relation to point to a new role. Seed again would update relation back.
        ext_relation = ExtRoleRelation.objects.first()
        origin_role = ext_relation.role
        ext_relation.role = Role.objects.get(name="User Access administrator")
        ext_relation.save()
        origin_role.version = 1
        origin_role.save()
        seed_roles()

        ext_relation.refresh_from_db()
        self.assertEqual(origin_role, ext_relation.role)

    def test_try_seed_permissions(self):
        """Test permission seeding."""
        self.assertFalse(len(Permission.objects.all()))

        try:
            seed_permissions()
        except Exception:
            self.fail(msg="seed_permissions encountered an exception")

        self.assertTrue(len(Permission.objects.all()))

        permission = Permission.objects.first()
        self.assertTrue(permission.application)
        self.assertTrue(permission.resource_type)
        self.assertTrue(permission.verb)
        self.assertTrue(permission.permission)
        self.assertEqual(permission.tenant, self.public_tenant)

    def test_try_seed_permissions_update_description(self):
        """Test permission seeding update description, skip string configs."""
        permission_string = "approval:templates:read"
        self.assertFalse(len(Permission.objects.all()))
        Permission.objects.create(permission=permission_string, tenant=self.public_tenant)

        try:
            seed_permissions()
        except Exception:
            self.fail(msg="seed_permissions encountered an exception")

        self.assertEqual(
            Permission.objects.exclude(permission=permission_string).values_list("description").distinct().first(),
            ("",),
        )

        permission = Permission.objects.filter(permission=permission_string)
        self.assertEqual(len(permission), 1)
        self.assertEqual(permission.first().description, "Approval local test templates read.")
        # Previous string verb still works
        self.assertEqual(Permission.objects.filter(permission="inventory:*:*").count(), 1)

    def is_create_event(self, relation: str, evt: ReplicationEvent) -> bool:
        return evt.event_type == ReplicationEventType.CREATE_SYSTEM_ROLE and any(
            t.relation == relation for t in evt.add
        )

    def is_remove_event(self, relation: str, evt: ReplicationEvent) -> bool:
        return evt.event_type == ReplicationEventType.DELETE_SYSTEM_ROLE and any(
            t.relation == relation for t in evt.remove
        )

    def is_update_event(self, relation: str, evt: ReplicationEvent) -> bool:
        return evt.event_type == ReplicationEventType.UPDATE_SYSTEM_ROLE and any(
            t.relation == relation for t in evt.add
        )

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_seed_roles_new_role(self, mock_replicate):
        seed_roles()
        self.assertTrue(
            any(self.is_create_event("inventory_hosts_read", args[0]) for args, _ in mock_replicate.call_args_list)
        )

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch("management.role.definer.destructive_ok")
    @patch("builtins.open", new_callable=mock_open, read_data='{"roles": []}')
    @patch("os.listdir")
    @patch("os.path.isfile")
    def test_seed_roles_delete_role(
        self,
        mock_isfile,
        mock_listdir,
        mock_open,
        mock_destructive_ok,
        mock_replicate,
    ):
        mock_destructive_ok.return_value = True
        # mock files
        mock_listdir.return_value = ["role.json"]
        mock_isfile.return_value = True

        # create a role in the database that's not in config
        role_to_delete = Role.objects.create(name="dummy_role_delete", system=True, tenant=self.public_tenant)
        permission, _ = Permission.objects.get_or_create(permission="inventory:hosts:read", tenant=self.public_tenant)
        _ = Access.objects.create(permission=permission, role=role_to_delete, tenant=self.public_tenant)

        role_to_delete.save()

        seed_roles()

        self.assertTrue(
            any(self.is_remove_event("inventory_hosts_read", args[0]) for args, _ in mock_replicate.call_args_list)
        )

        # verify role was deleted from the database
        self.assertFalse(Role.objects.filter(id=role_to_delete.id).exists())

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data='{"roles": [{"name": "dummy_role_update", "system": true, "version": 3, "access": [{"permission": "dummy:hosts:read"}]}]}',
    )
    @patch("os.listdir")
    @patch("os.path.isfile")
    def test_seed_roles_update_role(
        self,
        mock_isfile,
        mock_listdir,
        mock_open,
        mock_replicate,
    ):
        # mock files
        mock_listdir.return_value = ["role.json"]
        mock_isfile.return_value = True

        # create a role in the database that exists in config
        Role.objects.create(name="dummy_role_update", system=True, version=1, tenant=self.public_tenant)

        seed_roles()

        self.assertTrue(
            any(self.is_update_event("dummy_hosts_read", args[0]) for args, _ in mock_replicate.call_args_list)
        )
