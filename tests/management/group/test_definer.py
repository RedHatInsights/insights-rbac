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
"""Test the group definer."""
from unittest.mock import ANY, call, patch
from api.models import Tenant

from django.conf import settings
from management.group.definer import seed_group, add_roles, clone_default_group_in_public_schema
from management.role.definer import seed_roles
from tests.identity_request import IdentityRequest
from tests.core.test_kafka import copy_call_args
from management.models import Group, Role


class GroupDefinerTests(IdentityRequest):
    """Test the group definer functions."""

    def setUp(self):
        """Set up the group definer tests."""
        super().setUp()
        self.public_tenant = Tenant.objects.get(tenant_name="public")
        seed_roles()
        seed_group()

    def test_default_group_seeding_properly(self):
        """Test that default group are seeded properly."""
        group = Group.objects.get(platform_default=True)

        system_policy = group.policies.get(name="System Policy for Group {}".format(group.uuid))
        self.assertEqual(group.platform_default, True)
        self.assertEqual(group.system, True)
        self.assertEqual(group.name, "Default access")
        self.assertEqual(group.tenant, self.public_tenant)
        self.assertEqual(system_policy.system, True)
        self.assertEqual(system_policy.tenant, self.public_tenant)
        # only platform_default roles would be assigned to the default group
        for role in group.roles():
            self.assertTrue(role.platform_default)
            self.assertEqual(role.tenant, self.public_tenant)

    def test_default_group_seeding_skips(self):
        """Test that default groups with system flag false will be skipped during seeding"""

        self.modify_default_group(system=False)

        try:
            seed_group()
        except Exception:
            self.fail(msg="update seed_group encountered an exception")

        group = Group.objects.get(platform_default=True)
        self.assertEqual(group.system, False)
        self.assertEqual(group.tenant, self.public_tenant)
        group.roles().get(name="Ansible Automation Access Local Test")

    @patch("core.kafka.RBACProducer.send_kafka_message")
    def test_default_group_seeding_reassign_roles(self, send_kafka_message):
        """Test that previous assigned roles would be eliminated before assigning new roles."""
        kafka_mock = copy_call_args(send_kafka_message)
        self.modify_default_group()
        new_platform_role = Role.objects.create(
            name="new_platform_role", platform_default=True, tenant=self.public_tenant
        )
        role_to_remove = Role.objects.get(name="RBAC Administrator Local Test")
        with self.settings(NOTIFICATIONS_RH_ENABLED=True, NOTIFICATIONS_ENABLED=True):
            try:
                seed_group()
            except Exception:
                self.fail(msg="update seed_group encountered an exception")

            group = Group.objects.get(platform_default=True, tenant=self.public_tenant)
            self.assertEqual(group.system, True)
            self.assertRaises(Role.DoesNotExist, group.roles().get, name=role_to_remove.name)
            self.assertIsNotNone(group.roles().get(name=new_platform_role.name))
            for role in group.roles():
                self.assertTrue(role.platform_default)

            if settings.AUTHENTICATE_WITH_ORG_ID:
                org_id = self.customer_data["org_id"]
            else:
                org_id = None

            notification_messages = [
                call(
                    settings.NOTIFICATIONS_TOPIC,
                    {
                        "bundle": "console",
                        "application": "rbac",
                        "event_type": "rh-new-role-added-to-default-access",
                        "timestamp": ANY,
                        "account_id": self.customer_data["account_id"],
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "username": "Red Hat",
                                    "name": group.name,
                                    "uuid": str(group.uuid),
                                    "role": {"name": new_platform_role.name, "uuid": str(new_platform_role.uuid)},
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
                        "event_type": "rh-role-removed-from-default-access",
                        "timestamp": ANY,
                        "account_id": self.customer_data["account_id"],
                        "events": [
                            {
                                "metadata": {},
                                "payload": {
                                    "username": "Red Hat",
                                    "name": group.name,
                                    "uuid": str(group.uuid),
                                    "role": {"name": role_to_remove.name, "uuid": str(role_to_remove.uuid)},
                                },
                            }
                        ],
                        "org_id": org_id,
                    },
                    ANY,
                ),
            ]

            self.assertEqual(kafka_mock.call_args_list, notification_messages)

    def modify_default_group(self, system=True):
        """Add a role to the default group and/or change the system flag"""
        group = Group.objects.get(platform_default=True)
        roles = Role.objects.filter(name="RBAC Administrator Local Test")
        add_roles(group, roles, self.public_tenant)

        group.system = system
        group.save()

        self.assertIsNotNone(group.roles().get(name=roles.first().name))

    def test_admin_default_group_seeding_properly(self):
        """Test that admin default group are seeded properly."""
        group = Group.objects.get(admin_default=True)

        system_policy = group.policies.get(name="System Policy for Group {}".format(group.uuid))
        self.assertEqual(group.admin_default, True)
        self.assertEqual(group.system, True)
        self.assertEqual(group.name, "Default admin access")
        self.assertEqual(group.tenant, self.public_tenant)
        self.assertEqual(system_policy.system, True)
        self.assertEqual(system_policy.tenant, self.public_tenant)
        # only admin_default roles would be assigned to the admin_default group
        for role in group.roles():
            self.assertTrue(role.admin_default)
            self.assertEqual(role.tenant, self.public_tenant)

    def test_clone_default_group_in_public_schema(self):
        """Test that the custom default group contains only public tenant roles by default."""
        invalid_role = Role.objects.create(
            platform_default=True, system=True, tenant=self.tenant, name="INVALID SYSTEM ROLE ON TENANT"
        )
        group = Group.objects.get(platform_default=True, tenant=self.public_tenant)
        self.assertEqual(Group.objects.filter(platform_default=True, tenant=self.tenant).count(), 0)
        clone_default_group_in_public_schema(group, self.tenant)

        self.assertEqual(Group.objects.filter(platform_default=True, tenant=self.tenant).count(), 1)
        custom_default_group = Group.objects.filter(platform_default=True, tenant=self.tenant).last()
        self.assertTrue(invalid_role not in list(custom_default_group.roles()))
