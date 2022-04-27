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
from unittest.mock import call, patch
from management.role.definer import seed_roles, seed_permissions
from api.models import Tenant
from tests.identity_request import IdentityRequest
from management.models import Role, Permission, Access, ResourceDefinition


class RoleDefinerTests(IdentityRequest):
    """Test the role definer functions."""

    def setUp(self):
        """Set up the role definer tests."""
        super().setUp()
        self.public_tenant = Tenant.objects.get(tenant_name="public")

    @patch("management.notifications.producer_util.NotificationProducer.send_kafka_message")
    def test_role_create(self, send_kafka_message):
        """Test that we can run a role seeding update."""
        with self.settings(NOTIFICATIONS_RH_ENABLED=True, NOTIFICATIONS_ENABLED=True):
            self.try_seed_roles()

            roles = Role.objects.filter(platform_default=True)
            self.assertTrue(len(roles))
            self.assertFalse(Role.objects.get(name="RBAC Administrator Local Test").platform_default)

            send_kafka_message.assert_any_call(
                "rh-new-role-available",
                self.customer_data["account_id"],
                {"name": roles.first().name, "username": "Red Hat", "uuid": str(roles.first().uuid)},
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

    @patch("management.notifications.producer_util.NotificationProducer.send_kafka_message")
    def test_role_update_platform_default_role(self, send_kafka_message):
        """Test that role seeding updates send out notificaiton."""
        self.try_seed_roles()

        # Update non platform default role
        non_platform_role_to_update = Role.objects.get(name="RBAC Administrator Local Test")
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

        with self.settings(NOTIFICATIONS_RH_ENABLED=True, NOTIFICATIONS_ENABLED=True):
            seed_roles()

            platform_role_to_update.refresh_from_db()
            non_platform_role_to_update.refresh_from_db()
            self.assertEqual(non_platform_role_to_update.access.first().permission.permission, "rbac:*:*")
            self.assertEqual(platform_role_to_update.access.first().permission.permission, "rbac:principal:read")
            assert send_kafka_message.call_args_list[0] == call(
                "rh-non-platform-default-role-updated",
                self.customer_data["account_id"],
                {
                    "name": non_platform_role_to_update.name,
                    "username": "Red Hat",
                    "uuid": str(non_platform_role_to_update.uuid),
                },
            )
            assert send_kafka_message.call_args_list[1] == call(
                "rh-platform-default-role-updated",
                self.customer_data["account_id"],
                {
                    "name": platform_role_to_update.name,
                    "username": "Red Hat",
                    "uuid": str(platform_role_to_update.uuid),
                },
            )

    def try_seed_roles(self):
        """Try to seed roles"""
        try:
            seed_roles()
        except Exception:
            self.fail(msg="seed_roles encountered an exception")

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
        permission_string = "approval_local_test:templates:read"
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
        self.assertEqual(Permission.objects.filter(permission="catalog_local_test:approval_requests:read").count(), 1)
