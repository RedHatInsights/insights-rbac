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
from tenant_schemas.utils import tenant_context

from management.role.definer import seed_roles, seed_permissions
from tests.identity_request import IdentityRequest
from management.models import Role, Permission, Access, ResourceDefinition


class RoleDefinerTests(IdentityRequest):
    """Test the role definer functions."""

    def setUp(self):
        """Set up the role definer tests."""
        super().setUp()

    def test_role_create(self):
        """ Test that we can run a role seeding update. """
        self.try_seed_roles()

        with tenant_context(self.tenant):
            roles = Role.objects.filter(platform_default=True)
            self.assertTrue(len(roles))
            self.assertFalse(Role.objects.get(name="RBAC Administrator Local Test").platform_default)

    def test_role_update(self):
        """ Test that role seeding update will re-create the roles. """
        self.try_seed_roles()

        # delete all the roles and re-create roles again when seed_roles is called
        with tenant_context(self.tenant):
            Role.objects.all().delete()
            roles = Role.objects.filter(platform_default=True)
            self.assertFalse(len(roles))

            seed_roles(self.tenant)
            roles = Role.objects.filter(platform_default=True)
            self.assertTrue(len(roles))

            for access in Access.objects.all():
                self.assertEqual(access.tenant, self.tenant)
                for rd in ResourceDefinition.objects.filter(access=access):
                    self.assertEqual(rd.tenant, self.tenant)

    def test_role_update_version_diff(self):
        """ Test that role seeding updates attribute when version is changed. """
        self.try_seed_roles()

        # set the version to zero, so it would update attribute when seed_roles is called
        with tenant_context(self.tenant):
            roles = Role.objects.filter(platform_default=True).update(version=0, platform_default=False)
            self.assertFalse(len(Role.objects.filter(platform_default=True)))

            seed_roles(self.tenant)
            roles = Role.objects.filter(platform_default=True)
            self.assertTrue(len(roles))

    def try_seed_roles(self):
        """ Try to seed roles """
        try:
            seed_roles(self.tenant)
        except Exception:
            self.fail(msg="seed_roles encountered an exception")

    def test_try_seed_permissions(self):
        """ Test permission seeding. """
        with tenant_context(self.tenant):
            self.assertFalse(len(Permission.objects.all()))

        try:
            seed_permissions(self.tenant)
        except Exception:
            self.fail(msg="seed_permissions encountered an exception")

        with tenant_context(self.tenant):
            self.assertTrue(len(Permission.objects.all()))

            permission = Permission.objects.first()
            self.assertTrue(permission.application)
            self.assertTrue(permission.resource_type)
            self.assertTrue(permission.verb)
            self.assertTrue(permission.permission)
            self.assertEqual(permission.tenant, self.tenant)

    def test_try_seed_permissions_update_description(self):
        """ Test permission seeding update description, skip string configs. """
        permission_string = "approval_local_test:templates:read"
        with tenant_context(self.tenant):
            self.assertFalse(len(Permission.objects.all()))
            Permission.objects.create(permission=permission_string)

        try:
            seed_permissions(self.tenant)
        except Exception:
            self.fail(msg="seed_permissions encountered an exception")

        with tenant_context(self.tenant):
            self.assertEqual(
                Permission.objects.exclude(permission=permission_string).values_list("description").distinct().first(),
                ("",),
            )

            permission = Permission.objects.filter(permission=permission_string)
            self.assertEqual(len(permission), 1)
            self.assertEqual(permission.first().description, "Approval local test templates read.")
            # Previous string verb still works
            self.assertEqual(
                Permission.objects.filter(permission="catalog_local_test:approval_requests:read").count(), 1
            )
