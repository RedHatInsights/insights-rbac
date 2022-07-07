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
"""Test the internal viewset."""
from rest_framework import status
from rest_framework.test import APIClient
from unittest.mock import patch
from django.conf import settings
from django.db.migrations.recorder import MigrationRecorder
from django.test import TestCase, override_settings
from datetime import datetime, timedelta
from unittest.mock import patch
import pytz
import json

from api.models import User, Tenant
from management.models import Group, Policy, Role
from tests.identity_request import IdentityRequest


class InternalViewsetTests(IdentityRequest):
    """Test the internal viewset."""

    def valid_destructive_time():
        return datetime.utcnow().replace(tzinfo=pytz.UTC) + timedelta(hours=1)

    def invalid_destructive_time():
        return datetime.utcnow().replace(tzinfo=pytz.UTC) - timedelta(hours=1)

    def setUp(self):
        """Set up the internal viewset tests."""
        super().setUp()
        self.client = APIClient()
        self.customer = self.customer_data
        self.internal_request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, is_internal=True, create_tenant=False
        )

        self.request = self.internal_request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        self.request.user = user

        self.group = Group(name="System Group", system=True, tenant=self.tenant)
        self.group.save()
        self.role = Role.objects.create(
            name="System Role", description="A role for a group.", system=True, tenant=self.tenant
        )
        self.policy = Policy.objects.create(name="System Policy", group=self.group, tenant=self.tenant)
        self.policy.roles.add(self.role)
        self.policy.save()
        self.group.policies.add(self.policy)
        self.group.save()
        self.public_tenant = Tenant.objects.get(tenant_name="public")

    def tearDown(self):
        """Tear down internal viewset tests."""
        Group.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()

    def test_delete_tenant_disallowed(self):
        """Test that we cannot delete a tenant when disallowed."""
        response = self.client.delete(f"/_private/api/tenant/{self.tenant.org_id}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Destructive operations disallowed.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=invalid_destructive_time())
    def test_delete_tenant_disallowed_with_past_timestamp(self):
        """Test that we cannot delete a tenant when disallowed."""
        response = self.client.delete(f"/_private/api/tenant/{self.tenant.org_id}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Destructive operations disallowed.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch.object(Tenant, "delete")
    def test_delete_tenant_allowed_and_unmodified(self, mock):
        """Test that we can delete a tenant when allowed and unmodified."""
        response = self.client.delete(f"/_private/api/tenant/{self.tenant.org_id}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch.object(Tenant, "delete")
    def test_delete_tenant_no_schema(self, mock):
        """Test that we can delete a tenant with no schema."""
        public_tenant = Tenant.objects.get(tenant_name="public")
        Group.objects.create(name="Custom Group", tenant=public_tenant)

        tenant_no_schema = Tenant.objects.create(tenant_name="no_schema", org_id="1234")
        response = self.client.delete(f"/_private/api/tenant/{tenant_no_schema.org_id}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_tenant_allowed_but_multiple_groups(self):
        """Test that we cannot delete a tenant when allowed but modified."""
        Group.objects.create(name="Custom Group", tenant=self.tenant)

        response = self.client.delete(f"/_private/api/tenant/{self.tenant.org_id}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Tenant cannot be deleted.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_tenant_allowed_but_group_is_not_system(self):
        """Test that we cannot delete a tenant when allowed but modified."""
        self.group.system = False
        self.group.save()

        response = self.client.delete(f"/_private/api/tenant/{self.tenant.org_id}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Tenant cannot be deleted.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_tenant_allowed_but_role_is_not_system(self):
        """Test that we cannot delete a tenant when allowed but modified."""
        self.role.system = False
        self.role.save()

        response = self.client.delete(f"/_private/api/tenant/{self.tenant.org_id}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Tenant cannot be deleted.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_tenant_allowed_but_custom_one_role_is_not_system(self):
        """Test that we cannot delete a tenant when allowed but modified."""
        Role.objects.create(name="Custom Role", tenant=self.tenant)

        response = self.client.delete(f"/_private/api/tenant/{self.tenant.org_id}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Tenant cannot be deleted.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch.object(Tenant, "delete")
    def test_delete_tenant_allowed_and_unmodified_no_roles_or_groups(self, mock):
        """Test that we can delete a tenant when allowed and unmodified when there are no roles or groups."""
        Group.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()

        response = self.client.delete(f"/_private/api/tenant/{self.tenant.org_id}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_list_unmodified_tenants(self):
        """Test that only unmodified tenants are returned"""
        modified_tenant_groups = Tenant.objects.create(tenant_name="acctmodifiedgroups", org_id="1111")
        modified_tenant_roles = Tenant.objects.create(tenant_name="acctmodifiedroles", org_id="2222")
        unmodified_tenant_2 = Tenant.objects.create(tenant_name="acctunmodified2", org_id="3333")

        for t in [modified_tenant_groups, modified_tenant_roles, unmodified_tenant_2]:
            t.ready = True
            t.save()

        Group.objects.create(name="Custom Group", tenant=modified_tenant_groups)

        Role.objects.create(name="Custom Role", tenant=modified_tenant_roles)

        Group.objects.create(name="System Group", system=True, tenant=unmodified_tenant_2)
        Role.objects.create(name="System Role", system=True, tenant=unmodified_tenant_2)

        response = self.client.get(f"/_private/api/tenant/unmodified/", **self.request.META)
        response_data = json.loads(response.content)
        if settings.AUTHENTICATE_WITH_ORG_ID:
            self.assertCountEqual(
                response_data["unmodified_tenants"], [self.tenant.org_id, unmodified_tenant_2.org_id]
            )
        else:
            self.assertCountEqual(
                response_data["unmodified_tenants"], [self.tenant.tenant_name, unmodified_tenant_2.tenant_name]
            )
        self.assertEqual(response_data["unmodified_tenants_count"], 2)
        self.assertEqual(response_data["total_tenants_count"], 4)

        # the public schema is created in migrations but excluded from the internal view
        self.assertEqual(Tenant.objects.count(), 5)

        response = self.client.get(f"/_private/api/tenant/unmodified/?limit=2", **self.request.META)
        response_data = json.loads(response.content)
        self.assertEqual(response_data["total_tenants_count"], 2)

        response = self.client.get(f"/_private/api/tenant/unmodified/?limit=2&offset=3", **self.request.META)
        response_data = json.loads(response.content)
        self.assertEqual(response_data["total_tenants_count"], 1)

    @patch("management.tasks.run_migrations_in_worker.delay")
    def test_run_migrations(self, migration_mock):
        """Test that we can trigger migrations."""
        response = self.client.post(f"/_private/api/migrations/run/", **self.request.META)
        migration_mock.assert_called_once()
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.content.decode(), "Migrations are running in a background worker.")

    def test_list_migration_progress_without_migration_name(self):
        """Test that we get a 400 when no migration name supplied."""
        url = f"/_private/api/migrations/progress/"
        response = self.client.get(url, **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Please specify a migration name in the `?migration_name=` param.")

    @patch("management.tasks.run_seeds_in_worker.delay")
    def test_run_seeds_with_defaults(self, seed_mock):
        """Test that we can trigger seeds with defaults."""
        response = self.client.post(f"/_private/api/seeds/run/", **self.request.META)
        seed_mock.assert_called_once_with({})
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.content.decode(), "Seeds are running in a background worker.")

    @patch("management.tasks.run_seeds_in_worker.delay")
    def test_run_seeds_with_options(self, seed_mock):
        """Test that we can trigger seeds with options."""
        response = self.client.post(f"/_private/api/seeds/run/?seed_types=roles,groups", **self.request.META)
        seed_mock.assert_called_once_with({"roles": True, "groups": True})
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.content.decode(), "Seeds are running in a background worker.")

    @patch("management.tasks.run_seeds_in_worker.delay")
    def test_run_seeds_with_invalid_options(self, seed_mock):
        """Test that we get a 400 when invalid option supplied."""
        response = self.client.post(f"/_private/api/seeds/run/?seed_types=foo,bar", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        seed_mock.assert_not_called()
        self.assertEqual(
            response.content.decode(), "Valid options for \"seed_types\": ['permissions', 'roles', 'groups']."
        )

    @patch("api.tasks.populate_tenant_account_id_in_worker.delay")
    def test_populate_tenant_account_id(self, populate_mock):
        """Test that we can trigger population of account id's for tenants."""
        response = self.client.post(f"/_private/api/utils/populate_tenant_account_id/", **self.request.META)
        populate_mock.assert_called_once_with()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.content.decode(), "Tenant objects account_id values being updated in background worker."
        )

    @patch("api.tasks.populate_tenant_account_id_in_worker.delay")
    def test_populate_tenant_account_id_get_failure(self, populate_mock):
        """Test that we get a bad request for not using POST method."""
        response = self.client.get(f"/_private/api/utils/populate_tenant_account_id/", **self.request.META)
        populate_mock.assert_not_called()
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(response.content.decode(), 'Invalid method, only "POST" is allowed.')

    def test_get_invalid_default_admin_groups(self):
        """Test that we can get invalid groups."""
        invalid_admin_default_group = Group.objects.create(
            admin_default=True, system=False, tenant=self.tenant, name="Invalid Default Admin Group"
        )
        valid_admin_default_group = Group.objects.create(
            admin_default=True, system=True, tenant=self.public_tenant, name="Valid Default Admin Group"
        )
        response = self.client.get(f"/_private/api/utils/invalid_default_admin_groups/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = json.loads(response.content)
        self.assertEqual(response_data["invalid_default_admin_groups_count"], 1)
        self.assertEqual(len(response_data["invalid_default_admin_groups"]), 1)
        self.assertEqual(
            response_data["invalid_default_admin_groups"][0],
            {
                "name": invalid_admin_default_group.name,
                "admin_default": invalid_admin_default_group.admin_default,
                "system": invalid_admin_default_group.system,
                "platform_default": invalid_admin_default_group.platform_default,
                "tenant": invalid_admin_default_group.tenant.id,
            },
        )

    def test_delete_invalid_default_admin_groups_disallowed(self):
        """Test that we cannot delete invalid groups when disallowed."""
        response = self.client.delete(f"/_private/api/utils/invalid_default_admin_groups/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Destructive operations disallowed.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_invalid_default_admin_groups(self):
        """Test that we can delete invalid groups when allowed."""
        invalid_admin_default_group = Group.objects.create(
            admin_default=True, system=False, tenant=self.tenant, name="Invalid Default Admin Group"
        )
        valid_admin_default_group = Group.objects.create(
            admin_default=True, system=True, tenant=self.public_tenant, name="Valid Default Admin Group"
        )
        self.assertEqual(Group.objects.count(), 3)
        response = self.client.delete(f"/_private/api/utils/invalid_default_admin_groups/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Group.objects.count(), 2)
        self.assertEqual(Group.objects.filter(id=valid_admin_default_group.id).exists(), True)
        self.assertEqual(Group.objects.filter(id=invalid_admin_default_group.id).exists(), False)
