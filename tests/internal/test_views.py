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
from tenant_schemas.utils import tenant_context
from unittest.mock import patch
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
        self.customer = self._create_customer_data()
        self.internal_request_context = self._create_request_context(
            self.customer, self.user_data, create_customer=False, is_internal=True, create_tenant=True
        )

        self.request = self.internal_request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        self.request.user = user

        with tenant_context(self.tenant):
            self.group = Group(name="System Group", system=True)
            self.group.save()
            self.role = Role.objects.create(name="System Role", description="A role for a group.", system=True)
            self.policy = Policy.objects.create(name="System Policy", group=self.group)
            self.policy.roles.add(self.role)
            self.policy.save()
            self.group.policies.add(self.policy)
            self.group.save()

    def tearDown(self):
        """Tear down internal viewset tests."""
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Role.objects.all().delete()
            Policy.objects.all().delete()

    def test_delete_tenant_disallowed(self):
        """Test that we cannot delete a tenant when disallowed."""
        response = self.client.delete(f"/_private/api/tenant/{self.tenant.schema_name}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Destructive operations disallowed.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=invalid_destructive_time())
    def test_delete_tenant_disallowed_with_past_timestamp(self):
        """Test that we cannot delete a tenant when disallowed."""
        response = self.client.delete(f"/_private/api/tenant/{self.tenant.schema_name}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Destructive operations disallowed.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch.object(Tenant, "delete")
    def test_delete_tenant_allowed_and_unmodified(self, mock):
        """Test that we can delete a tenant when allowed and unmodified."""
        response = self.client.delete(f"/_private/api/tenant/{self.tenant.schema_name}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_tenant_allowed_but_multiple_groups(self):
        """Test that we cannot delete a tenant when allowed but modified."""
        with tenant_context(self.tenant):
            Group.objects.create(name="Custom Group")

        response = self.client.delete(f"/_private/api/tenant/{self.tenant.schema_name}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Tenant cannot be deleted.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_tenant_allowed_but_group_is_not_system(self):
        """Test that we cannot delete a tenant when allowed but modified."""
        with tenant_context(self.tenant):
            self.group.system = False
            self.group.save()

        response = self.client.delete(f"/_private/api/tenant/{self.tenant.schema_name}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Tenant cannot be deleted.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_tenant_allowed_but_role_is_not_system(self):
        """Test that we cannot delete a tenant when allowed but modified."""
        with tenant_context(self.tenant):
            self.role.system = False
            self.role.save()

        response = self.client.delete(f"/_private/api/tenant/{self.tenant.schema_name}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Tenant cannot be deleted.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_tenant_allowed_but_custom_one_role_is_not_system(self):
        """Test that we cannot delete a tenant when allowed but modified."""
        with tenant_context(self.tenant):
            Role.objects.create(name="Custom Role")

        response = self.client.delete(f"/_private/api/tenant/{self.tenant.schema_name}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Tenant cannot be deleted.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch.object(Tenant, "delete")
    def test_delete_tenant_allowed_and_unmodified_no_roles_or_groups(self, mock):
        """Test that we can delete a tenant when allowed and unmodified when there are no roles or groups."""
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Role.objects.all().delete()
            Policy.objects.all().delete()

        response = self.client.delete(f"/_private/api/tenant/{self.tenant.schema_name}/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_list_unmodified_tenants(self):
        """Test that only unmodified tenants are returned"""
        modified_tenant_groups = Tenant.objects.create(schema_name="acctmodifiedgroups")
        modified_tenant_roles = Tenant.objects.create(schema_name="acctmodifiedroles")
        unmodified_tenant_2 = Tenant.objects.create(schema_name="acctunmodified2")

        for t in [modified_tenant_groups, modified_tenant_roles, unmodified_tenant_2]:
            t.create_schema()
            t.ready = True
            t.save()

        with tenant_context(modified_tenant_groups):
            Group.objects.create(name="Custom Group")

        with tenant_context(modified_tenant_roles):
            Role.objects.create(name="Custom Role")

        with tenant_context(unmodified_tenant_2):
            Group.objects.create(name="System Group", system=True)
            Role.objects.create(name="System Role", system=True)

        response = self.client.get(f"/_private/api/tenant/unmodified/", **self.request.META)
        response_data = json.loads(response.content)
        self.assertCountEqual(
            response_data["unmodified_tenants"], [self.tenant.schema_name, unmodified_tenant_2.schema_name]
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

    def test_list_migration_progress(self):
        """Test that we can get the status of migrations."""
        migration_name = "foo_migration"
        app_name = "foo_app"
        tenant_migrations_complete = Tenant.objects.create(schema_name="acctcomplete")
        tenant_migrations_incomplete = Tenant.objects.create(schema_name="acctincomplete")
        for t in [tenant_migrations_complete, tenant_migrations_incomplete]:
            t.create_schema()

        with tenant_context(tenant_migrations_complete):
            migrations_have_run = MigrationRecorder.Migration.objects.create(name=migration_name, app=app_name)

        url = f"/_private/api/migrations/progress/?migration_name={migration_name}&app={app_name}"
        response = self.client.get(url, **self.request.META)
        response_data = json.loads(response.content)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response_data["migration_name"], migration_name)
        self.assertEqual(response_data["app_name"], app_name)
        self.assertEqual(response_data["tenants_completed_count"], 1)
        self.assertEqual(response_data["percent_completed"], 33)
        self.assertIn("acctincomplete", response_data["incomplete_tenants"])
        self.assertNotIn("acctcomplete", response_data["incomplete_tenants"])
        self.assertEqual(len(response_data["incomplete_tenants"]), 2)

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
