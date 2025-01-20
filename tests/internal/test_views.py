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
import logging

from rest_framework import status
from rest_framework.test import APIClient
from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from datetime import datetime, timedelta
from unittest.mock import MagicMock
from unittest.mock import patch
import pytz
import json

from api.models import User, Tenant
from api.utils import reset_imported_tenants
from management.audit_log.model import AuditLog
from management.cache import TenantCache
from management.models import BindingMapping, Group, Permission, Policy, Role, Workspace
from management.principal.model import Principal
from management.relation_replicator.noop_replicator import NoopReplicator
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType
from management.role.model import Access, ResourceDefinition
from management.tenant_mapping.model import TenantMapping
from management.tenant_service.v1 import V1TenantBootstrapService
from management.tenant_service.v2 import V2TenantBootstrapService
from management.workspace.model import Workspace
from migration_tool.in_memory_tuples import InMemoryRelationReplicator, InMemoryTuples
from migration_tool.utils import create_relationship
from rbac.settings import REPLICATION_TO_RELATION_ENABLED
from tests.identity_request import IdentityRequest
from tests.management.role.test_dual_write import RbacFixture


@override_settings(
    LOGGING={
        "version": 1,
        "disable_existing_loggers": False,
        "loggers": {
            "management.relation_replicator.outbox_replicator": {
                "level": "INFO",
            },
        },
    },
)
class InternalViewsetTests(IdentityRequest):
    """Test the internal viewset."""

    _tuples: InMemoryTuples

    def valid_destructive_time():
        return datetime.utcnow().replace(tzinfo=pytz.UTC) + timedelta(hours=1)

    def invalid_destructive_time():
        return datetime.utcnow().replace(tzinfo=pytz.UTC) - timedelta(hours=1)

    def setUp(self):
        """Set up the internal viewset tests."""
        super().setUp()
        self.client = APIClient()
        self.customer = self.customer_data
        self.internal_request_context = self._create_request_context(self.customer, self.user_data, is_internal=True)

        self.request = self.internal_request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        self.request.user = user

        self.group = Group(name="System Group", system=True, tenant=self.tenant)
        self.group.save()
        self.role = Role.objects.create(
            name="System Role",
            description="A role for a group.",
            system=True,
            tenant=self.tenant,
        )
        self.policy = Policy.objects.create(name="System Policy", group=self.group, tenant=self.tenant)
        self.policy.roles.add(self.role)
        self.policy.save()
        self.group.policies.add(self.policy)
        self.group.save()
        self.public_tenant = Tenant.objects.get(tenant_name="public")

        self._prior_logging_disable_level = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self._tuples = InMemoryTuples()

    def tearDown(self):
        """Tear down internal viewset tests."""
        Group.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()
        logging.disable(self._prior_logging_disable_level)

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
        self.assertCountEqual(response_data["unmodified_tenants"], [self.tenant.org_id, unmodified_tenant_2.org_id])

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
        self.assertEqual(
            response.content.decode(),
            "Please specify a migration name in the `?migration_name=` param.",
        )

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
            response.content.decode(),
            "Valid options for \"seed_types\": ['permissions', 'roles', 'groups'].",
        )

    @patch("api.tasks.populate_tenant_account_id_in_worker.delay")
    def test_populate_tenant_account_id(self, populate_mock):
        """Test that we can trigger population of account id's for tenants."""
        response = self.client.post(f"/_private/api/utils/populate_tenant_account_id/", **self.request.META)
        populate_mock.assert_called_once_with()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.content.decode(),
            "Tenant objects account_id values being updated in background worker.",
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
            admin_default=True,
            system=False,
            tenant=self.tenant,
            name="Invalid Default Admin Group",
        )
        valid_admin_default_group = Group.objects.create(
            admin_default=True,
            system=True,
            tenant=self.public_tenant,
            name="Valid Default Admin Group",
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
            admin_default=True,
            system=False,
            tenant=self.tenant,
            name="Invalid Default Admin Group",
        )
        valid_admin_default_group = Group.objects.create(
            admin_default=True,
            system=True,
            tenant=self.public_tenant,
            name="Valid Default Admin Group",
        )
        self.assertEqual(Group.objects.count(), 3)
        response = self.client.delete(f"/_private/api/utils/invalid_default_admin_groups/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Group.objects.count(), 2)
        self.assertEqual(Group.objects.filter(id=valid_admin_default_group.id).exists(), True)
        self.assertEqual(Group.objects.filter(id=invalid_admin_default_group.id).exists(), False)

    def test_get_org_admin_type_not_set(self):
        """Test that we get a bad request for not using type query param."""
        response = self.client.get(f"/_private/api/utils/get_org_admin/123456/", **self.request.META)
        option_key = "type"
        valid_values = ["account_id", "org_id"]
        expected_message = (
            f'Invalid request, must supply the "{option_key}" query parameter; Valid values: {valid_values}.'
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), expected_message)

    def test_get_org_admin_bad_type(self):
        """Test that we get a bad request for not using type query param."""
        response = self.client.get(
            f"/_private/api/utils/get_org_admin/123456/?type=foobar",
            **self.request.META,
        )
        option_key = "type"
        valid_values = ["account_id", "org_id"]
        expected_message = f'Valid options for "{option_key}": {valid_values}.'
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), expected_message)

    def test_get_org_admin_post(self):
        """Test that we get a bad request for not using GET method."""
        response = self.client.post(f"/_private/api/utils/get_org_admin/123456/", **self.request.META)
        expected_message = 'Invalid method, only "GET" is allowed.'
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertEqual(response.content.decode(), expected_message)

    def test_get_org_admin_bad_connection(self):
        """Test getting the org admin and failing to connect to BOP."""
        response = self.client.get(
            "/_private/api/utils/get_org_admin/123456/?type=account_id",
            **self.request.META,
        )
        expected_message = "Unable to connect for URL"
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn(expected_message, response.content.decode())

    @patch("internal.views.requests")
    def test_get_org_admin_account(self, mock_proxy):
        """Test getting the org admin back with mock proxy using account id."""
        mockresponse = MagicMock()
        mockresponse.status_code = 200
        mockresponse.json.return_value = {
            "userCount": "1",
            "users": [{"username": "test_user"}],
        }
        users = [{"username": "test_user"}]
        mock_proxy.get.return_value = mockresponse
        response = self.client.get(
            "/_private/api/utils/get_org_admin/123456/?type=account_id",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        string_data = response.content.decode()
        dictionary_data = eval(string_data.replace("null", "None"))
        self.assertEqual(users, dictionary_data.get("data"))

    @patch("internal.views.requests")
    def test_get_org_admin_org_id(self, mock_proxy):
        """Test getting the org admin back with mock proxy using org id."""
        mockresponse = MagicMock()
        mockresponse.status_code = 200
        mockresponse.json.return_value = {
            "userCount": "1",
            "users": [{"username": "test_user"}],
        }
        users = [{"username": "test_user"}]
        mock_proxy.get.return_value = mockresponse
        response = self.client.get("/_private/api/utils/get_org_admin/123456/?type=org_id", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        string_data = response.content.decode()
        dictionary_data = eval(string_data.replace("null", "None"))
        self.assertEqual(users, dictionary_data.get("data"))

    @patch("internal.views.requests")
    def test_get_org_admin_bad_proxy_response(self, mock_proxy):
        """Test getting the org admin with bad proxy response."""
        mockresponse = MagicMock()
        mockresponse.status_code = 500
        mockresponse.json.return_value = {"error": "some error"}
        mock_proxy.get.return_value = mockresponse
        response = self.client.get("/_private/api/utils/get_org_admin/123456/?type=org_id", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        string_data = response.content.decode()
        dictionary_data = eval(string_data.replace("null", "None"))
        self.assertEqual(dictionary_data, mockresponse.json.return_value)

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=invalid_destructive_time())
    def test_delete_selective_roles_disallowed(self):
        """Test that we cannot delete selective roles when disallowed."""
        response = self.client.delete(f"/_private/api/utils/role/?name={self.role.name}", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Destructive operations disallowed.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_selective_roles(self):
        """Test that we can delete selective roles when allowed and no roles."""
        # No name specified
        response = self.client.delete(f"/_private/api/utils/role/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # No role found
        response = self.client.delete("/_private/api/utils/role/?name=non_exist_name", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Custom roles cannot be deleted
        response = self.client.delete(f"/_private/api/utils/role/?name={self.role.name}", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Delete successful
        self.role.tenant = self.public_tenant
        self.role.save()
        response = self.client.delete(f"/_private/api/utils/role/?name={self.role.name}", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=invalid_destructive_time())
    def test_delete_selective_permission_disallowed(self):
        """Test that we cannot delete selective permission when disallowed."""
        response = self.client.delete("/_private/api/utils/permission/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.content.decode(), "Destructive operations disallowed.")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_selective_permission(self):
        """Test that we can delete selective permission when allowed and no permissions."""
        # No permission param specified
        response = self.client.delete("/_private/api/utils/permission/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # No permission found
        response = self.client.delete(
            "/_private/api/utils/permission/?permission=rbac:roles:write",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        Permission.objects.create(permission="rbac:roles:write", tenant=self.tenant)
        response = self.client.delete(
            "/_private/api/utils/permission/?permission=rbac:roles:write",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    @override_settings(READ_ONLY_API_MODE=True)
    @patch("management.tasks.migrate_data_in_worker.delay")
    def test_run_migrations_of_data(self, migration_mock):
        """Test that we can trigger migrations of data to migrate from V1 to V2."""
        response = self.client.post(
            f"/_private/api/utils/data_migration/?exclude_apps=rbac,costmanagement&orgs=acct00001,acct00002",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        migration_mock.assert_called_once_with(
            {
                "exclude_apps": ["rbac", "costmanagement"],
                "orgs": ["acct00001", "acct00002"],
                "write_relationships": "False",
                "skip_roles": False,
            }
        )
        self.assertEqual(
            response.content.decode(),
            "Data migration from V1 to V2 are running in a background worker.",
        )

        # Without params uses global default
        with self.settings(V2_MIGRATION_APP_EXCLUDE_LIST=["fooapp"]):
            migration_mock.reset_mock()
            response = self.client.post(
                f"/_private/api/utils/data_migration/",
                **self.request.META,
            )
            migration_mock.assert_called_once_with(
                {"exclude_apps": ["fooapp"], "orgs": [], "write_relationships": "False", "skip_roles": False}
            )
            self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
            self.assertEqual(
                response.content.decode(),
                "Data migration from V1 to V2 are running in a background worker.",
            )

        # Without params uses none if no global default
        with self.settings(V2_MIGRATION_APP_EXCLUDE_LIST=[]):
            migration_mock.reset_mock()
            response = self.client.post(
                f"/_private/api/utils/data_migration/",
                **self.request.META,
            )
            migration_mock.assert_called_once_with(
                {"exclude_apps": [], "orgs": [], "write_relationships": "False", "skip_roles": False}
            )
            self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
            self.assertEqual(
                response.content.decode(),
                "Data migration from V1 to V2 are running in a background worker.",
            )

    @patch("management.tasks.migrate_data_in_worker.delay")
    def test_run_migrations_of_data_outbox_replication(self, migration_mock):
        """Test that we can trigger migrations of data to migrate from V1 to V2."""
        response = self.client.post(
            f"/_private/api/utils/data_migration/?exclude_apps=rbac,costmanagement&orgs=acct00001,acct00002"
            "&write_relationships=outbox",
            **self.request.META,
        )
        migration_mock.assert_called_once_with(
            {
                "exclude_apps": ["rbac", "costmanagement"],
                "orgs": ["acct00001", "acct00002"],
                "write_relationships": "outbox",
                "skip_roles": False,
            }
        )
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(
            response.content.decode(),
            "Data migration from V1 to V2 are running in a background worker.",
        )

    def test_list_bindings_by_role(self):
        """Test that we can list bindingmapping by role."""
        response = self.client.get(
            f"/_private/api/utils/bindings/{self.role.uuid}/",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "[]")

        binding_attrs = {
            "resource_id": "123456",
            "resource_type_namespace": "rbac",
            "resource_type_name": "workspace",
            "mappings": {"foo": "bar"},
        }
        # Create a binding mapping
        binding_mapping = BindingMapping.objects.create(
            role=self.role,
            **binding_attrs,
        )
        response = self.client.get(
            f"/_private/api/utils/bindings/{self.role.uuid}/",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        binding_attrs.update({"id": binding_mapping.id, "role": self.role.id})
        self.assertEqual(json.loads(response.content.decode()), [binding_attrs])

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_delete_bindings_by_role(self, replicate):
        """Test that we can delete bindingmapping by role."""
        replicator = InMemoryRelationReplicator(self._tuples)
        replicate.side_effect = replicator.replicate
        binding_mapping_id = "abcdefg"
        workspace_id = "123456"
        relations = [
            create_relationship(
                ("rbac", "role_binding"),
                binding_mapping_id,
                ("rbac", "role"),
                str(self.role.uuid),
                "role",
            ),
            create_relationship(
                ("rbac", "workspace"),
                workspace_id,
                ("rbac", "role_binding"),
                binding_mapping_id,
                "binding",
            ),
        ]
        self._tuples.write(relations, [])
        bindings_attrs = [
            {
                "resource_id": workspace_id,
                "resource_type_namespace": "rbac",
                "resource_type_name": "workspace",
                "mappings": {
                    "id": binding_mapping_id,
                    "role": {"is_system": True, "id": str(self.role.uuid), "permissions": []},
                },
            },
            {
                "resource_id": workspace_id,
                "resource_type_namespace": "rbac",
                "resource_type_name": "workspace",
                "mappings": {"foo": "bar"},
            },
        ]
        self._tuples.find_tuples()
        # Create binding mappings
        binding_mappings = BindingMapping.objects.bulk_create(
            [BindingMapping(role=self.role, **binding_attrs) for binding_attrs in bindings_attrs]
        )
        response = self.client.delete(
            f"/_private/api/utils/bindings/{self.role.uuid}/?mappings__role__is_system=True",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        with self.assertRaises(BindingMapping.DoesNotExist):
            binding_mappings[0].refresh_from_db()
        binding_mappings[1].refresh_from_db()
        self.assertEqual(self._tuples.find_tuples(), [])

    def test_bootstrapping_tenant(self):
        """Test that we can bootstrap a tenant."""
        org_id = "12345"
        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/?org_id={org_id}",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        tenant = Tenant.objects.create(org_id=org_id)
        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/?org_id={org_id}",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        Workspace.objects.filter(tenant=tenant, type=Workspace.Types.ROOT).exists()
        Workspace.objects.filter(tenant=tenant, type=Workspace.Types.DEFAULT).exists()
        self.assertTrue(getattr(tenant, "tenant_mapping"))

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_bootstrapping_existing_tenant_without_force_does_nothing(self, replicate):
        tuples = InMemoryTuples()
        replicator = InMemoryRelationReplicator(tuples)
        replicate.side_effect = replicator.replicate
        fixture = RbacFixture(V2TenantBootstrapService(replicator))

        org_id = "12345"

        fixture.new_tenant(org_id)
        tuples.clear()

        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/?org_id={org_id}",
            **self.request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(tuples), 0)

        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/?org_id={org_id}&force=false",
            **self.request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(tuples), 0)

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @override_settings(REPLICATION_TO_RELATION_ENABLED=False)
    def test_force_bootstrapping_tenant(self, replicate):
        tuples = InMemoryTuples()
        replicator = InMemoryRelationReplicator(tuples)
        replicate.side_effect = replicator.replicate
        fixture = RbacFixture(V2TenantBootstrapService(replicator))

        org_id = "12345"

        fixture.new_tenant(org_id)
        tuples.clear()

        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/?org_id={org_id}&force=true",
            **self.request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(tuples), 9)

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    def test_cannot_force_bootstrapping_while_replication_enabled(self):
        org_id = "12345"
        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/?org_id={org_id}&force=true",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_listing_migration_resources(self):
        """Test that we can list migration resources."""
        org_id = "12345678"
        bootstrap_service = V2TenantBootstrapService(NoopReplicator())
        bootstrapped_tenant = bootstrap_service.bootstrap_tenant(self.tenant)
        another_bootstrapped_tenant = bootstrap_service.new_bootstrapped_tenant(org_id)
        another_tenant = another_bootstrapped_tenant.tenant
        root_workspaces = [bootstrapped_tenant.root_workspace, another_bootstrapped_tenant.root_workspace]
        default_workspaces = [
            bootstrapped_tenant.default_workspace,
            another_bootstrapped_tenant.default_workspace,
        ]

        # Test limit and offset
        response = self.client.get(
            "/_private/api/utils/migration_resources/?resource=workspace&limit=1",
            **self.request.META,
        )
        workspace_list_1 = json.loads(response.getvalue())
        self.assertEqual(len(workspace_list_1), 1)
        response = self.client.get(
            "/_private/api/utils/migration_resources/?resource=workspace&limit=1&offset=1",
            **self.request.META,
        )
        workspace_list_2 = json.loads(response.getvalue())
        self.assertEqual(len(workspace_list_2), 1)
        self.assertNotEqual(workspace_list_1, workspace_list_2)

        response = self.client.get(
            "/_private/api/utils/migration_resources/?resource=workspace",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        id_set = {str(workspace.id) for workspace in default_workspaces}
        for workspace in root_workspaces:
            id_set.add(str(workspace.id))
        self.assertEqual(set(json.loads(response.getvalue())), id_set)

        response = self.client.get(
            f"/_private/api/utils/migration_resources/?resource=workspace&org_id={org_id}",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            set(json.loads(response.getvalue())), {str(default_workspaces[1].id), str(root_workspaces[1].id)}
        )

        # Listing tenantmappings
        tenant_mappings = [bootstrapped_tenant.mapping, another_bootstrapped_tenant.mapping]
        response = self.client.get(
            "/_private/api/utils/migration_resources/?resource=mapping",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            set(json.loads(response.getvalue())), {str(tenant_mapping.id) for tenant_mapping in tenant_mappings}
        )
        response = self.client.get(
            f"/_private/api/utils/migration_resources/?resource=mapping&org_id={org_id}",
            **self.request.META,
        )
        self.assertEqual(json.loads(response.getvalue()), [str(tenant_mappings[1].id)])

        # List bindingmappings
        tenant_role = Role.objects.create(
            name="role",
            tenant=self.tenant,
        )
        another_role = Role.objects.create(
            name="role",
            tenant=another_tenant,
        )
        binding = BindingMapping.objects.create(
            role=tenant_role,
        )
        another_binding = BindingMapping.objects.create(
            role=another_role,
        )
        response = self.client.get(
            "/_private/api/utils/migration_resources/?resource=binding",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(set(json.loads(response.getvalue())), {str(binding.id), str(another_binding.id)})

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("api.tasks.run_migration_resource_deletion.delay")
    def test_deleting_migration_resources(self, delay_mock):
        """Test that we can delete migration resources."""
        org_id = "12345678"
        response = self.client.delete(
            f"/_private/api/utils/migration_resources/?resource=workspace&org_id={org_id}",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        delay_mock.assert_called_once_with(
            {
                "resource": "workspace",
                "org_id": org_id,
            }
        )

    def test_reset_imported_tenants_get_does_not_include_sample_tenant_with_tenanted_resources(self):
        response = self.client.get("/_private/api/utils/reset_imported_tenants/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "0 tenants would be deleted")

    def test_reset_imported_tenants_get_does_not_include_tenant_with_principals(self):
        self.fixture = RbacFixture(V1TenantBootstrapService())
        o1 = self.fixture.new_tenant("o1")
        self.fixture.new_principals_in_tenant(["u1"], o1.tenant)
        response = self.client.get("/_private/api/utils/reset_imported_tenants/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "0 tenants would be deleted")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("api.tasks.run_reset_imported_tenants.delay")
    def test_reset_imported_tenants_does_not_delete_public_tenant(self, delay):
        delay.side_effect = lambda args: reset_imported_tenants(**args)
        self.assertTrue(Tenant.objects.filter(tenant_name="public").exists())

        with self.assertLogs("api.utils", level="INFO") as logs:
            response = self.client.delete("/_private/api/utils/reset_imported_tenants/", **self.request.META)

        self.assertIn("Deleted 0 tenants.", logs.output[0])
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(Tenant.objects.filter(tenant_name="public").exists())

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("api.tasks.run_reset_imported_tenants.delay")
    def test_reset_imported_tenants_removes_tenants_without_tenanted_objects(self, delay):
        delay.side_effect = lambda args: reset_imported_tenants(**args)
        self.fixture = RbacFixture(V1TenantBootstrapService())
        o1 = self.fixture.new_tenant("o1")
        o2 = self.fixture.new_tenant("o2")
        self.fixture.new_tenant("o3")
        self.fixture.new_tenant("o4")
        self.fixture.new_principals_in_tenant(["u1"], o1.tenant)
        self.fixture.new_principals_in_tenant(["u2"], o2.tenant)

        with self.assertLogs("api.utils", level="INFO") as logs:
            response = self.client.delete("/_private/api/utils/reset_imported_tenants/", **self.request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Deleted 2 tenants.", logs.output[0])
        self.assertTrue(Tenant.objects.filter(org_id="o1").exists())
        self.assertTrue(Tenant.objects.filter(org_id="o2").exists())
        self.assertFalse(Tenant.objects.filter(org_id="o3").exists())
        self.assertFalse(Tenant.objects.filter(org_id="o4").exists())

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("api.tasks.run_reset_imported_tenants.delay")
    def test_reset_imported_tenants_removes_up_to_limit(self, delay):
        delay.side_effect = lambda args: reset_imported_tenants(**args)

        self.fixture = RbacFixture(V1TenantBootstrapService())
        for i in range(10):
            self.fixture.new_tenant(f"o{i}")

        with self.assertLogs("api.utils", level="INFO") as logs:
            response = self.client.delete("/_private/api/utils/reset_imported_tenants/?limit=3", **self.request.META)

        self.assertIn("Deleted 3 tenants.", logs.output[0])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # two extra tenants for test tenant and public tenant
        self.assertEqual(Tenant.objects.count(), 9)

    def test_reset_imported_tenants_get_counts_all_tenants_to_be_deleted(self):
        self.fixture = RbacFixture(V1TenantBootstrapService())
        o1 = self.fixture.new_tenant("o1")
        o2 = self.fixture.new_tenant("o2")
        self.fixture.new_principals_in_tenant(["u1"], o1.tenant)
        self.fixture.new_principals_in_tenant(["u2"], o2.tenant)

        for i in range(100):
            self.fixture.new_tenant(f"o{i + 3}")

        response = self.client.get("/_private/api/utils/reset_imported_tenants/", **self.request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "100 tenants would be deleted")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("api.tasks.run_reset_imported_tenants.delay")
    def test_reset_imported_tenants_no_tenanted_objects_allow_tenant_to_be_deleted(self, delay):
        delay.side_effect = lambda args: reset_imported_tenants(**args)
        self.fixture = RbacFixture(V1TenantBootstrapService())

        for object in [
            (Principal, {"username": "u1"}),
            (TenantMapping, {}),
            (Access, {}),
            (Group, {}),
            (Permission, {"permission": "test:app:foo"}),
            (Policy, {}),
            (ResourceDefinition, {}),
            (Role, {}),
            (AuditLog, {}),
            (Workspace, {"name": "Root", "type": Workspace.Types.ROOT}),
        ]:
            model, kwargs = object
            # Create a new tenant
            t = self.fixture.new_tenant(f"o_{model.__name__}")
            # Create an object that references the tenant
            model.objects.create(tenant=t.tenant, **kwargs)

        # Now create some tenants that don't have any of these
        self.fixture.new_tenant("o_no_objects1")
        self.fixture.new_tenant("o_no_objects2")
        self.fixture.new_tenant("o_no_objects3")
        self.fixture.new_tenant("o_no_objects4")

        with self.assertLogs("api.utils", level="INFO") as logs:
            response = self.client.delete("/_private/api/utils/reset_imported_tenants/", **self.request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Deleted 4 tenants.", logs.output[0])
        # two extra tenants for test tenant and public tenant
        self.assertEqual(Tenant.objects.count(), 12)
        self.assertFalse(Tenant.objects.filter(org_id="o_no_objects1").exists())
        self.assertFalse(Tenant.objects.filter(org_id="o_no_objects2").exists())
        self.assertFalse(Tenant.objects.filter(org_id="o_no_objects3").exists())
        self.assertFalse(Tenant.objects.filter(org_id="o_no_objects4").exists())

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("api.tasks.run_reset_imported_tenants.delay")
    def test_reset_imported_tenants_no_tenanted_objects_allow_tenant_to_be_deleted_with_limit(self, delay):
        delay.side_effect = lambda args: reset_imported_tenants(**args)
        self.fixture = RbacFixture(V1TenantBootstrapService())

        for object in [
            (Principal, {"username": "u1"}),
            (TenantMapping, {}),
            (Access, {}),
            (Group, {}),
            (Permission, {"permission": "test:app:foo"}),
            (Policy, {}),
            (ResourceDefinition, {}),
            (Role, {}),
            (AuditLog, {}),
            (Workspace, {"name": "Root", "type": Workspace.Types.ROOT}),
        ]:
            model, kwargs = object
            # Create a new tenant
            t = self.fixture.new_tenant(f"o_{model.__name__}")
            # Create an object that references the tenant
            model.objects.create(tenant=t.tenant, **kwargs)

        # Now create some tenants that don't have any of these
        self.fixture.new_tenant("o_no_objects1")
        self.fixture.new_tenant("o_no_objects2")
        self.fixture.new_tenant("o_no_objects3")
        self.fixture.new_tenant("o_no_objects4")

        with self.assertLogs("api.utils", level="INFO") as logs:
            response = self.client.delete("/_private/api/utils/reset_imported_tenants/?limit=1", **self.request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Deleted 1 tenants.", logs.output[0])
        # two extra tenants for test tenant and public tenant
        self.assertEqual(Tenant.objects.count(), 15)
        self.assertFalse(Tenant.objects.filter(org_id="o_no_objects1").exists())
        self.assertTrue(Tenant.objects.filter(org_id="o_no_objects2").exists())
        self.assertTrue(Tenant.objects.filter(org_id="o_no_objects3").exists())
        self.assertTrue(Tenant.objects.filter(org_id="o_no_objects4").exists())

    def test_reset_imported_tenants_get_also_excludes_tenants_with_objects(self):
        self.fixture = RbacFixture(V1TenantBootstrapService())

        for object in [
            (Principal, {"username": "u1"}),
            (TenantMapping, {}),
            (Access, {}),
            (Group, {}),
            (Permission, {"permission": "test:app:foo"}),
            (Policy, {}),
            (ResourceDefinition, {}),
            (Role, {}),
            (AuditLog, {}),
            (Workspace, {"name": "Root", "type": Workspace.Types.ROOT}),
        ]:
            model, kwargs = object
            # Create a new tenant
            t = self.fixture.new_tenant(f"o_{model.__name__}")
            # Create an object that references the tenant
            model.objects.create(tenant=t.tenant, **kwargs)

        # Now create some tenants that don't have any of these
        self.fixture.new_tenant("o_no_objects1")
        self.fixture.new_tenant("o_no_objects2")
        self.fixture.new_tenant("o_no_objects3")
        self.fixture.new_tenant("o_no_objects4")

        response = self.client.get("/_private/api/utils/reset_imported_tenants/", **self.request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "4 tenants would be deleted")

    def test_reset_imported_tenants_get_also_excludes_tenants_with_objects_up_to_limit(self):
        self.fixture = RbacFixture(V1TenantBootstrapService())

        for object in [
            (Principal, {"username": "u1"}),
            (TenantMapping, {}),
            (Access, {}),
            (Group, {}),
            (Permission, {"permission": "test:app:foo"}),
            (Policy, {}),
            (ResourceDefinition, {}),
            (Role, {}),
            (AuditLog, {}),
            (Workspace, {"name": "Root", "type": Workspace.Types.ROOT}),
        ]:
            model, kwargs = object
            # Create a new tenant
            t = self.fixture.new_tenant(f"o_{model.__name__}")
            # Create an object that references the tenant
            model.objects.create(tenant=t.tenant, **kwargs)

        # Now create some tenants that don't have any of these
        self.fixture.new_tenant("o_no_objects1")
        self.fixture.new_tenant("o_no_objects2")
        self.fixture.new_tenant("o_no_objects3")
        self.fixture.new_tenant("o_no_objects4")

        response = self.client.get("/_private/api/utils/reset_imported_tenants/?limit=1", **self.request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "1 tenants would be deleted")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_reset_imported_tenants_does_nothing_if_zero_limit(self):
        self.fixture = RbacFixture(V1TenantBootstrapService())

        self.fixture.new_tenant("o_no_objects1")
        self.fixture.new_tenant("o_no_objects2")
        self.fixture.new_tenant("o_no_objects3")
        self.fixture.new_tenant("o_no_objects4")

        self.assertEqual(6, Tenant.objects.count())

        response = self.client.delete("/_private/api/utils/reset_imported_tenants/?limit=0", **self.request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(6, Tenant.objects.count())

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_reset_imported_tenants_rejects_invalid_limit(self):
        response = self.client.delete("/_private/api/utils/reset_imported_tenants/?limit=foo", **self.request.META)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_reset_imported_tenants_excludes_get(self):
        # Create some tenants that would be deleted but exclude some
        self.fixture = RbacFixture(V1TenantBootstrapService())

        t1 = self.fixture.new_tenant("o_no_objects1").tenant
        self.fixture.new_tenant("o_no_objects2")
        t3 = self.fixture.new_tenant("o_no_objects3").tenant
        self.fixture.new_tenant("o_no_objects4")

        self.assertEqual(6, Tenant.objects.count())

        response = self.client.get(
            f"/_private/api/utils/reset_imported_tenants/?exclude_id={t1.id}&exclude_id={t3.id}",
            **self.request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "2 tenants would be deleted")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("api.tasks.run_reset_imported_tenants.delay")
    def test_reset_imported_tenants_excludes_delete(self, delay):
        delay.side_effect = lambda args: reset_imported_tenants(**args)

        # Create some tenants that would be deleted but exclude some
        self.fixture = RbacFixture(V1TenantBootstrapService())

        t1 = self.fixture.new_tenant("o_no_objects1").tenant
        self.fixture.new_tenant("o_no_objects2")
        t3 = self.fixture.new_tenant("o_no_objects3").tenant
        self.fixture.new_tenant("o_no_objects4")

        self.assertEqual(6, Tenant.objects.count())

        with self.assertLogs("api.utils", level="INFO") as logs:
            response = self.client.delete(
                f"/_private/api/utils/reset_imported_tenants/?exclude_id={t1.id}&exclude_id={t3.id}",
                **self.request.META,
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Deleted 2 tenants.", logs.output[0])
        self.assertEqual(4, Tenant.objects.count())

    def test_update_system_flag_in_role(self):
        """Test that we can update a role."""
        tenant = Tenant.objects.create(tenant_name="1234", org_id="1234")
        custom_role = Role.objects.create(
            name="role 1", system=True, tenant=tenant, platform_default=False, admin_default=False
        )

        request_body = {
            "system": "false",
        }

        json_request_body = json.dumps(request_body)

        self.assertTrue(custom_role.system)
        self.assertFalse(custom_role.platform_default)
        self.assertFalse(custom_role.admin_default)

        response = self.client.put(
            f"/_private/api/roles/{custom_role.uuid}/",
            json_request_body,
            **self.request.META,
            content_type="application/json",
        )

        custom_role.refresh_from_db()

        self.assertFalse(custom_role.system)
        self.assertFalse(custom_role.platform_default)
        self.assertFalse(custom_role.admin_default)
        self.assertEqual(response.status_code, 200)

    def test_update_platform_default_flag_in_role(self):
        """Test that we can update a role."""
        tenant = Tenant.objects.create(tenant_name="1234", org_id="1234")
        custom_role = Role.objects.create(
            name="role 1", system=False, tenant=tenant, platform_default=True, admin_default=False
        )

        request_body = {
            "platform_default": "false",
        }

        json_request_body = json.dumps(request_body)

        self.assertFalse(custom_role.system)
        self.assertTrue(custom_role.platform_default)
        self.assertFalse(custom_role.admin_default)

        response = self.client.put(
            f"/_private/api/roles/{custom_role.uuid}/",
            json_request_body,
            **self.request.META,
            content_type="application/json",
        )

        custom_role.refresh_from_db()

        self.assertFalse(custom_role.system, False)
        self.assertFalse(custom_role.platform_default, False)
        self.assertFalse(custom_role.admin_default, False)
        self.assertEqual(response.status_code, 200)

    def test_update_admin_default_flag_in_role(self):
        """Test that we can update a role."""
        tenant = Tenant.objects.create(tenant_name="1234", org_id="1234")
        custom_role = Role.objects.create(
            name="role 1", system=False, tenant=tenant, platform_default=False, admin_default=True
        )

        request_body = {
            "admin_default": "false",
        }

        json_request_body = json.dumps(request_body)

        self.assertFalse(custom_role.system)
        self.assertFalse(custom_role.platform_default)
        self.assertTrue(custom_role.admin_default)

        response = self.client.put(
            f"/_private/api/roles/{custom_role.uuid}/",
            json_request_body,
            **self.request.META,
            content_type="application/json",
        )

        custom_role.refresh_from_db()

        self.assertFalse(custom_role.system)
        self.assertFalse(custom_role.platform_default)
        self.assertFalse(custom_role.admin_default)
        self.assertEqual(response.status_code, 200)

    def test_update_role(self):
        """Test that we can update a role."""
        tenant = Tenant.objects.create(tenant_name="1234", org_id="1234")
        custom_role = Role.objects.create(
            name="role 1", system=False, tenant=tenant, platform_default=False, admin_default=False
        )

        request_body = {"admin_default": "true", "system": "true", "platform_default": "true"}

        json_request_body = json.dumps(request_body)

        self.assertFalse(custom_role.system)
        self.assertFalse(custom_role.platform_default)
        self.assertFalse(custom_role.admin_default)

        response = self.client.put(
            f"/_private/api/roles/{custom_role.uuid}/",
            json_request_body,
            **self.request.META,
            content_type="application/json",
        )

        custom_role.refresh_from_db()

        self.assertTrue(custom_role.system)
        self.assertTrue(custom_role.platform_default)
        self.assertTrue(custom_role.admin_default)
        self.assertEqual(response.status_code, 200)

    def test_update_role_fails_disallowed_attributes(self):
        """Test that we can update a role."""
        tenant = Tenant.objects.create(tenant_name="1234", org_id="1234")
        custom_role = Role.objects.create(
            name="role 1", system=False, tenant=tenant, platform_default=False, admin_default=False
        )

        request_body = {"admin_default": "true", "system": "true", "name": "platform_default"}

        json_request_body = json.dumps(request_body)

        self.assertFalse(custom_role.system)
        self.assertFalse(custom_role.platform_default)
        self.assertFalse(custom_role.admin_default)

        response = self.client.put(
            f"/_private/api/roles/{custom_role.uuid}/",
            json_request_body,
            **self.request.META,
            content_type="application/json",
        )

        custom_role.refresh_from_db()

        self.assertFalse(custom_role.system)
        self.assertFalse(custom_role.platform_default)
        self.assertFalse(custom_role.admin_default)
        self.assertEqual(response.status_code, 400)

    def test_fetch_role(self):
        """Test that we can update a role."""
        tenant = Tenant.objects.create(tenant_name="1234", org_id="1234")
        custom_role = Role.objects.create(
            name="role 1", system=False, tenant=tenant, platform_default=False, admin_default=False
        )

        response = self.client.get(
            f"/_private/api/roles/{custom_role.uuid}/",
            **self.request.META,
            content_type="application/json",
        )

        body = json.loads(response.content.decode())
        role = body["role"]
        self.assertFalse(role["system"])
        self.assertFalse(role["platform_default"])
        self.assertFalse(role["admin_default"])
        self.assertEqual(response.status_code, 200)


class InternalViewsetResourceDefinitionTests(IdentityRequest):
    def setUp(self):
        """Set up the access view tests."""
        super().setUp()
        self.client = APIClient()
        self.customer = self.customer_data
        self.internal_request_context = self._create_request_context(self.customer, self.user_data, is_internal=True)
        self.internal_request = self.internal_request_context["request"]

        request = self.request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        user.org_id = self.customer_data["org_id"]
        request.user = user
        public_tenant = Tenant.objects.get(tenant_name="public")

        test_tenant_org_id = "100001"

        # we need to delete old test_tenant's that may exist in cache
        TENANTS = TenantCache()
        TENANTS.delete_tenant(test_tenant_org_id)

        # items with test_ prefix have hard coded attributes for new BOP requests
        self.test_tenant = Tenant(
            tenant_name="acct1111111", account_id="1111111", org_id=test_tenant_org_id, ready=True
        )
        self.test_tenant.save()
        self.test_principal = Principal(username="test_user", tenant=self.test_tenant)
        self.test_principal.save()
        self.test_group = Group(name="test_groupA", tenant=self.test_tenant)
        self.test_group.save()
        self.test_group.principals.add(self.test_principal)
        self.test_group.save()
        self.test_permission = Permission.objects.create(permission="app:test_*:test_*", tenant=self.test_tenant)
        Permission.objects.create(permission="app:test_foo:test_bar", tenant=self.test_tenant)
        user_data = {"username": "test_user", "email": "test@gmail.com"}
        request_context = self._create_request_context(
            {"account_id": "1111111", "tenant_name": "acct1111111", "org_id": "100001"}, user_data, is_org_admin=True
        )
        request = request_context["request"]
        self.test_headers = request.META
        test_tenant_root_workspace = Workspace.objects.create(
            name="Test Tenant Root Workspace", type=Workspace.Types.ROOT, tenant=self.test_tenant
        )
        Workspace.objects.create(
            name="Test Tenant Default Workspace",
            type=Workspace.Types.DEFAULT,
            parent=test_tenant_root_workspace,
            tenant=self.test_tenant,
        )

        self.principal = Principal(username=user.username, tenant=self.tenant)
        self.principal.save()
        self.admin_principal = Principal(username="user_admin", tenant=self.tenant)
        self.admin_principal.save()
        self.group = Group(name="groupA", tenant=self.tenant)
        self.group.save()
        self.group.principals.add(self.principal)
        self.group.save()
        self.permission = Permission.objects.create(permission="app:*:*", tenant=self.tenant)
        Permission.objects.create(permission="app:foo:bar", tenant=self.tenant)
        tenant_root_workspace = Workspace.objects.create(
            name="root",
            description="Root workspace",
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
        )
        Workspace.objects.create(
            name="Tenant Default Workspace",
            type=Workspace.Types.DEFAULT,
            parent=tenant_root_workspace,
            tenant=self.tenant,
        )

    def tearDown(self):
        """Tear down access view tests."""
        Group.objects.all().delete()
        Principal.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()
        Workspace.objects.filter(parent__isnull=False).delete()
        Workspace.objects.filter(parent__isnull=True).delete()

    def create_role(self, role_name, headers, in_access_data=None):
        """Create a role."""
        access_data = self.access_data
        if in_access_data:
            access_data = in_access_data
        test_data = {"name": role_name, "access": [access_data]}

        # create a role
        url = reverse("v1_management:role-list")
        client = APIClient()
        response = client.post(url, test_data, format="json", **headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        return response

    def create_policy(self, policy_name, group, roles, tenant):
        """Create a policy."""
        # create a policy
        policy = Policy.objects.create(name=policy_name, tenant=tenant, system=True)
        for role in Role.objects.filter(uuid__in=roles):
            policy.roles.add(role)
        policy.group = Group.objects.get(uuid=group)
        policy.save()

    def create_platform_default_resource(self):
        """Setup default group and role."""
        default_permission = Permission.objects.create(permission="default:*:*", tenant=self.tenant)
        default_role = Role.objects.create(name="default role", platform_default=True, system=True, tenant=self.tenant)
        default_access = Access.objects.create(permission=default_permission, role=default_role, tenant=self.tenant)
        default_policy = Policy.objects.create(name="default policy", system=True, tenant=self.tenant)
        default_policy.roles.add(default_role)
        default_group = Group.objects.create(
            name="default group", system=True, platform_default=True, tenant=self.tenant
        )
        default_group.policies.add(default_policy)

    def create_role_and_permission(self, role_name, permission):
        role = Role.objects.create(name=role_name, tenant=self.tenant)
        assigned_permission = Permission.objects.create(permission=permission, tenant=self.tenant)
        access = Access.objects.create(role=role, permission=assigned_permission, tenant=self.tenant)
        return role

    def test_get_correct_string_resource_definition(self):
        """Test that a string attributeFilter can have the equal operation"""

        role_name = "roleA"

        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [{"attributeFilter": {"key": "key1.id", "operation": "equal", "value": "value1"}}],
        }

        response = self.create_role(role_name, headers=self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"0 resource definitions would be corrected")

    def test_get_incorrect_string_resource_definition(self):
        """Test that a string attributeFilter cannot have the in operation"""

        role_name = "roleA"

        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [{"attributeFilter": {"key": "key1.id", "operation": "in", "value": "value1"}}],
        }

        response = self.create_role(role_name, headers=self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"1 resource definitions would be corrected")

    def test_get_correct_list_resource_definition(self):
        """Test that a list attributeFilter can have the in operation"""

        role_name = "roleA"

        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [
                {"attributeFilter": {"key": "key1.id", "operation": "in", "value": ["value1", "value2"]}}
            ],
        }

        response = self.create_role(role_name, headers=self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"0 resource definitions would be corrected")

    def test_get_incorrect_list_resource_definition(self):
        """Test that a list attributeFilter cannot have the equal operation"""

        role_name = "roleA"

        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [
                {"attributeFilter": {"key": "key1.id", "operation": "equal", "value": ["value1", "value2"]}}
            ],
        }

        response = self.create_role(role_name, headers=self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"1 resource definitions would be corrected")

    def test_patch_correct_string_resource_definition(self):
        """Test patching a string attributeFilter with the equal operation"""

        role_name = "roleA"

        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [{"attributeFilter": {"key": "key1.id", "operation": "equal", "value": "value1"}}],
        }

        response = self.create_role(role_name, headers=self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.patch(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"Updated 0 bad resource definitions")

        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"0 resource definitions would be corrected")

    def test_patch_incorrect_string_resource_definition(self):
        """Test patching a string attributeFilter with the in operation"""

        role_name = "roleA"

        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [{"attributeFilter": {"key": "key1.id", "operation": "in", "value": "value1"}}],
        }

        response = self.create_role(role_name, headers=self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.patch(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"Updated 1 bad resource definitions")

        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"0 resource definitions would be corrected")

    def test_patch_correct_list_resource_definition(self):
        """Test patching a list attributeFilter with the in operation"""

        role_name = "roleA"

        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [
                {"attributeFilter": {"key": "key1.id", "operation": "in", "value": ["value1", "value2"]}}
            ],
        }

        response = self.create_role(role_name, headers=self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.patch(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"Updated 0 bad resource definitions")

        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"0 resource definitions would be corrected")

    def test_patch_incorrect_list_resource_definition(self):
        """Test patching a list attributeFilter with the equal operation"""

        role_name = "roleA"

        self.access_data = {
            "permission": "app:*:*",
            "resourceDefinitions": [
                {"attributeFilter": {"key": "key1.id", "operation": "equal", "value": ["value1", "value2"]}}
            ],
        }

        response = self.create_role(role_name, headers=self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.patch(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"Updated 1 bad resource definitions")

        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"0 resource definitions would be corrected")
