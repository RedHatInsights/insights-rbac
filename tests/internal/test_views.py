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
from abc import abstractmethod
import logging

from rest_framework import status
from rest_framework.test import APIClient
from django.test import override_settings
from django.urls import reverse
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from unittest.mock import patch
import pytz
import json

from api.cross_access.model import CrossAccountRequest
from api.models import User, Tenant
from api.utils import reset_imported_tenants
from management.audit_log.model import AuditLog
from management.cache import TenantCache
from management.models import BindingMapping, Group, Permission, Policy, Role, Workspace
from management.principal.model import Principal
from management.relation_replicator.noop_replicator import NoopReplicator
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.role.model import Access, ResourceDefinition
from management.tenant_mapping.model import TenantMapping
from management.tenant_service.v1 import V1TenantBootstrapService
from management.tenant_service.v2 import V2TenantBootstrapService
from management.workspace.model import Workspace
from migration_tool.in_memory_tuples import (
    all_of,
    InMemoryRelationReplicator,
    InMemoryTuples,
    relation,
    resource,
    subject,
)
from migration_tool.utils import create_relationship
from tests.identity_request import IdentityRequest
from tests.management.role.test_dual_write import RbacFixture
from tests.rbac.test_middleware import EnvironmentVarGuard


class BaseInternalViewsetTests(IdentityRequest):
    """Base class for testing internal views"""

    _tuples: InMemoryTuples

    @abstractmethod
    def setUp(self):
        """Set up the base internal viewset tests."""
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

    @abstractmethod
    def tearDown(self):
        """Tear down base internal viewset tests."""
        Group.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()
        logging.disable(self._prior_logging_disable_level)


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
class InternalViewsetTests(BaseInternalViewsetTests):
    """Test the internal viewset."""

    def valid_destructive_time():
        return datetime.now(timezone.utc).replace(tzinfo=pytz.UTC) + timedelta(hours=1)

    def invalid_destructive_time():
        return datetime.now(timezone.utc).replace(tzinfo=pytz.UTC) - timedelta(hours=1)

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

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_setting_ready_flag_for_tenants(self):
        """Test that we can get the total of not ready tenants and set them to true."""
        Tenant.objects.create(tenant_name="acct_not_ready", org_id="1234")
        response = self.client.get(f"/_private/api/utils/set_tenant_ready/", **self.request.META)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "Total of 1 tenants not set to be ready.")

        response = self.client.post(f"/_private/api/utils/set_tenant_ready/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.post(f"/_private/api/utils/set_tenant_ready/?max_expected=2", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.content.decode(), "Total of 1 tenants has been updated. 0 tenant with ready flag equal to false."
        )
        self.assertEqual(Tenant.objects.filter(ready=False).count(), 0)

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
        self.assertEqual(self._tuples.count_tuples(), 0)

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_clean_bindings(self, replicate):
        """Test that we can clean bindingmapping."""
        car = CrossAccountRequest.objects.create(
            target_org="123456",
            user_id="1111111",
            start_date=datetime.now(),
            end_date=datetime.now() + timedelta(10),
            status="approved",
        )
        car.roles.add(self.role)
        replicator = InMemoryRelationReplicator(self._tuples)
        replicate.side_effect = replicator.replicate
        workspace_id = "123456"
        group_to_remove = Group.objects.create(name="test", tenant=self.tenant)
        group_id_to_remove = str(group_to_remove.uuid)
        # Create binding mappings
        binding_attrs = {
            "resource_id": workspace_id,
            "resource_type_namespace": "rbac",
            "resource_type_name": "workspace",
            "mappings": {
                "role": {"is_system": True, "id": str(self.role.uuid), "permissions": []},
                "groups": [group_id_to_remove, str(self.group.uuid)],
                "users": [car.user_id, "not_exist_user"],
            },
        }
        binding_mapping = BindingMapping.objects.create(
            role=self.role,
            **binding_attrs,
        )
        binding_mapping_id = str(binding_mapping.id)
        binding_mapping.mappings["id"] = binding_mapping_id
        binding_mapping.save()
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
            create_relationship(
                ("rbac", "role_binding"),
                binding_mapping_id,
                ("rbac", "principal"),
                f"redhat/{car.user_id}",
                "subject",
            ),
            create_relationship(
                ("rbac", "role_binding"),
                binding_mapping_id,
                ("rbac", "group"),
                group_id_to_remove,
                "subject",
                "member",
            ),
        ]
        self._tuples.write(relations, [])
        # Deleting user still related is not allowed
        response = self.client.post(
            f"/_private/api/utils/binding/{binding_mapping_id}/clean/?field=users",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        car.status = "expired"
        car.save()
        response = self.client.post(
            f"/_private/api/utils/binding/{binding_mapping_id}/clean/?field=users",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            0,
            self._tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", binding_mapping_id),
                    relation("subject"),
                    subject("rbac", "principal", f"redhat/{car.user_id}"),
                )
            ),
        )

        # All group still exist
        response = self.client.post(
            f"/_private/api/utils/binding/{binding_mapping_id}/clean/?field=groups",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        group_to_remove.delete()
        response = self.client.post(
            f"/_private/api/utils/binding/{binding_mapping_id}/clean/?field=groups",
            **self.request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            0,
            self._tuples.count_tuples(
                all_of(
                    resource("rbac", "role_binding", binding_mapping_id),
                    relation("subject"),
                    subject("rbac", "group", f"redhat/{group_id_to_remove}", "member"),
                )
            ),
        )
        binding_mapping.refresh_from_db()
        self.assertEqual(binding_mapping.mappings["users"], {})
        self.assertEqual(binding_mapping.mappings["groups"], [str(self.group.uuid)])

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_bootstrapping_tenant(self, replicate):
        """Test that we can bootstrap a tenant."""
        org_id = "12345"

        payload = {"org_ids": [org_id]}
        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/",
            data=payload,
            **self.request.META,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        tuples = InMemoryTuples()
        replicator = InMemoryRelationReplicator(tuples)
        replicate.side_effect = replicator.replicate
        RbacFixture(V2TenantBootstrapService(replicator))
        tuples.clear()

        tenant = Tenant.objects.create(org_id=org_id)
        with self.assertRaises(Workspace.DoesNotExist) as root_assertion:
            Workspace.objects.root(tenant=tenant)
        self.assertEqual("Workspace matching query does not exist.", str(root_assertion.exception))

        with self.assertRaises(Workspace.DoesNotExist) as default_assertion:
            Workspace.objects.default(tenant=tenant)
        self.assertEqual("Workspace matching query does not exist.", str(default_assertion.exception))

        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/",
            data=payload,
            **self.request.META,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(Workspace.objects.root(tenant=tenant))
        self.assertIsNotNone(Workspace.objects.default(tenant=tenant))
        self.assertTrue(getattr(tenant, "tenant_mapping"))
        self.assertEqual(len(tuples), 9)

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_bootstrapping_multiple_tenants(self, replicate):
        """Test that we can bootstrap a tenant."""
        org_ids = ["12345", "123456", "6789"]

        payload = {"org_ids": org_ids}

        tuples = InMemoryTuples()
        replicator = InMemoryRelationReplicator(tuples)
        replicate.side_effect = replicator.replicate
        RbacFixture(V2TenantBootstrapService(replicator))
        tuples.clear()

        for org_id in org_ids:
            tenant = Tenant.objects.create(org_id=org_id)
            with self.assertRaises(Workspace.DoesNotExist) as root_assertion:
                Workspace.objects.root(tenant=tenant)
            self.assertEqual("Workspace matching query does not exist.", str(root_assertion.exception))

            with self.assertRaises(Workspace.DoesNotExist) as default_assertion:
                Workspace.objects.default(tenant=tenant)
            self.assertEqual("Workspace matching query does not exist.", str(default_assertion.exception))

        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/",
            data=payload,
            **self.request.META,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for org_id in org_ids:
            tenant = Tenant.objects.get(org_id=org_id)
            self.assertIsNotNone(Workspace.objects.root(tenant=tenant))
            self.assertIsNotNone(Workspace.objects.default(tenant=tenant))
            self.assertTrue(getattr(tenant, "tenant_mapping"))
        self.assertEqual(
            len(tuples), 9 + 9 + 9
        )  # orgs: 3 for workspaces, 3 for default and 3 for admin default access

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_bootstrapping_existing_tenant_without_force_does_nothing(self, replicate):
        tuples = InMemoryTuples()
        replicator = InMemoryRelationReplicator(tuples)
        replicate.side_effect = replicator.replicate
        fixture = RbacFixture(V2TenantBootstrapService(replicator))

        org_id = "12345"
        payload = {"org_ids": [org_id]}
        fixture.new_tenant(org_id)
        tuples.clear()

        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/?org_id={org_id}",
            data=payload,
            **self.request.META,
            content_type="application/json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(tuples), 0)

        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/?org_id={org_id}&force=false",
            data=payload,
            **self.request.META,
            content_type="application/json",
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
        payload = {"org_ids": [org_id]}
        fixture.new_tenant(org_id)
        tuples.clear()

        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/?org_id={org_id}&force=true",
            data=payload,
            **self.request.META,
            content_type="application/json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(tuples), 9)

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    def test_cannot_force_bootstrapping_while_replication_enabled(self):
        org_id = "12345"
        payload = {"org_ids": [org_id]}
        response = self.client.post(
            f"/_private/api/utils/bootstrap_tenant/?org_id={org_id}&force=true",
            data=payload,
            **self.request.META,
            content_type="application/json",
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
            response = self.client.delete(
                "/_private/api/utils/reset_imported_tenants/?only_ready_false_flag=false", **self.request.META
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Deleted 2 tenants.", logs.output[0])
        self.assertTrue(Tenant.objects.filter(org_id="o1").exists())
        self.assertTrue(Tenant.objects.filter(org_id="o2").exists())
        self.assertFalse(Tenant.objects.filter(org_id="o3").exists())
        self.assertFalse(Tenant.objects.filter(org_id="o4").exists())

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("api.tasks.run_reset_imported_tenants.delay")
    def test_reset_imported_tenants_with_ready_false_flag(self, delay):
        """Test that tenants flagged as ready=false are properly removed."""
        delay.side_effect = lambda args: reset_imported_tenants(**args)
        self.fixture = RbacFixture(V1TenantBootstrapService())
        self.fixture.new_unbootstrapped_tenant("o1")  # Tenant with ready=true
        self.fixture.new_unbootstrapped_tenant("o2")  # Tenant with ready=true

        # Test the query without and with the query param 'only_ready_false_flag=true' (default value)
        for query_param in ["", "?only_ready_false_flag=true"]:
            self.fixture.new_not_ready_tenant("o3")  # Tenant with ready=false
            self.fixture.new_not_ready_tenant("o4")  # Tenant with ready=false

            with self.assertLogs("api.utils", level="INFO") as logs:
                response = self.client.delete(
                    f"/_private/api/utils/reset_imported_tenants/{query_param}", **self.request.META
                )

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
            response = self.client.delete(
                "/_private/api/utils/reset_imported_tenants/?only_ready_false_flag=false&limit=3", **self.request.META
            )

        self.assertIn("Deleted 3 tenants.", logs.output[0])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # two extra tenants for test tenant and public tenant
        self.assertEqual(Tenant.objects.count(), 9)

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("api.tasks.run_reset_imported_tenants.delay")
    def test_reset_imported_tenants_removes_up_to_limit_with_ready_false_flag(self, delay):
        """Test that tenants flagged as ready=false are properly removed up to the specified limit."""
        delay.side_effect = lambda args: reset_imported_tenants(**args)

        self.fixture = RbacFixture(V1TenantBootstrapService())
        for i in range(10):
            self.fixture.new_not_ready_tenant(f"o{i}")

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

        response = self.client.get(
            "/_private/api/utils/reset_imported_tenants/?only_ready_false_flag=false", **self.request.META
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "100 tenants would be deleted")

    def test_reset_imported_tenants_get_counts_all_tenants_to_be_deleted_with_ready_false_flag(self):
        self.fixture = RbacFixture(V1TenantBootstrapService())
        self.fixture.new_tenant("o1")
        self.fixture.new_tenant("o2")

        for i in range(100):
            self.fixture.new_not_ready_tenant(f"o{i + 3}")

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
            response = self.client.delete(
                "/_private/api/utils/reset_imported_tenants/?only_ready_false_flag=false", **self.request.META
            )

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
            response = self.client.delete(
                "/_private/api/utils/reset_imported_tenants/?only_ready_false_flag=false&limit=1", **self.request.META
            )

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

        response = self.client.get(
            "/_private/api/utils/reset_imported_tenants/?only_ready_false_flag=false", **self.request.META
        )

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

        response = self.client.get(
            "/_private/api/utils/reset_imported_tenants/?only_ready_false_flag=false&limit=1", **self.request.META
        )

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
            f"/_private/api/utils/reset_imported_tenants/?only_ready_false_flag=false&exclude_id={t1.id}&exclude_id={t3.id}",
            **self.request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content.decode(), "2 tenants would be deleted")

    def test_reset_imported_tenants_excludes_get_with_ready_false_flag(self):
        # Create some tenants that would be deleted but exclude some
        self.fixture = RbacFixture(V1TenantBootstrapService())
        t1 = self.fixture.new_not_ready_tenant("o1")
        t2 = self.fixture.new_not_ready_tenant("o2")
        self.fixture.new_not_ready_tenant("o3")
        self.fixture.new_not_ready_tenant("o4")

        self.assertEqual(6, Tenant.objects.count())

        response = self.client.get(
            f"/_private/api/utils/reset_imported_tenants/?exclude_id={t1.id}&exclude_id={t2.id}",
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
                f"/_private/api/utils/reset_imported_tenants/?only_ready_false_flag=false&exclude_id={t1.id}&exclude_id={t3.id}",
                **self.request.META,
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Deleted 2 tenants.", logs.output[0])
        self.assertEqual(4, Tenant.objects.count())

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("api.tasks.run_reset_imported_tenants.delay")
    def test_reset_imported_tenants_excludes_delete_with_ready_false_flag(self, delay):
        delay.side_effect = lambda args: reset_imported_tenants(**args)

        # Create some tenants that would be deleted but exclude some
        self.fixture = RbacFixture(V1TenantBootstrapService())
        t1 = self.fixture.new_not_ready_tenant("o1")
        t2 = self.fixture.new_not_ready_tenant("o2")
        self.fixture.new_not_ready_tenant("o3")
        self.fixture.new_not_ready_tenant("o4")

        self.assertEqual(6, Tenant.objects.count())

        with self.assertLogs("api.utils", level="INFO") as logs:
            response = self.client.delete(
                f"/_private/api/utils/reset_imported_tenants/?exclude_id={t1.id}&exclude_id={t2.id}",
                **self.request.META,
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Deleted 2 tenants.", logs.output[0])
        self.assertEqual(4, Tenant.objects.count())

        self.assertTrue(Tenant.objects.filter(org_id="o1").exists())
        self.assertTrue(Tenant.objects.filter(org_id="o2").exists())
        self.assertFalse(Tenant.objects.filter(org_id="o3").exists())
        self.assertFalse(Tenant.objects.filter(org_id="o4").exists())

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

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_update_username_to_lowercase(self):
        """Test that the uppercase username would be updated to lowercase."""
        # Only POST is allowed
        response = self.client.delete(
            f"/_private/api/utils/username_lower/",
            **self.request.META,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        Principal.objects.bulk_create(
            [
                Principal(username="12345", tenant=self.tenant),
                Principal(username="ABCDE", tenant=self.tenant),
                Principal(username="Xyz", tenant=self.tenant),
                Principal(username="iJkLm", tenant=self.tenant),
                Principal(username="i.J.k@.L.m", tenant=self.tenant),
                Principal(username="user", tenant=self.tenant),
            ]
        )

        response = self.client.get(
            f"/_private/api/utils/username_lower/",
            **self.request.META,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.content.decode(),
            "Usernames to be updated: ['ABCDE', 'Xyz', 'i.J.k@.L.m', 'iJkLm'] to ['abcde', 'i.j.k@.l.m', 'ijklm', 'xyz']",
        )

        response = self.client.post(
            f"/_private/api/utils/username_lower/",
            **self.request.META,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        usernames = Principal.objects.values_list("username", flat=True).order_by("username")
        self.assertEqual({"12345", "abcde", "i.j.k@.l.m", "ijklm", "user", "xyz"}, set(usernames))

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@email.com",
                    "first_name": "user",
                    "last_name": "test",
                    "user_id": "u1",
                    "org_id": "12345",
                    "is_active": False,
                }
            ],
        },
    )
    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_delete_principal(self, _):
        """Test that we can delete principal."""
        # No username specified
        response = self.client.delete(f"/_private/api/utils/principal/", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        tenant = Tenant.objects.create(tenant_name="test_tenant", org_id="12345")
        Principal.objects.bulk_create(
            [
                Principal(username="test_user", tenant=tenant),
                Principal(username="test2", tenant=tenant),
            ]
        )
        # Get usernames of the principals to be deleted
        response = self.client.get(
            "/_private/api/utils/principal/?usernames=test_user,test2&user_type=user", **self.request.META
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.content.decode(),
            "Principals to be deleted: ['test2']",
        )

        # Delete the principals of type user
        response = self.client.delete(
            "/_private/api/utils/principal/?usernames=test_user, test2&user_type=user", **self.request.META
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertTrue(Principal.objects.filter(username="test_user").exists())
        self.assertTrue(Principal.objects.filter(username="test2").exists())

        # Delete the principals of type service-account
        Principal.objects.bulk_create(
            [
                Principal(username="sa_1", tenant=tenant, type="service-account"),
                Principal(username="sa_2", tenant=tenant, type="service-account"),
            ]
        )
        response = self.client.delete(
            "/_private/api/utils/principal/?usernames=sa_1,sa_2&user_type=service-account", **self.request.META
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Principal.objects.filter(type="service-account").exists())

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    def test_clean_up_roles_in_cars(self):
        """Test that we can get and clean up cars with custom roles."""
        tenant = Tenant.objects.create(tenant_name="1234", org_id="XXXX")
        custom_role = Role.objects.create(
            name="role 1", system=False, tenant=tenant, platform_default=False, admin_default=False
        )
        system_role = self.role
        car = CrossAccountRequest.objects.create(
            target_org="123456",
            user_id="1111111",
            start_date=datetime.now(),
            end_date=datetime.now() + timedelta(10),
            status="approved",
        )
        car.roles.add(*(system_role, custom_role))
        self.assertTrue(system_role.system)
        self.assertTrue(car.roles.filter(id=system_role.id).exists())
        self.assertTrue(car.roles.filter(id=custom_role.id).exists())
        response = self.client.get(
            f"/_private/api/cars/clean/",
            **self.request.META,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.content.decode(), json.dumps({str(car.request_id): (custom_role.id, custom_role.display_name)})
        )
        custom_role.refresh_from_db()
        system_role.refresh_from_db()

        response = self.client.post(
            f"/_private/api/cars/clean/",
            **self.request.META,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(car.roles.filter(id=system_role.id).exists())
        self.assertFalse(car.roles.filter(id=custom_role.id).exists())


class InternalViewsetUserLookupTests(BaseInternalViewsetTests):
    """Test the /api/utils/user_lookup/ endpoint from internal viewset"""

    def setUp(self):
        """Set up the get user data tests"""
        super().setUp()

        self.API_PATH = "/_private/api/utils/user_lookup/"

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@redhat.com",
                    "is_org_admin": "true",
                    "org_id": "12345",
                }
            ],
        },
    )
    def test_user_lookup_happy_path(self, _):
        # given (a lot of setup)
        # user data we want to query for
        username = "test_user"
        email = "test_user@redhat.com"

        # create a tenant and principal for our user
        tenant = Tenant.objects.create(tenant_name="test_tenant", org_id="12345")
        principal = Principal.objects.create(username=username, tenant=tenant)

        # create platform & admin default groups
        Group.objects.create(
            name="test_group_platform_default",
            tenant=self.public_tenant,
            system=True,
            admin_default=False,
            platform_default=True,
        )
        Group.objects.create(
            name="test_group_admin_default",
            tenant=self.public_tenant,
            system=True,
            admin_default=True,
            platform_default=False,
        )

        # create a test group and add our user to it
        test_group = Group.objects.create(name="test_group", tenant=tenant)
        test_group.principals.add(principal)

        # add some roles to our test group
        test_role1 = Role.objects.create(name="test_role1", tenant=tenant)
        test_role2 = Role.objects.create(name="test_role2", tenant=tenant)
        test_policy = Policy.objects.create(name="test_policy", group=test_group, tenant=tenant)
        test_policy.roles.add(test_role1, test_role2)
        test_group.policies.add(test_policy)

        # and finally add some permissions to our test roles
        test_perm1 = Permission.objects.create(permission="app:res1:*", tenant=tenant)
        test_perm2 = Permission.objects.create(permission="app:res2:*", tenant=tenant)
        Access.objects.create(permission=test_perm1, role=test_role1, tenant=tenant)
        Access.objects.create(permission=test_perm2, role=test_role1, tenant=tenant)

        test_perm3 = Permission.objects.create(permission="app:res3:read", tenant=tenant)
        test_perm4 = Permission.objects.create(permission="app:res3:write", tenant=tenant)
        Access.objects.create(permission=test_perm3, role=test_role2, tenant=tenant)
        Access.objects.create(permission=test_perm4, role=test_role2, tenant=tenant)

        # when
        response = self.client.get(f"{self.API_PATH}?username={username}", **self.request.META)

        resp = response.content.decode()
        msg = f"[response from rbac: '{resp}']"

        # then
        self.assertEqual(response.status_code, status.HTTP_200_OK, msg=msg)
        body = json.loads(resp)

        # check top level fields
        self.assertTrue(("username" in body), msg=msg)
        self.assertTrue(("email_address" in body), msg=msg)
        self.assertTrue(("groups" in body), msg=msg)
        self.assertEqual(body["username"], username, msg=msg)
        self.assertEqual(body["email_address"], email, msg=msg)

        resp_groups = body["groups"]
        self.assertIsInstance(resp_groups, list, msg=msg)
        self.assertEqual(len(resp_groups), 3, msg=msg)

        # check all our groups were returned
        group_names = [group["name"] for group in resp_groups]
        self.assertCountEqual(
            group_names, ["test_group", "test_group_platform_default", "test_group_admin_default"], msg=msg
        )

        # check our test group has all its roles
        resp_test_group = [group for group in resp_groups if group["name"] == "test_group"][0]
        self.assertIsNotNone(resp_test_group, msg=msg)

        resp_test_group_roles = resp_test_group["roles"]
        self.assertIsNotNone(resp_test_group_roles, msg=msg)
        self.assertIsInstance(resp_test_group_roles, list, msg=msg)
        self.assertEqual(len(resp_test_group_roles), 2, msg=msg)

        role_names = [role["name"] for role in resp_test_group_roles]
        self.assertCountEqual(role_names, ["test_role1", "test_role2"], msg=msg)

        # and finally check all our roles have all their permissions
        resp_test_group_role1 = resp_test_group_roles[0]
        resp_test_group_role2 = resp_test_group_roles[1]

        self.assertIsInstance(resp_test_group_role1["permissions"], list, msg=msg)
        self.assertEqual(len(resp_test_group_role1["permissions"]), 2)
        self.assertCountEqual(resp_test_group_role1["permissions"], ["app | res1 | *", "app | res2 | *"], msg=msg)

        self.assertIsInstance(resp_test_group_role2["permissions"], list, msg=msg)
        self.assertEqual(len(resp_test_group_role2["permissions"]), 2, msg=msg)
        self.assertCountEqual(
            resp_test_group_role2["permissions"], ["app | res3 | read", "app | res3 | write"], msg=msg
        )

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@redhat.com",
                    "is_org_admin": "true",
                    "org_id": "12345",
                }
            ],
        },
    )
    def test_user_lookup_custom_default_groups(self, _):
        # given (a lot of setup)
        # user data we want to query for
        username = "test_user"
        email = "test_user@redhat.com"

        # create a tenant and principal for our user
        tenant = Tenant.objects.create(tenant_name="test_tenant", org_id="12345")
        principal = Principal.objects.create(username=username, tenant=tenant)

        # create custom platform & admin default groups
        Group.objects.create(
            name="test_group_platform_default_custom",
            tenant=tenant,
            system=True,
            admin_default=False,
            platform_default=True,
        )
        Group.objects.create(
            name="test_group_admin_default_custom",
            tenant=tenant,
            system=True,
            admin_default=True,
            platform_default=False,
        )

        # create public platform & admin default groups
        Group.objects.create(
            name="test_group_platform_default_public",
            tenant=self.public_tenant,
            system=True,
            admin_default=False,
            platform_default=True,
        )
        Group.objects.create(
            name="test_group_admin_default_public",
            tenant=self.public_tenant,
            system=True,
            admin_default=True,
            platform_default=False,
        )

        # when
        response = self.client.get(f"{self.API_PATH}?username={username}", **self.request.META)

        resp = response.content.decode()
        msg = f"[response from rbac: '{resp}']"

        # then
        self.assertEqual(response.status_code, status.HTTP_200_OK, msg=msg)
        body = json.loads(resp)

        self.assertTrue(("groups" in body), msg=msg)
        resp_groups = body["groups"]
        self.assertIsInstance(resp_groups, list, msg=msg)
        self.assertEqual(len(resp_groups), 2, msg=msg)

        # the custom groups should be present, not the public ones
        group_names = [group["name"] for group in resp_groups]
        self.assertCountEqual(
            group_names, ["test_group_platform_default_custom", "test_group_admin_default_custom"], msg=msg
        )

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@redhat.com",
                    "is_org_admin": "true",
                    "org_id": "12345",
                }
            ],
        },
    )
    def test_user_lookup_via_email(self, _):
        # given
        username = "test_user"
        email = "test_user@redhat.com"

        # create a tenant and principal for our user
        tenant = Tenant.objects.create(tenant_name="test_tenant", org_id="12345")
        Principal.objects.create(username=username, tenant=tenant)

        # when
        response = self.client.get(f"{self.API_PATH}?email={email}", **self.request.META)

        resp = response.content.decode()
        msg = f"[response from rbac: '{resp}']"

        # then
        self.assertEqual(response.status_code, status.HTTP_200_OK, msg=msg)
        body = json.loads(resp)

        # check top level fields
        self.assertTrue(("username" in body), msg=msg)
        self.assertTrue(("email_address" in body), msg=msg)
        self.assertEqual(body["username"], username, msg=msg)
        self.assertEqual(body["email_address"], email, msg=msg)

    def test_user_lookup_only_get_method_allowed(self):
        # when
        response = self.client.post(f"{self.API_PATH}", **self.request.META)

        # then
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        resp_body = json.loads(response.content.decode())
        self.assertIsNotNone(resp_body["error"])
        self.assertIn("Invalid http method", resp_body["error"])

    def test_user_lookup_no_input_provided(self):
        # when
        response = self.client.get(f"{self.API_PATH}", **self.request.META)

        # then
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        resp_body = json.loads(response.content.decode())
        self.assertIsNotNone(resp_body["error"])
        self.assertIn("you must provide either 'email' or 'username' as query params", resp_body["error"])

    def test_user_lookup_username_invalid(self):
        # given
        username = "   "

        # when
        response = self.client.get(f"{self.API_PATH}?username={username}", **self.request.META)

        # then
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        resp_body = json.loads(response.content.decode())
        self.assertIsNotNone(resp_body["error"])
        self.assertIn("username contains only whitespace", resp_body["error"])

    def test_user_lookup_email_invalid(self):
        # given
        email = "   "

        # when
        response = self.client.get(f"{self.API_PATH}?email={email}", **self.request.META)

        # then
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        resp_body = json.loads(response.content.decode())
        self.assertIsNotNone(resp_body["error"])
        self.assertIn("email contains only whitespace", resp_body["error"])

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 500,
            "errors": [{"connection refused rip"}],
        },
    )
    def test_user_lookup_bop_returns_error(self, _):
        # given
        username = "test_user"

        # when
        response = self.client.get(f"{self.API_PATH}?username={username}", **self.request.META)

        # then
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

        resp_body = json.loads(response.content.decode())
        self.assertIsNotNone(resp_body["error"])
        self.assertIn("unexpected status: '500' returned from bop", resp_body["error"])

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [],
        },
    )
    def test_user_lookup_bop_returns_empty_set(self, _):
        # given
        username = "test_user"

        # when
        response = self.client.get(f"{self.API_PATH}?username={username}", **self.request.META)

        # then
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        resp_body = json.loads(response.content.decode())
        self.assertIsNotNone(resp_body["error"])
        self.assertIn("Not found", resp_body["error"])

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "email": "test_user@redhat.com",
                    "is_org_admin": "true",
                    "org_id": "12345",
                }
            ],
        },
    )
    def test_user_lookup_bop_returns_user_without_username(self, _):
        # given
        email = "test_user@redhat.com"

        # when
        response = self.client.get(f"{self.API_PATH}?email={email}", **self.request.META)

        # then
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

        resp_body = json.loads(response.content.decode())
        self.assertIsNotNone(resp_body["error"])
        self.assertIn("user found in bop but no username exists", resp_body["error"])

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@redhat.com",
                    "org_id": "12345",
                }
            ],
        },
    )
    def test_user_lookup_bop_returns_user_without_is_org_admin(self, _):
        # given
        email = "test_user@redhat.com"

        # create a tenant and principal for our user
        tenant = Tenant.objects.create(tenant_name="test_tenant", org_id="12345")
        Principal.objects.create(username="test_user", tenant=tenant)

        # create platform & admin default groups
        Group.objects.create(
            name="test_group_platform_default",
            tenant=tenant,
            system=True,
            admin_default=False,
            platform_default=True,
        )
        Group.objects.create(
            name="test_group_admin_default",
            tenant=tenant,
            system=True,
            admin_default=True,
            platform_default=False,
        )

        # when
        response = self.client.get(f"{self.API_PATH}?email={email}", **self.request.META)

        # then - in this case it should default is_org_admin to false and continue request
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        resp_body = json.loads(response.content.decode())
        self.assertTrue(("groups" in resp_body))

        resp_groups = resp_body["groups"]
        self.assertIsInstance(resp_groups, list)

        group_names = [group["name"] for group in resp_groups]
        self.assertNotIn("test_group_admin_default", group_names)
        self.assertIn("test_group_platform_default", group_names)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@redhat.com",
                    "is_org_admin": "true",
                }
            ],
        },
    )
    def test_user_lookup_bop_returns_user_without_org_id(self, _):
        # given
        username = "test_user"

        # when
        response = self.client.get(f"{self.API_PATH}?username={username}", **self.request.META)

        # then
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

        resp_body = json.loads(response.content.decode())
        self.assertIsNotNone(resp_body["error"])
        self.assertIn("user found in bop but no org_id exists", resp_body["error"])

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@redhat.com",
                    "is_org_admin": "false",
                    "org_id": "12345",
                }
            ],
        },
    )
    def test_user_lookup_tenant_does_not_exist_in_rbac(self, _):
        # given
        username = "test_user"

        # when
        response = self.client.get(f"{self.API_PATH}?username={username}", **self.request.META)

        # then
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

        resp_body = json.loads(response.content.decode())
        self.assertIsNotNone(resp_body["error"])
        self.assertIn("failed to query rbac for tenant with org_id: '12345'", resp_body["error"])

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@redhat.com",
                    "is_org_admin": "false",
                    "org_id": "12345",
                }
            ],
        },
    )
    @patch(
        "internal.views.get_principal",
        side_effect=Exception("something went wrong"),
    )
    def test_user_lookup_get_principal_raises_exception(self, __, _):
        # given
        username = "test_user"

        Tenant.objects.create(tenant_name="test_tenant", org_id="12345")

        # when
        response = self.client.get(f"{self.API_PATH}?username={username}", **self.request.META)

        # then
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

        resp_body = json.loads(response.content.decode())
        self.assertIsNotNone(resp_body["error"])
        self.assertIn("failed to query rbac for user: 'test_user'", resp_body["error"])

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "username": "test_user",
                    "email": "test_user@redhat.com",
                    "is_org_admin": "false",
                    "org_id": "12345",
                }
            ],
        },
    )
    def test_user_lookup_user_does_not_exist_in_rbac(self, _):
        # given
        username = "test_user"
        # we don't add principal to rbac db
        tenant = Tenant.objects.create(tenant_name="test_tenant", org_id="12345")
        Group.objects.create(
            name="test_group_platform_default",
            tenant=tenant,
            system=True,
            admin_default=False,
            platform_default=True,
        )

        # when
        response = self.client.get(f"{self.API_PATH}?username={username}", **self.request.META)

        # then
        # only groups that exist should be default
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        resp_body = json.loads(response.content.decode())
        self.assertTrue(("groups" in resp_body))

        resp_groups = resp_body["groups"]
        self.assertIsInstance(resp_groups, list)
        self.assertEqual(len(resp_groups), 1)
        self.assertEqual(resp_groups[0]["name"], "test_group_platform_default")


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
        role = Role.objects.create(name="role_A", tenant=self.tenant)
        perm = Permission.objects.create(permission="test_app:operation:*", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter={"key": "key1.id", "operation": "in", "value": "value1"},
            tenant=self.tenant,
        )

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
        role = Role.objects.create(name="role_A", tenant=self.tenant)
        perm = Permission.objects.create(permission="test_app:operation:*", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter={"key": "key1.id", "operation": "equal", "value": ["value1", "value2"]},
            tenant=self.tenant,
        )

        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"1 resource definitions would be corrected")

    def test_get_incorrect_resource_definition_with_details(self):
        """Test we can get list of invalid resource definitions with 'detail=true' query param."""
        role = Role.objects.create(name="role_A", tenant=self.tenant)
        perm = Permission.objects.create(permission="test_app:operation:*", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        attribute_filter_data = [
            {"key": "key1_id", "operation": "equal", "value": ["value1", "value2"]},
            {"key": "key2_id", "operation": "in", "value": "value1, value2"},
            {"key": "key3_id", "operation": "in", "value": "string"},
        ]
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter=attribute_filter_data[0],
            tenant=self.tenant,
        )
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter=attribute_filter_data[1],
            tenant=self.tenant,
        )
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter=attribute_filter_data[2],
            tenant=self.tenant,
        )
        # Send the request without 'detail=true' query param
        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"3 resource definitions would be corrected")

        # Send the request with 'detail=true' query param
        response = self.client.get(
            f"/_private/api/utils/resource_definitions/?detail=true",
            **self.internal_request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.json()), 3)
        for rf_from_response in response.json():
            for at in attribute_filter_data:
                if rf_from_response["attributeFilter"]["key"] == at["key"]:
                    operation = rf_from_response["attributeFilter"]["operation"]
                    value = rf_from_response["attributeFilter"]["value"]
                    expected_operation = at["operation"]
                    expected_value = at["value"]
                    self.assertEqual(operation, expected_operation)
                    self.assertEqual(value, expected_value)

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
        role = Role.objects.create(name="role_A", tenant=self.tenant)
        perm = Permission.objects.create(permission="test_app:operation:*", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter={"key": "key1.id", "operation": "in", "value": "value1"},
            tenant=self.tenant,
        )

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
        role = Role.objects.create(name="role_A", tenant=self.tenant)
        perm = Permission.objects.create(permission="test_app:*:*", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter={"key": "key1.id", "operation": "equal", "value": ["value1", "value2"]},
            tenant=self.tenant,
        )

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

    def test_patch_incorrect_resource_definition_all(self):
        """Test we can patch all invalid resource definitions."""
        role_name = "role_A"
        role = Role.objects.create(name=role_name, tenant=self.tenant)
        perm = Permission.objects.create(permission="test_app:operation:*", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        attribute_filter_data = [
            {"key": "key1_id", "operation": "equal", "value": ["value1", "value2"]},
            {"key": "key2_id", "operation": "in", "value": "value1, value2"},
            {"key": "key3_id", "operation": "in", "value": "string"},
        ]
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter=attribute_filter_data[0],
            tenant=self.tenant,
        )
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter=attribute_filter_data[1],
            tenant=self.tenant,
        )
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter=attribute_filter_data[2],
            tenant=self.tenant,
        )

        # Send the GET request to check we have fixable resource definitions
        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"3 resource definitions would be corrected")

        # Send the PATCH request to fix all resource definitions
        response = self.client.patch(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"Updated 3 bad resource definitions")

        # Send the GET request to check we don't have fixable resource definitions
        response = self.client.get(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"0 resource definitions would be corrected")

        # Check the resource definitions were fixed as expected
        for rf in ResourceDefinition.objects.filter(access__role__name=role_name):
            if rf.attributeFilter["key"] == "key1_id":
                operation = rf.attributeFilter["operation"]
                self.assertEqual(operation, "in")
            elif rf.attributeFilter["key"] == "key2_id":
                value = rf.attributeFilter["value"]
                self.assertIsInstance(value, list)
                self.assertEqual(len(value), 2)
                self.assertEqual(value[0], "value1")
                self.assertEqual(value[1], "value2")
            elif rf.attributeFilter["key"] == "key3_id":
                operation = rf.attributeFilter["operation"]
                self.assertEqual(operation, "equal")

    def test_patch_incorrect_resource_definition_by_id(self):
        """Test we can patch one invalid resource definitions with 'id' query param."""
        role_name = "role_A"
        role = Role.objects.create(name=role_name, tenant=self.tenant)
        perm = Permission.objects.create(permission="test_app:operation:*", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        attribute_filter_data = [
            {"key": "key1_id", "operation": "equal", "value": ["value1", "value2"]},
            {"key": "key2_id", "operation": "in", "value": "value1, value2"},
            {"key": "key3_id", "operation": "in", "value": "string"},
        ]
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter=attribute_filter_data[0],
            tenant=self.tenant,
        )
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter=attribute_filter_data[1],
            tenant=self.tenant,
        )
        ResourceDefinition.objects.create(
            access=access,
            attributeFilter=attribute_filter_data[2],
            tenant=self.tenant,
        )

        # Send the GET request to get details resource definitions ids
        response = self.client.get(
            f"/_private/api/utils/resource_definitions/?detail=true",
            **self.internal_request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        resource_definitions_ids = [rf["id"] for rf in response.json()]

        # Send the PATCH request with 'id' query parameter to fix only 1 resource definition
        for rf_id in resource_definitions_ids:
            response = self.client.patch(
                f"/_private/api/utils/resource_definitions/?id={rf_id}",
                **self.internal_request.META,
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.content.decode(), f"Resource definition id = {rf_id} updated.")

        # Send the PATCH request to fix all resource definitions
        response = self.client.patch(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"Updated 0 bad resource definitions")

        # Check the resource definitions were fixed as expected
        for rf in ResourceDefinition.objects.filter(access__role__name=role_name):
            if rf.attributeFilter["key"] == "key1_id":
                operation = rf.attributeFilter["operation"]
                self.assertEqual(operation, "in")
            elif rf.attributeFilter["key"] == "key2_id":
                value = rf.attributeFilter["value"]
                self.assertIsInstance(value, list)
                self.assertEqual(len(value), 2)
                self.assertEqual(value[0], "value1")
                self.assertEqual(value[1], "value2")
            elif rf.attributeFilter["key"] == "key3_id":
                operation = rf.attributeFilter["operation"]
                self.assertEqual(operation, "equal")

    def test_patch_hbi_resource_definition(self):
        """Test we can patch one invalid hbi resource definitions."""
        role_name = "role_A"
        role = Role.objects.create(name=role_name, tenant=self.tenant)
        perm = Permission.objects.create(permission="test_app:operation:*", tenant=self.tenant)
        access = Access.objects.create(permission=perm, role=role, tenant=self.tenant)
        attribute_filter_data = [
            {"key": "group.id", "operation": "equal", "value": ["value1", "value2"]},
            {"key": "group.id", "operation": "equal", "value": None},
            {"key": "group.id", "operation": "equal", "value": "string"},
            {"key": "group.id", "operation": "in", "value": {"id": "12345"}},
            {"key": "group.id", "operation": "equal", "value": 2},
            {"key": "group.id", "operation": "in", "value": {}},
        ]
        rfs = ResourceDefinition.objects.bulk_create(
            [
                ResourceDefinition(
                    access=access,
                    attributeFilter=attribute_filter_data[0],
                    tenant=self.tenant,
                ),
                ResourceDefinition(
                    access=access,
                    attributeFilter=attribute_filter_data[1],
                    tenant=self.tenant,
                ),
                ResourceDefinition(
                    access=access,
                    attributeFilter=attribute_filter_data[2],
                    tenant=self.tenant,
                ),
                ResourceDefinition(
                    access=access,
                    attributeFilter=attribute_filter_data[3],
                    tenant=self.tenant,
                ),
                ResourceDefinition(
                    access=access,
                    attributeFilter=attribute_filter_data[4],
                    tenant=self.tenant,
                ),
                ResourceDefinition(
                    access=access,
                    attributeFilter=attribute_filter_data[5],
                    tenant=self.tenant,
                ),
            ]
        )

        # Send the PATCH request to fix all resource definitions
        response = self.client.patch(
            f"/_private/api/utils/resource_definitions/",
            **self.internal_request.META,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, b"Updated 6 bad resource definitions")

        # Check the resource definitions were fixed as expected
        values = [["value1", "value2"], [None], ["string"], ["12345"], [2], [None]]
        for index, rf in enumerate(rfs):
            rf.refresh_from_db()
            operation = rf.attributeFilter["operation"]
            self.assertEqual(operation, "in")
            value = rf.attributeFilter["value"]
            self.assertEqual(values[index], value)

    def test_bootstrap_pending_tenants(self):
        tenant = Tenant.objects.create(org_id="111", account_id="111")
        Tenant.objects.create(account_id="112")
        response = self.client.get(
            f"/_private/api/utils/bootstrap_pending_tenants/",
            **self.internal_request.META,
        )

        expected_json = {
            "org_ids": sorted([str(self.tenant.org_id), str(self.test_tenant.org_id), str(tenant.org_id)]),
        }

        response_json = json.loads(response.content)
        response_json["org_ids"].sort()

        self.assertEqual(response_json, expected_json)


class InternalS2SViewsetTests(IdentityRequest):

    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate_workspace")
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    def test_create_ungrouped_workspace(self, replicate, replicate_workspace):
        tuples = InMemoryTuples()
        replicator = InMemoryRelationReplicator(tuples)
        replicate.side_effect = replicator.replicate
        fixture = RbacFixture(V2TenantBootstrapService(replicator))

        org_id = "12345"
        payload = {"org_ids": [org_id]}
        bootstraped_tenant = fixture.new_tenant(org_id)
        tuples.clear()
        self.env = EnvironmentVarGuard()
        self.env.set("SERVICE_PSKS", '{"hbi": {"secret": "abc123"}}')
        self.service_headers = {
            "HTTP_X_RH_RBAC_PSK": "abc123",
            "HTTP_X_RH_RBAC_CLIENT_ID": "hbi",
            "HTTP_X_RH_RBAC_ORG_ID": org_id,
        }

        self.assertFalse(
            Workspace.objects.filter(tenant=bootstraped_tenant.tenant, type=Workspace.Types.UNGROUPED_HOSTS).exists()
        )
        response = self.client.get(
            f"/_private/_s2s/workspaces/ungrouped/",
            data=payload,
            **self.service_headers,
            content_type="application/json",
        )

        default = Workspace.objects.get(tenant=bootstraped_tenant.tenant, type=Workspace.Types.DEFAULT)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        ungrouped_hosts = response.json()
        ungrouped_host_relation = tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", ungrouped_hosts["id"]),
                relation("parent"),
                subject("rbac", "workspace", str(default.id)),
            )
        )
        self.assertEqual(len(ungrouped_host_relation), 1)
        workspace_event = replicate_workspace.call_args[0][0]
        self.assertEqual(workspace_event.org_id, org_id)
        self.assertEqual(workspace_event.event_type, ReplicationEventType.CREATE_WORKSPACE)
        self.assertEqual(workspace_event.workspace["type"], str(Workspace.Types.UNGROUPED_HOSTS))

        # Get existing ungrouped workspace
        response = self.client.get(
            f"/_private/_s2s/workspaces/ungrouped/",
            **self.service_headers,
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        ungrouped_hosts.pop("modified")
        payload_get = response.json()
        payload_get.pop("modified")
        self.assertEqual(ungrouped_hosts, payload_get)
