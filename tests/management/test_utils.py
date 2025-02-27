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
"""Test the utils module."""
import uuid

from api.models import Tenant, User
from management.models import Access, Group, Permission, Principal, Policy, Role
from management.utils import (
    access_for_principal,
    get_principal_from_request,
    groups_for_principal,
    policies_for_principal,
    roles_for_principal,
    account_id_for_tenant,
    get_principal,
    validate_and_get_key,
)
from tests.identity_request import IdentityRequest

from unittest import mock
from unittest.mock import Mock

from rest_framework import serializers

SERVICE_ACCOUNT_KEY = "service-account"


class UtilsTests(IdentityRequest):
    """Test the utils module."""

    def setUp(self):
        """Set up the utils tests."""
        super().setUp()

        # setup principal
        self.principal = Principal.objects.create(username="principalA", tenant=self.tenant)

        # setup data for the principal
        self.roleA = Role.objects.create(name="roleA", tenant=self.tenant)
        self.permission = Permission.objects.create(permission="app:*:*", tenant=self.tenant)
        self.accessA = Access.objects.create(permission=self.permission, role=self.roleA, tenant=self.tenant)
        self.policyA = Policy.objects.create(name="policyA", tenant=self.tenant)
        self.policyA.roles.add(self.roleA)
        self.groupA = Group.objects.create(name="groupA", tenant=self.tenant)
        self.groupA.policies.add(self.policyA)
        self.groupA.principals.add(self.principal)

        # setup data the principal does not have access to
        self.roleB = Role.objects.create(name="roleB", tenant=self.tenant)
        self.accessB = Access.objects.create(permission=self.permission, role=self.roleB, tenant=self.tenant)
        self.policyB = Policy.objects.create(name="policyB", tenant=self.tenant)
        self.policyB.roles.add(self.roleB)
        self.groupB = Group.objects.create(name="groupB", tenant=self.tenant)
        self.groupB.policies.add(self.policyB)

        # setup default group/role which all tenant users
        # should inherit without explicit association
        self.default_role = Role.objects.create(
            name="default role", platform_default=True, system=True, tenant=self.tenant
        )
        self.default_access = Access.objects.create(
            permission=self.permission, role=self.default_role, tenant=self.tenant
        )
        self.default_policy = Policy.objects.create(name="default policy", system=True, tenant=self.tenant)
        self.default_policy.roles.add(self.default_role)
        self.default_group = Group.objects.create(
            name="default group", system=True, platform_default=True, tenant=self.tenant
        )
        self.default_group.policies.add(self.default_policy)

        # setup admin default group/role which all tenant admin users
        # should inherit without explicit association
        self.default_admin_role = Role.objects.create(
            name="default admin role", platform_default=False, system=True, tenant=self.tenant, admin_default=True
        )
        self.default_admin_access = Access.objects.create(
            permission=self.permission, role=self.default_admin_role, tenant=self.tenant
        )
        self.default_admin_policy = Policy.objects.create(name="default admin policy", system=True, tenant=self.tenant)
        self.default_admin_policy.roles.add(self.default_admin_role)
        self.default_admin_group = Group.objects.create(
            name="default admin access", system=True, platform_default=False, tenant=self.tenant, admin_default=True
        )
        self.default_admin_group.policies.add(self.default_admin_policy)

    def tearDown(self):
        """Tear down the utils tests."""
        Group.objects.all().delete()
        Principal.objects.all().delete()
        Policy.objects.all().delete()
        Role.objects.all().delete()
        Access.objects.all().delete()

    def test_access_for_principal(self):
        """Test that we get the correct access for a principal."""
        kwargs = {"application": "app"}
        access = access_for_principal(self.principal, self.tenant, **kwargs)
        self.assertCountEqual(access, [self.accessA, self.default_access])

    def test_access_for_org_admin(self):
        """Test that an org admin has access to admin_default groups"""
        kwargs = {"application": "app", "is_org_admin": True}
        access = access_for_principal(self.principal, self.tenant, **kwargs)
        self.assertCountEqual(access, [self.accessA, self.default_access, self.default_admin_access])

    def test_access_for_non_org_admin(self):
        """Test that a non-(org admin) doesn't have access to admin_default groups"""
        kwargs = {"application": "app", "is_org_admin": False}
        access = access_for_principal(self.principal, self.tenant, **kwargs)
        self.assertCountEqual(access, [self.accessA, self.default_access])

    def test_groups_for_principal(self):
        """Test that we get the correct groups for a principal."""
        groups = groups_for_principal(self.principal, self.tenant)
        self.assertCountEqual(groups, [self.groupA, self.default_group])

    def test_policies_for_principal(self):
        """Test that we get the correct groups for a principal."""
        policies = policies_for_principal(self.principal, self.tenant)
        self.assertCountEqual(policies, [self.policyA, self.default_policy])

    def test_roles_for_principal(self):
        """Test that we get the correct groups for a principal."""
        roles = roles_for_principal(self.principal, self.tenant)
        self.assertCountEqual(roles, [self.roleA, self.default_role])

    def test_account_number_from_tenant_name(self):
        """Test that we get the expected account number from a tenant name."""
        tenant = Tenant.objects.create(tenant_name="acct1234")
        self.assertEqual(account_id_for_tenant(tenant), "1234")

    @mock.patch("management.utils.verify_principal_with_proxy")
    def test_get_principal_created(self, mocked):
        """Test that when a user principal does not exist in the database, it gets created."""
        # Build a non existent user principal.
        user = User()
        user.username = "abcde"

        request = mock.Mock()
        request.user = user
        request.tenant = self.tenant
        request.query_params = {}

        # Attempt to fetch the service account principal from the database. Since it does not exist, it should create
        # one.
        get_principal(username=user.username, request=request)

        # Assert that the service account was properly created in the database.
        created_service_account = Principal.objects.get(username=user.username)
        self.assertEqual(created_service_account.type, "user")
        self.assertEqual(created_service_account.username, user.username)

    @mock.patch("management.utils.verify_principal_with_proxy")
    def test_get_username_principal_not_service_account_validated(self, verify_principal_with_proxy: Mock):
        """Test that the username gets validated only when it is not a service account username."""
        # Create a database principal in order to make the function under test get it from the database, and to make
        # sure that we are calling the first "verify_principal_with_proxy" call and not the one in the exception
        # handling block.
        database_principal = Principal()
        database_principal.cross_account = False
        database_principal.tenant = self.tenant
        database_principal.type = "user"
        database_principal.username = "clearly-not-a-service-account-db"
        database_principal.user_id = "1234567890"
        database_principal.save()

        request = mock.Mock()
        request.tenant = self.tenant
        request.user.user_id = "1234567890"

        # Call the function under test with the database principal's username and the "from_query" flag as "True", so
        # that we execute the "verify_principal_with_proxy" function from the "try" block, and not the "except" one.
        fetched_result = get_principal(username=database_principal.username, request=request, from_query=True)

        # Verify that the principal validation function got called.
        verify_principal_with_proxy.assert_called_with(
            username=database_principal.username, request=request, verify_principal=True
        )

        self.assertEqual(
            database_principal.uuid,
            fetched_result.uuid,
            "this flags that the fetched principal is not the one created to avoid executing the code in the"
            " exception handling block",
        )

        # Call the function under test again which should create the new principal, and run the
        # "verify_principal_with_proxy" method from the "except" block, and not from the "try" block.
        username = "clearly-not-another-service-account"

        created_result = get_principal(username=username, request=request, from_query=False)

        # Verify that the principal validation function got called.
        verify_principal_with_proxy.assert_called_with(username=username, request=request, verify_principal=True)

        self.assertNotEqual(
            database_principal.uuid,
            created_result.uuid,
            "this flags that the specified username is from the database principal created in the test, but in"
            "this case we were expecting a new principal to be created",
        )

    def test_get_principal_service_account_created(self):
        """Test that when a service account principal does not exist in the database, it gets created."""
        client_id = uuid.uuid4()
        service_account_username = f"service-account-{client_id}"

        request = mock.Mock()
        request.tenant = self.tenant
        request.query_params = {}

        # Attempt to fetch the service account principal from the database. Since it does not exist, it should create
        # one.
        get_principal(username=service_account_username, request=request)

        # Assert that the service account was properly created in the database.
        created_service_account = Principal.objects.get(username=service_account_username)
        self.assertEqual(created_service_account.service_account_id, str(client_id))
        self.assertEqual(created_service_account.type, "service-account")
        self.assertEqual(created_service_account.username, service_account_username)

    @mock.patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "100001",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "user_a",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_get_principal_from_request_created(self, mock_request_principals):
        """Test that when a principal does not exist in the database, it gets created."""
        username = "abcde"

        request = mock.Mock()
        request.tenant = self.tenant
        request.user = User()
        request.user.username = username
        request.query_params = {}

        # Attempt to fetch the principal from the database. Since it does not exist, it should create one.
        get_principal_from_request(request=request)

        # Assert that the principal was properly created in the database.
        created_principal = Principal.objects.get(username=username)
        self.assertEqual(created_principal.type, "user")
        self.assertEqual(created_principal.username, username)

    def test_validate_and_get_key_success(self):
        """Test we can validate the query param value."""
        query_key = "type"
        query_value = "service-account"
        params = {query_key: query_value}
        valid_values = ["user", "service-account"]
        default_value = "user"
        required = False
        result = validate_and_get_key(params, query_key, valid_values, default_value, required)

        self.assertEqual(result, query_value)

    def test_validate_and_get_key_invalid(self):
        """Test we get error with invalid query param value."""
        query_key = "type"
        query_value = "foo"
        params = {query_key: query_value}
        valid_values = ["user", "service-account"]
        default_value = "user"
        required = False
        with self.assertRaises(serializers.ValidationError) as assertion:
            validate_and_get_key(params, query_key, valid_values, default_value, required)

        expected_err = (
            f"{query_key} query parameter value '{query_value}' is invalid. {valid_values} are valid inputs."
        )
        self.assertEqual(assertion.exception.detail.get("detail"), expected_err)

    def test_validate_and_get_key_required_invalid(self):
        """Test we get error with missing required query parameter value."""
        query_key = "type"
        params = {}
        valid_values = ["user", "service-account"]
        required = True
        with self.assertRaises(serializers.ValidationError) as assertion:
            validate_and_get_key(params, query_key, valid_values, required=required)

        expected_err = f"Query parameter '{query_key}' is required."
        self.assertEqual(assertion.exception.detail.get("detail"), expected_err)

    def test_validate_and_get_key_required_success(self):
        """Test we get the default value if the mandatory parameter is not provided."""
        query_key = "type"
        params = {}
        valid_values = ["user", "service-account"]
        default_value = "user"
        required = True

        result = validate_and_get_key(params, query_key, valid_values, default_value=default_value, required=required)
        self.assertEqual(result, default_value)

    def test_validate_and_get_key_param_not_provided(self):
        """Test we get None if the optional parameter is not provided (without default value)."""
        query_key = "type"
        params = {}
        valid_values = ["user", "service-account"]
        required = False

        result = validate_and_get_key(params, query_key, valid_values, required=required)
        self.assertIsNone(result)

    def test_validate_and_get_key_param_default_value(self):
        """Test we get the default value if the optional parameter is not provided."""
        query_key = "type"
        params = {}
        valid_values = ["user", "service-account"]
        default_value = "user"
        required = False

        result = validate_and_get_key(params, query_key, valid_values, default_value=default_value, required=required)
        self.assertEqual(result, default_value)

        # The default value is used even if the query key is part of the request
        # for example /principals/?type=
        params = {query_key: ""}

        result = validate_and_get_key(params, query_key, valid_values, default_value=default_value, required=required)
        self.assertEqual(result, default_value)
