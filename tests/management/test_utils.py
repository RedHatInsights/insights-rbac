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
    groups_for_principal,
    policies_for_principal,
    roles_for_principal,
    account_id_for_tenant,
    get_principal,
)
from rest_framework.exceptions import ValidationError
from tests.identity_request import IdentityRequest

from unittest import mock
from unittest.mock import Mock

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

    @mock.patch("management.authorization.token_validator.ITSSOTokenValidator.validate_token")
    @mock.patch("management.principal.it_service.ITService.is_service_account_valid_by_username")
    @mock.patch("management.utils.verify_principal_with_proxy")
    def test_get_principal_service_account_created(
        self, mocked: Mock, is_service_account_valid_by_username: Mock, validate_token: Mock
    ):
        """Test that when a service account principal does not exist in the database, it gets created."""
        # Build a non-existent service account.
        user = User()
        user.client_id = uuid.uuid4()
        user.is_service_account = True
        user.username = f"service-account-{user.client_id}"

        request = mock.Mock()
        request.user = user
        request.tenant = self.tenant
        request.query_params = {}

        # Make sure the service account gets flagged as valid so that it gets persisted in the database.
        is_service_account_valid_by_username.return_value = True

        # Attempt to fetch the service account principal from the database. Since it does not exist, it should create
        # one.
        get_principal(username=user.username, request=request)

        # Assert that the service account was properly created in the database.
        created_service_account = Principal.objects.get(username=user.username)
        self.assertEqual(created_service_account.service_account_id, str(user.client_id))
        self.assertEqual(created_service_account.type, "service-account")
        self.assertEqual(created_service_account.username, user.username)

        @mock.patch("management.principal.it_service.ITService.is_service_account_valid_by_username")
        def test_get_principal_from_query_service_account_validated_once_principal_exists(
            self, is_service_account_valid_by_username: Mock
        ):
            """Test that when specifying the "from query" parameter the service account is validated"""
            # Create a service account principal in the database, which will be fetched by the function under test.
            client_id = uuid.uuid4()
            username = f"service-account-{client_id}"

            created_principal = Principal.objects.create(
                username=username, tenant=self.tenant, type=SERVICE_ACCOUNT_KEY, service_account_id=client_id
            )

            # Simulate that a bearer token was given, and that it was correctly validated.
            validate_token.return_value = "mocked-bearer-token"

            # Simulate that the IT service says the service account's username is valid.
            is_service_account_valid_by_username.return_value = True

            # Mock the request with the required bits.
            request = Mock()
            request.tenant = self.tenant
            request.user = User()

            # Call the function under test.
            returned_principal = get_principal(
                username=username, request=request, verify_principal=True, from_query=True
            )

            self.assertEqual(
                created_principal,
                returned_principal,
                "the service account principal we created and the returned principal should be the same",
            )

    @mock.patch("management.authorization.token_validator.ITSSOTokenValidator.validate_token")
    @mock.patch("management.principal.it_service.ITService.is_service_account_valid_by_username")
    def test_get_principal_from_query_service_account_not_validated_validation_error(
        self, is_service_account_valid_by_username: Mock, validate_token: Mock
    ):
        """Test that when the service account username cannot be validated, a validation error is raised"""
        # Create a service account principal in the database, which will be fetched by the function under test.
        client_id = uuid.uuid4()
        username = f"service-account-{client_id}"

        # Simulate that a bearer token was given, and that it was correctly validated.
        validate_token.return_value = "mocked-bearer-token"

        # Simulate that the IT service says the service account's username is valid.
        is_service_account_valid_by_username.return_value = False

        # Mock the request with the required bits.
        request = Mock()
        request.tenant = self.tenant
        request.user = User()

        # Call the function under test.
        try:
            get_principal(username=username, request=request, verify_principal=True, from_query=True)
            self.fail("expected a validation exception, none gotten")
        except ValidationError as ve:
            self.assertEqual(
                f"No data found for service account with username '{username}'",
                str(ve.detail.get("detail")),
                "unexpected exception message",
            )

        # Assert that the validation function gets called once.
        is_service_account_valid_by_username.assert_called_with(user=request.user, service_account_username=username)

    @mock.patch("management.authorization.token_validator.ITSSOTokenValidator.validate_token")
    @mock.patch("management.principal.it_service.ITService.is_service_account_valid_by_username")
    def test_get_principal_from_query_service_account_validated_principal_exists(
        self, is_service_account_valid_by_username: Mock, validate_token: Mock
    ):
        """Test that when specifying the "from query" parameter the service account is validated"""
        # Create a service account principal in the database, which will be fetched by the function under test.
        client_id = uuid.uuid4()
        username = f"service-account-{client_id}"

        created_principal = Principal.objects.create(
            username=username, tenant=self.tenant, type=SERVICE_ACCOUNT_KEY, service_account_id=client_id
        )

        # Simulate that a bearer token was given, and that it was correctly validated.
        validate_token.return_value = "mocked-bearer-token"

        # Simulate that the IT service says the service account's username is valid.
        is_service_account_valid_by_username.return_value = True

        # Mock the request with the required bits.
        request = Mock()
        request.tenant = self.tenant
        request.user = User()

        # Call the function under test.
        returned_principal = get_principal(username=username, request=request, verify_principal=True, from_query=True)

        # Assert that the validation function gets called once.
        is_service_account_valid_by_username.assert_called_with(user=request.user, service_account_username=username)

        # Assert that the returned principal is the same one as the one created for the test.
        self.assertEqual(
            created_principal,
            returned_principal,
            "the service account principal we created and the returned principal should be the same",
        )

    @mock.patch("management.authorization.token_validator.ITSSOTokenValidator.validate_token")
    @mock.patch("management.principal.it_service.ITService.is_service_account_valid_by_username")
    def test_get_principal_from_query_service_account_validated_principal_not_exists(
        self, is_service_account_valid_by_username: Mock, validate_token: Mock
    ):
        """Test that when specifying the "from query" parameter the service account is validated just once"""
        # Create a service account principal in the database, which will be fetched by the function under test.
        client_id = uuid.uuid4()
        username = f"service-account-{client_id}"

        # Simulate that a bearer token was given, and that it was correctly validated.
        validate_token.return_value = "mocked-bearer-token"

        # Simulate that the IT service says the service account's username is valid.
        is_service_account_valid_by_username.return_value = True

        # Mock the request with the required bits.
        user = User()
        user.client_id = str(uuid.uuid4())
        user.is_service_account = True
        user.username = f"service-account-{user.client_id}"

        request = Mock()
        request.tenant = self.tenant
        request.user = user

        # Call the function under test.
        returned_principal: Principal = get_principal(
            username=username, request=request, verify_principal=True, from_query=True
        )

        # Assert that the validation function gets called once.
        self.assertEqual(
            1,
            is_service_account_valid_by_username.call_count,
            "the verification of the service account should have only be made once",
        )
        is_service_account_valid_by_username.assert_called_with(user=request.user, service_account_username=username)

        # Assert that the created principal has the data from the username.
        self.assertEqual(
            username,
            returned_principal.username,
            "the username of the created service account principal does not match the given username to the function",
        )
        self.assertEqual(
            self.tenant,
            returned_principal.tenant,
            "the created service account's principal tenant does not match the one specified",
        )
        self.assertEqual(
            SERVICE_ACCOUNT_KEY,
            returned_principal.type,
            "the type of the created service account principal is not correct",
        )
        self.assertEqual(
            client_id,
            returned_principal.service_account_id,
            "the client ID of the created service account principal does not match the one given to the function under test",
        )

    @mock.patch("management.authorization.token_validator.ITSSOTokenValidator.validate_token")
    @mock.patch("management.principal.it_service.ITService.is_service_account_valid_by_username")
    def test_get_principal_service_account_validated_principal_not_exists(
        self, is_service_account_valid_by_username: Mock, validate_token: Mock
    ):
        """Test that when the "from query" parameter is missing the service account is validated just once"""
        # Create a service account principal in the database, which will be fetched by the function under test.
        client_id = uuid.uuid4()
        username = f"service-account-{client_id}"

        # Simulate that a bearer token was given, and that it was correctly validated.
        validate_token.return_value = "mocked-bearer-token"

        # Simulate that the IT service says the service account's username is valid.
        is_service_account_valid_by_username.return_value = True

        # Mock the request with the required bits.
        user = User()
        user.client_id = str(uuid.uuid4())
        user.is_service_account = True
        user.username = f"service-account-{user.client_id}"

        request = Mock()
        request.tenant = self.tenant
        request.user = user

        # Call the function under test.
        returned_principal: Principal = get_principal(
            username=username, request=request, verify_principal=True, from_query=False
        )

        # Assert that the validation function gets called once.
        self.assertEqual(
            1,
            is_service_account_valid_by_username.call_count,
            "the verification of the service account should have only be made once",
        )
        is_service_account_valid_by_username.assert_called_with(user=request.user, service_account_username=username)

        # Assert that the created principal has the data from the username.
        self.assertEqual(
            username,
            returned_principal.username,
            "the username of the created service account principal does not match the given username to the function",
        )
        self.assertEqual(
            self.tenant,
            returned_principal.tenant,
            "the created service account's principal tenant does not match the one specified",
        )
        self.assertEqual(
            SERVICE_ACCOUNT_KEY,
            returned_principal.type,
            "the type of the created service account principal is not correct",
        )
        self.assertEqual(
            client_id,
            returned_principal.service_account_id,
            "the client ID of the created service account principal does not match the one given to the function under test",
        )
