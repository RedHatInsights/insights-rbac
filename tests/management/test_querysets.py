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
"""Test the Management queryset helpers."""
from unittest.mock import Mock

from django.core.exceptions import PermissionDenied
from django.db import connection
from django.db.models.aggregates import Count
from django.test import TestCase
from django.urls import reverse
from management.group.model import Group
from management.policy.model import Policy
from management.principal.model import Principal
from management.role.model import Role
from management.models import Permission, Access
from management.querysets import (
    PRINCIPAL_SCOPE,
    SCOPE_KEY,
    get_group_queryset,
    get_policy_queryset,
    get_role_queryset,
    get_access_queryset,
)
from management.utils import APPLICATION_KEY
from rest_framework import serializers

from api.models import Tenant, User
from tests.identity_request import IdentityRequest


class QuerySetTest(TestCase):
    """Test the Management queryset helper functions."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.tenant = Tenant.objects.get(schema_name="test")
        except:
            cls.tenant = Tenant(schema_name="test")
            cls.tenant.save(verbosity=0)
            cls.tenant.create_schema()

        connection.set_tenant(cls.tenant)

    @classmethod
    def tearDownClass(cls):
        connection.set_schema_to_public()
        cls.tenant.delete()

    def _create_groups(self):
        """Setup groups for tests."""
        Group.objects.create(name="group1", tenant=self.tenant)
        Group.objects.create(name="group2", tenant=self.tenant)
        Group.objects.create(name="group3", tenant=self.tenant)
        Group.objects.create(name="group4", tenant=self.tenant)
        Group.objects.create(name="group5", tenant=self.tenant)

    def _create_roles(self):
        """Setup roles for tests."""
        Role.objects.create(name="role1", tenant=self.tenant)
        Role.objects.create(name="role2", tenant=self.tenant)
        Role.objects.create(name="role3", tenant=self.tenant)
        Role.objects.create(name="role4", tenant=self.tenant)
        Role.objects.create(name="role5", tenant=self.tenant)

    def _create_policies(self):
        """Setup policies for tests."""
        Policy.objects.create(name="policy1", tenant=self.tenant)
        Policy.objects.create(name="policy2", tenant=self.tenant)
        Policy.objects.create(name="policy3", tenant=self.tenant)
        Policy.objects.create(name="policy4", tenant=self.tenant)
        Policy.objects.create(name="policy5", tenant=self.tenant)

    def test_get_group_queryset_admin(self):
        """Test get_group_queryset as an admin."""
        self._create_groups()
        user = Mock(spec=User, admin=True)
        req = Mock(user=user, tenant=self.tenant, query_params={})
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_user_group_queryset_admin(self):
        """Test get_group_queryset as an admin."""
        self._create_groups()
        principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        group = Group.objects.first()
        group.principals.add(principal)
        user = Mock(spec=User, admin=True, account="00001", username="test_user")
        req = Mock(user=user, tenant=self.tenant, query_params={"username": "test_user"})
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_group_queryset_get_users_own_groups(self):
        """Test get_group_queryset to get a users own groups."""
        self._create_groups()
        principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        group = Group.objects.first()
        group.principals.add(principal)
        user = Mock(spec=User, admin=False, account="00001", username="test_user")
        req = Mock(
            user=user,
            method="GET",
            tenant=self.tenant,
            query_params={"username": "test_user"},
            path=reverse("group-list"),
        )
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_group_queryset_get_users_other_users_groups(self):
        """Test get_group_queryset to get a users other users groups."""
        self._create_groups()
        principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        principal2 = Principal.objects.create(username="test_user2", tenant=self.tenant)
        group = Group.objects.first()
        group.principals.add(principal)
        user = Mock(spec=User, admin=False, account="00001", username="test_user")
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={"username": "test_user2"})
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_user_group_queryset_admin_default_org_admin(self):
        """Test get_group_queryset as an org admin searching for admin default groups."""
        principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        group = Group.objects.create(name="group_admin_default", tenant=self.tenant, admin_default=True)
        group.principals.add(principal)
        user = Mock(spec=User, admin=True, account="00001", username="test_user")
        req = Mock(user=user, tenant=self.tenant, query_params={"username": "test_user"})
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_user_group_queryset_admin_default_non_org_admin(self):
        """Test get_group_queryset not as an org admin, searching for admin default groups."""
        principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        group = Group.objects.create(name="group_admin_default", tenant=self.tenant, admin_default=True)
        group.principals.add(principal)
        user = Mock(spec=User, admin=False, account="00001", username="test_user")
        req = Mock(user=user, tenant=self.tenant, query_params={"username": "test_user"})
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_user_group_queryset_admin_default_rbac_admin(self):
        """Test get_group_queryset not as an org admin, but as an RBAC admin searching for admin default groups."""
        principal = Principal.objects.create(username="test_user", tenant=self.tenant)
        group = Group.objects.create(name="group_admin_default", tenant=self.tenant, admin_default=True)
        group.principals.add(principal)
        permission = Permission.objects.create(permission="rbac:*:*", tenant=self.tenant)
        rbac_admin_role = Role.objects.create(name="RBAC admin role", tenant=self.tenant)
        access = Access.objects.create(permission=permission, role=rbac_admin_role, tenant=self.tenant)
        user = Mock(spec=User, admin=False, account="00001", username="test_user", access=access)
        req = Mock(user=user, tenant=self.tenant, query_params={"username": "test_user"})
        queryset = get_group_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_role_queryset_admin(self):
        """Test get_role_queryset as an admin."""
        self._create_roles()
        user = Mock(spec=User, admin=True)
        req = Mock(user=user, tenant=self.tenant, query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 5)
        self.assertIsNotNone(queryset.last().accessCount)

    def test_get_role_queryset_non_admin_username(self):
        """Test get_role_queryset as a non-admin supplying a username."""
        roles = self._setup_roles_for_role_username_queryset_tests()

        user = Mock(spec=User, admin=False, username="test_user2", access={})
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={"username": "test_user2"})
        with self.assertRaises(PermissionDenied):
            get_role_queryset(req)

    def test_get_role_queryset_non_admin_username_with_perms_diff_user(self):
        """Test get_role_queryset as a non-admin supplying a username."""
        roles = self._setup_roles_for_role_username_queryset_tests()

        user = Mock(
            spec=User,
            admin=False,
            username="test_user3",
            access={"role": {"read": ["*"]}, "principal": {"read": ["*"]}},
        )
        req = Mock(user=user, method="GET", query_params={"username": "test_user2"}, tenant=self.tenant)
        get_role_queryset(req)

    def test_get_role_queryset_non_admin_username_with_perms(self):
        """Test get_role_queryset as a non-admin supplying a username."""
        roles = self._setup_roles_for_role_username_queryset_tests()

        user = Mock(
            spec=User,
            admin=False,
            username="test_user2",
            access={"role": {"read": ["*"]}, "principal": {"read": ["*"]}},
        )
        req = Mock(user=user, method="GET", query_params={"username": "test_user2"}, tenant=self.tenant)
        get_role_queryset(req)

    def test_get_role_queryset_non_admin_username_different(self):
        """Test get_role_queryset as a non-admin supplying a different username."""
        roles = self._setup_roles_for_role_username_queryset_tests()

        user = Mock(spec=User, admin=False, username="test_user", access={})
        req = Mock(user=user, tenant=self.tenant, method="GET", query_params={"username": "test_user2"})
        queryset = get_role_queryset(req)
        self.assertEquals(list(queryset), [])
        self.assertEquals(queryset.count(), 0)

    def test_get_role_queryset_admin_username(self):
        """Test get_role_queryset as an admin supplying a username."""
        roles = self._setup_roles_for_role_username_queryset_tests()

        user = Mock(spec=User, admin=True, account="00001", username="test_user2")
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={"username": "test_user2"})
        queryset = get_role_queryset(req)
        role = queryset.last()
        self.assertEquals(list(queryset), [roles.first()])
        self.assertEquals(queryset.count(), 1)
        self.assertTrue(hasattr(role, "accessCount"))
        self.assertTrue(hasattr(role, "policyCount"))

    def test_get_role_queryset_principal_scope(self):
        """Test get_role_queryset with principal scope."""
        roles = self._setup_roles_for_role_username_queryset_tests()

        user = Mock(spec=User, admin=True, account="00001", username="test_user2")
        req = Mock(
            user=user,
            method="GET",
            tenant=self.tenant,
            query_params={SCOPE_KEY: PRINCIPAL_SCOPE, "username": "test_user2"},
        )
        queryset = get_role_queryset(req)
        role = queryset.last()
        self.assertEquals(list(queryset), [roles.first()])
        self.assertEquals(queryset.count(), 1)
        self.assertTrue(hasattr(role, "accessCount"))
        self.assertTrue(hasattr(role, "policyCount"))

    def test_get_role_queryset_admin_username_different(self):
        """Test get_role_queryset as an admin supplying a different username."""
        roles = self._setup_roles_for_role_username_queryset_tests()
        user = Mock(spec=User, admin=True, account="00001", username="admin")
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={"username": "test_user2"})
        queryset = get_role_queryset(req)
        self.assertEquals(list(queryset), [roles.first()])
        self.assertEquals(queryset.count(), 1)

    def test_get_role_queryset_get_all(self):
        """Test get_role_queryset as a user with all access."""
        self._create_roles()
        access = {"role": {"read": ["*"]}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_role_queryset_get_some(self):
        """Test get_role_queryset as a user with one role access."""
        self._create_roles()
        access = {"role": {"read": [Role.objects.first().uuid]}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_role_queryset_get_none(self):
        """Test get_role_queryset as a user with no access."""
        self._create_roles()
        access = {"role": {"read": []}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_role_queryset_post_all(self):
        """Test get_role_queryset as a user with all access."""
        self._create_roles()
        access = {"role": {"write": ["*"]}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="PUT", tenant=self.tenant, query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_role_queryset_put_some(self):
        """Test get_role_queryset as a user with one role access."""
        self._create_roles()
        access = {"role": {"write": [Role.objects.first().uuid]}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="PUT", tenant=self.tenant, query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_role_queryset_put_none(self):
        """Test get_role_queryset as a user with no access."""
        self._create_roles()
        access = {"role": {"write": []}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="PUT", tenant=self.tenant, query_params={})
        queryset = get_role_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_policy_queryset_admin(self):
        """Test get_policy_queryset as an admin."""
        self._create_policies()
        user = Mock(spec=User, admin=True)
        req = Mock(user=user, tenant=self.tenant, query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_policy_queryset_get_all(self):
        """Test get_policy_queryset as a user with all access."""
        self._create_policies()
        access = {"policy": {"read": ["*"]}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_policy_queryset_get_some(self):
        """Test get_policy_queryset as a user with one role access."""
        self._create_policies()
        access = {"policy": {"read": [Policy.objects.first().uuid]}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_policy_queryset_get_none(self):
        """Test get_policy_queryset as a user with no access."""
        self._create_policies()
        access = {"policy": {"read": []}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_policy_queryset_post_all(self):
        """Test get_policy_queryset as a user with all access."""
        self._create_policies()
        access = {"policy": {"write": ["*"]}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="PUT", tenant=self.tenant, query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 5)

    def test_get_policy_queryset_put_some(self):
        """Test get_policy_queryset as a user with one role access."""
        self._create_policies()
        access = {"policy": {"write": [Policy.objects.first().uuid]}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="PUT", tenant=self.tenant, query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_policy_queryset_put_none(self):
        """Test get_policy_queryset as a user with no access."""
        self._create_policies()
        access = {"policy": {"write": []}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="PUT", tenant=self.tenant, query_params={})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_policy_queryset_scope_put_none(self):
        """Test get_policy_queryset for a principal scope with put."""
        self._create_policies()
        access = {"policy": {"write": []}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="PUT", tenant=self.tenant, query_params={SCOPE_KEY: PRINCIPAL_SCOPE})
        queryset = get_policy_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_policy_queryset_bad_scope(self):
        """Test get_policy_queryset with a bad scope."""
        self._create_policies()
        access = {"policy": {"read": ["*"]}}
        user = Mock(spec=User, admin=False, access=access)
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={SCOPE_KEY: "bad"})
        with self.assertRaises(serializers.ValidationError):
            get_policy_queryset(req)

    def test_get_access_queryset_org_admin(self):
        """Test get_access_queryset with an org admin user"""
        user_data = {"username": "test_user", "email": "admin@example.com"}
        customer = {"account_id": "10001"}
        request_context = IdentityRequest._create_request_context(customer, user_data, is_org_admin=True)
        encoded_req = request_context["request"]

        self._setup_group_for_org_admin_tests()

        user = Mock(spec=User, account="00001", username="test_user", admin=True)
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={APPLICATION_KEY: "app"})
        req.META = encoded_req.META

        queryset = get_access_queryset(req)
        self.assertEquals(queryset.count(), 1)

    def test_get_access_queryset_non_org_admin(self):
        """Test get_access_queryset with a non 'org admin' user"""
        user_data = {"username": "test_user", "email": "admin@example.com"}
        customer = {"account_id": "10001"}
        request_context = IdentityRequest._create_request_context(customer, user_data, is_org_admin=False)
        encoded_req = request_context["request"]

        self._setup_group_for_org_admin_tests()

        user = Mock(spec=User, account="00001", username="test_user", admin=False)
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={APPLICATION_KEY: "app"})
        req.META = encoded_req.META

        queryset = get_access_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def test_get_access_queryset_non_org_admin_rbac_admin(self):
        """Test get_access_queryset with a non 'org admin' but rbac admin user"""
        user_data = {"username": "test_user", "email": "admin@example.com"}
        customer = {"account_id": "10001"}
        request_context = IdentityRequest._create_request_context(customer, user_data, is_org_admin=False)
        encoded_req = request_context["request"]

        self._setup_group_for_org_admin_tests()

        permission = Permission.objects.create(permission="rbac:*:*", tenant=self.tenant)
        rbac_admin_role = Role.objects.create(name="RBAC admin role", tenant=self.tenant)
        access = Access.objects.create(permission=permission, role=rbac_admin_role, tenant=self.tenant)
        user = Mock(spec=User, account="00001", username="test_user", admin=False, access=access)
        req = Mock(user=user, method="GET", tenant=self.tenant, query_params={APPLICATION_KEY: "app"})
        req.META = encoded_req.META

        queryset = get_access_queryset(req)
        self.assertEquals(queryset.count(), 0)

    def _setup_group_for_org_admin_tests(self):
        role = Role.objects.create(name="role_admin_default", tenant=self.tenant)
        policy = Policy.objects.create(name="policy_admin_default", tenant=self.tenant)
        group = Group.objects.create(name="group_admin_default", tenant=self.tenant, admin_default=True)
        policy.roles.add(role)
        group.policies.add(policy)
        permission = Permission.objects.create(permission="app:*:*", tenant=self.tenant)
        access = Access.objects.create(permission=permission, role=role, tenant=self.tenant)

    def _setup_roles_for_role_username_queryset_tests(self):
        self._create_groups()
        self._create_policies()
        self._create_roles()

        principal = Principal.objects.create(username="test_user2", tenant=self.tenant)
        group = Group.objects.first()
        policy = Policy.objects.first()
        roles = Role.objects.all()

        policy.roles.add(roles.first())
        group.principals.add(principal)
        group.policies.add(policy)
        return roles
