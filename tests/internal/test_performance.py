# Baseline tests for OCM performance 
# 
# 1 request for each tenant (to get tenant's groups)
# 1 request for each group (to get roles)
# 1 request for each tenant (to get the principles)
# 1 request for each principle in each org (to get the principles' groups)

# Populate the database with a large number of tenants, groups, principles, and roles
# ~20k requests = ~2k tenants ~10 principle per tenant 
# optional req: 2 groups per principle, 5 roles per group with 10 permissions each

import collections
import os
from unittest.mock import Mock
from django.conf import settings

from django.db import connection
from django.test import TestCase
from django.urls import reverse
from api.common import RH_IDENTITY_HEADER

from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant, User
from api.serializers import create_tenant_name
from tests.identity_request import IdentityRequest
from rbac.middleware import HttpResponseUnauthorizedRequest, IdentityHeaderMiddleware, TENANTS
from management.models import Access, Group, Permission, Principal, Policy, ResourceDefinition, Role

class OCMPerformanceTest(TestCase):
    @classmethod
    def setUpClass(self):
        """Set up the tenant."""
        super().setUpClass()
        self.tenant = Tenant.objects.create(tenant_name="acct12345", org_id="4585")
        self.tenant.ready = True
        self.tenant.save()

    def setUp(self):
        super().setUp()
        self.principal_a = Principal.objects.create(username="principal_a", tenant=self.tenant)
        self.principal_b = Principal.objects.create(username="principal_b", tenant=self.tenant)
        self.group_a = Group.objects.create(name="group_a", platform_default=True, tenant=self.tenant)
        self.group_b = Group.objects.create(name="group_b", tenant=self.tenant)
        self.policy_a = Policy.objects.create(name="policy_a", tenant=self.tenant)
        self.policy_b = Policy.objects.create(name="policy_b", tenant=self.tenant)
        self.role_a = Role.objects.create(name="role_a", tenant=self.tenant)
        self.role_b = Role.objects.create(name="role_b", tenant=self.tenant)

    def test_creations(self):
        """Test the creation of the objects."""
        self.assertEqual(Tenant.objects.count(), 1)
        self.assertEqual(Principal.objects.count(), 2)
        self.assertEqual(Group.objects.count(), 2)
        self.assertEqual(Policy.objects.count(), 2)
        self.assertEqual(Role.objects.count(), 2)

    # def test_tenant_groups(self):
    #     """Test tenant groups."""
    #     # 1 request for each tenant (to get tenant's groups)
    #     with self.assertNumQueries(1):
    #         self.tenant.groups.all()

    # def test_group_roles(self):
    #     """Test group roles."""
    #     # 1 request for each group (to get roles)
    #     with self.assertNumQueries(1):
    #         self.group_a.roles.all()

    # def test_tenant_principals(self):
    #     """Test tenant principals."""
    #     # 1 request for each tenant (to get the principles)
    #     with self.assertNumQueries(1):
    #         self.tenant.principals.all()

    # def test_principal_groups(self):
    #     """Test principal groups."""
    #     # 1 request for each principle in each org (to get the principles' groups)
    #     with self.assertNumQueries(1):
    #         self.principal_a.groups.all()

    @classmethod
    def tearDownClass(self):
        self.tenant.delete()
        super().tearDownClass()