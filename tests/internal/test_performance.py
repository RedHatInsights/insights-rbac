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
from unittest.mock import patch

from django.db import connection
from django.test import TestCase
from django.urls import reverse
from api.common import RH_IDENTITY_HEADER
from management.role.model import ExtRoleRelation, ExtTenant

from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant, User
from api.serializers import create_tenant_name
from tests.identity_request import IdentityRequest
from rbac.middleware import HttpResponseUnauthorizedRequest, IdentityHeaderMiddleware, TENANTS
from management.models import Access, Group, Permission, Principal, Policy, ResourceDefinition, Role

class OCMPerformanceTest(IdentityRequest):

    def setUp(self):
        super().setUp()

        self.tenant = Tenant.objects.create(tenant_name="acct12345", org_id="4585")
        self.tenant.ready = True
        self.tenant.save()

        self.ext_tenant = ExtTenant.objects.create(name="acct12345")
        self.ext_tenant.ready = True
        self.ext_tenant.save()

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

        self.principal_a = Principal.objects.create(username="principal_a", tenant=self.tenant)
        self.principal_b = Principal.objects.create(username="principal_b", tenant=self.tenant)
        self.group_a = Group.objects.create(name="group_a", tenant=self.tenant)
        self.group_b = Group.objects.create(name="group_b", tenant=self.tenant)
        self.policy_a = Policy.objects.create(name="policy_a", tenant=self.tenant)
        self.policy_b = Policy.objects.create(name="policy_b", tenant=self.tenant)
        self.role_a = Role.objects.create(name="role_a", tenant=self.tenant)
        self.role_b = Role.objects.create(name="role_b", tenant=self.tenant)

        self.ext_role_a = ExtRoleRelation.objects.create(ext_id="OCMRoleTest1", ext_tenant=self.ext_tenant, role=self.role_a)
        self.ext_role_b = ExtRoleRelation.objects.create(ext_id="OCMRoleTest2", ext_tenant=self.ext_tenant, role=self.role_b)

        self.ext_role_a.save()
        self.ext_role_b.save()

        self.group_a.principals.add(self.principal_a)
        self.group_b.principals.add(self.principal_b)

        self.group_a.policies.add(self.policy_a)
        self.group_b.policies.add(self.policy_b)

        self.group_a.save()
        self.group_b.save()

        self.policy_a.roles.add(self.role_a)

        self.policy_b.roles.add(self.role_b)

        self.policy_a.save()

        self.principal_a.save()
        self.principal_b.save()
        self.policy_b.save()
        self.role_a.save()
        self.role_b.save()

    def test_creations(self):
        """Test the creation of the objects."""
        self.assertEqual(Principal.objects.count(), 2)
        self.assertEqual(Group.objects.count(), 2)
        self.assertEqual(Policy.objects.count(), 2)
        self.assertEqual(Role.objects.count(), 2)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "4585",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "principal_a",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_tenant_groups(self, mock_request):
        """Test tenant groups"""
        # 1 request for each tenant (to get tenant's groups)
        response = self.client.get(
            f"/_private/api/v1/integrations/tenant/{self.tenant.org_id}/groups/?username=principal_a",
            **self.request.META,
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Expecting ["group_a", "]
        self.assertEqual(response.data.get("meta").get("count"), 1)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "4585",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "principal_a",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_group_roles(self, mock_request):
        """Test group roles."""
        # 1 request for each group (to get roles)
        groups = Group.objects.all()

        for group in groups:
            response = self.client.get(
                f"/_private/api/v1/integrations/tenant/{self.tenant.org_id}/groups/{group.uuid}/roles/",
                **self.request.META,
                follow=True,
            )

            # ensure the correct response
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            # ensure the correct number of roles
            self.assertEqual(response.data.get("meta").get("count"), 1)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "4585",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "principal_a",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_tenant_principals(self, mock_request):
        """Test tenant principals."""
        # 1 request for each tenant (to get the principles)

        principles = Principal.objects.all()
        # use default endpoint

        # for principle in principles:
            # response = self.client.get(
            #     f"/_private/api/v1/tenant/{self.tenant.org_id}/principals/",
            #     **self.request.META,
            #     follow=True,
            # )

            # # ensure the correct response
            # self.assertEqual(response.status_code, status.HTTP_200_OK)
            # # ensure the correct number of principles
            # self.assertEqual(response.data.get("meta").get("count"), 1)

    @patch(
        "management.principal.proxy.PrincipalProxy.request_filtered_principals",
        return_value={
            "status_code": 200,
            "data": [
                {
                    "org_id": "4585",
                    "is_org_admin": False,
                    "is_internal": False,
                    "id": 52567473,
                    "username": "principal_a",
                    "account_number": "1111111",
                    "is_active": True,
                }
            ],
        },
    )
    def test_principal_groups(self, mock_request):
        """Test principal groups."""
        # 1 request for each principle in each org (to get the principles' groups)
        principles = Principal.objects.all()

        for principle in principles:
            response = self.client.get(
                    f"/_private/api/v1/integrations/tenant/{self.tenant.org_id}/principal/{principle.username}/groups/",
                    **self.request.META,
                    follow=True,
                )

            # ensure the correct response
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            # ensure the correct number of roles
            self.assertEqual(response.data.get("meta").get("count"), 1)

    @classmethod
    def tearDownClass(self):
        """Clean up the test."""
        Group.objects.all().delete()
        Role.objects.all().delete()
        Policy.objects.all().delete()
        Principal.objects.all().delete()
        Tenant.objects.all().delete()
        ExtTenant.objects.all().delete()
        ExtRoleRelation.objects.all().delete()
        super().tearDownClass()