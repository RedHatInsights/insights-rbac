# Baseline tests for OCM performance 
# 
# 1 request for each tenant (to get tenant's groups)
# 1 request for each group (to get roles)
# 1 request for each tenant (to get the principles)
# 1 request for each principle in each org (to get the principles' groups)

# Populate the database with a large number of tenants, groups, principles, and roles
# ~20k requests = ~2k tenants ~10 principle per tenant 
# optional req: 2 groups per principle, 5 roles per group with 10 permissions each

from http.client import REQUEST_TIMEOUT
import time

import concurrent
from concurrent.futures import ThreadPoolExecutor, as_completed

from base64 import b64encode
from json import dumps as json_dumps
from urllib import request, response

from django.test import TestCase
from management.role.model import ExtRoleRelation, ExtTenant

from rest_framework import status

from api.models import Tenant, User
from api.serializers import create_tenant_name
from rbac.middleware import HttpResponseUnauthorizedRequest, IdentityHeaderMiddleware, TENANTS
from management.models import Access, Group, Permission, Principal, Policy, ResourceDefinition, Role

N = 10 # number of roles per group, number of principals per group
N_TENANTS = 10

PRINCIPLES_PER_TENANT = 10
GROUPS_PER_TENANT = 2

HEADERS = {"User-Type":"associate"}

THREADS = 10

class OCMPerformanceTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        """Set up the test data."""

        tenants = []
        ext_tenant = ExtTenant.objects.create(
                name="ocm")
        # create 2k tenants locally (so 2k different orgs)
        for i in range(N_TENANTS):
            tenants.append(Tenant.objects.create(
                org_id=f"{i}",
                tenant_name=f"Tenant {i}"
            ))
            tenants[i].ready = True
            tenants[i].save()

        # for each org, create 10 principals
        for i in range(N_TENANTS):
            for j in range(PRINCIPLES_PER_TENANT):
                Principal.objects.create(
                    username=f"principal_{i}_{j}",
                    tenant=tenants[i],
                )

        # for each org, create 2 custom groups
        for i in range(N_TENANTS):
            for j in range(GROUPS_PER_TENANT):
                group = Group.objects.create(
                    name=f"group_{i}_{j}",
                    tenant=tenants[i],
                )

                policy = Policy.objects.create(
                    name=f"policy_{i}_{j}",
                    tenant=tenants[i],
                )

                roles = []
                # for each group, add "n" number of roles (should be OCM roles, so those with an external tenant)
                for k in range(N):
                    role = Role.objects.create(
                        name=f"role_{i}_{j}_{k}",
                        tenant=tenants[i],
                    )

                    ExtRoleRelation.objects.create(
                        ext_id=f"OCM_{i}_{j}_{k}",
                        ext_tenant=ext_tenant,
                        role=role,
                    )

                    policy.roles.add(role)
                
                policy.save()
                group.policies.add(policy)
        
                # for each group, assign "n" number of principals to the group
                for k in range(N):
                    group.principals.add(Principal.objects.get(username=f"principal_{i}_{k}"))

                group.save()

    def test_seeding(self):
        """Test seeding."""
        self.assertEqual(Principal.objects.count(), N_TENANTS * PRINCIPLES_PER_TENANT)
        self.assertEqual(Group.objects.count(), N_TENANTS * GROUPS_PER_TENANT)
        self.assertEqual(Policy.objects.count(), N_TENANTS * GROUPS_PER_TENANT)
        self.assertEqual(Role.objects.count(), N_TENANTS * GROUPS_PER_TENANT * N)

    def test_tenant_groups(self):
        """Test tenant groups with /integrations/tenant/{tenant_id}/groups/ endpoint."""

        tenants = Tenant.objects.exclude(tenant_name="public")
        # 1 request for each tenant (to get tenant's groups)

        start = timerStart("Tenant groups")

        for t in tenants:
            response = self.client.get(
              f"/_private/api/v1/integrations/tenant/{t.org_id}/groups/?external_tenant=ocm",
                HEADERS,
                follow=True,
            )

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data.get("meta").get("count"), GROUPS_PER_TENANT)

        timerStop(start, N_TENANTS)

    def test_tenant_roles(self):
        """Test tenant roles with /integrations/tenant/{tenant_id}/roles/ endpoint."""
        tenants = Tenant.objects.exclude(tenant_name="public")
        # 1 request for each tenant (to get the tenant's roles)

        start = timerStart("Tenant roles")
        
        for t in tenants:
            response = self.client.get(
                f"/_private/api/v1/integrations/tenant/{t.org_id}/roles/?external_tenant=ocm",
                HEADERS,
                follow=True,
            )

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data.get("meta").get("count"), N * GROUPS_PER_TENANT)
        
        timerStop(start, N_TENANTS)

    def test_group_roles(self):
        """Test group roles with /integrations/tenant/{tenant_id}/groups/{group_id}/roles/ endpoint."""
        # 1 request for each group (to get roles)

        tenants = Tenant.objects.exclude(tenant_name="public")

        start = timerStart("Group Roles")

        for t in tenants:
            groups = Group.objects.filter(tenant=t)

            for g in groups:
                response = self.client.get(
                    f"/_private/api/v1/integrations/tenant/{t.org_id}/groups/{g.uuid}/roles/?external_tenant=ocm",
                    HEADERS,
                    follow=True,
                )

                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(response.data.get("meta").get("count"), N)

        timerStop(start, N_TENANTS * GROUPS_PER_TENANT)

    def test_principals_groups(self):
        """Test tenant principals groups with /integrations/tenant/{tenant_id}/principal/{principal_id}/groups/ endpoint."""
        # 1 request for each tenant (to get the principles)

        tenants = Tenant.objects.exclude(tenant_name="public")

        start = timerStart("Principals Groups")

        for t in tenants:
            principals = Principal.objects.filter(tenant=t)

            for p in principals:
                response = self.client.get(
                    f"/_private/api/v1/integrations/tenant/{t.org_id}/principal/{p.username}/groups/?external_tenant=ocm",
                    HEADERS,
                    follow=True,
                )

                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(response.data.get("meta").get("count"), GROUPS_PER_TENANT)

        timerStop(start, N_TENANTS * PRINCIPLES_PER_TENANT)

    def test_principals_roles(self):
        """Test tenant principals roles with /integrations/tenant/{tenant_id}/principal/{principal_id}/groups/{group_id}/roles/ endpoint."""
        # 1 request for each tenant (to get the principles)
        tenants = Tenant.objects.exclude(tenant_name="public")

        start = timerStart("Principals Roles")

        for t in tenants:
            principals = Principal.objects.filter(tenant=t)

            for p in principals:
                groups = Group.objects.filter(tenant=t)

                for g in groups:
                    response = self.client.get(
                        f"/_private/api/v1/integrations/tenant/{t.org_id}/principal/{p.username}/groups/{g.uuid}/roles/?external_tenant=ocm",
                        HEADERS,
                        follow=True,
                    )

                    self.assertEqual(response.status_code, status.HTTP_200_OK)
                    self.assertEqual(response.data.get("meta").get("count"), N)

        timerStop(start, N_TENANTS * PRINCIPLES_PER_TENANT * GROUPS_PER_TENANT)

    def test_full_sync(self):
        """Test full sync with /integrations/tenant/{tenant_id}/sync/ endpoint."""
        tenants = Tenant.objects.exclude(tenant_name="public")

        num_requests = N_TENANTS * (2 + GROUPS_PER_TENANT + PRINCIPLES_PER_TENANT)

        start = timerStart("Full Sync")

        for t in tenants:
            # tenant groups, get orgs groups
            response = self.client.get(
                f"/_private/api/v1/integrations/tenant/{t.org_id}/groups/?external_tenant=ocm",
                HEADERS,
                follow=True,
            )

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data.get("meta").get("count"), GROUPS_PER_TENANT)

            groups = response.data.get("data")
            
            for g in groups:
                g_uuid = g.get("uuid")
                # tenant groups rolesk, get orgs groups roles
                response = self.client.get(
                    f"/_private/api/v1/integrations/tenant/{t.org_id}/groups/{g_uuid}/roles/?external_tenant=ocm",
                    HEADERS,
                    follow=True,
                )

                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(response.data.get("meta").get("count"), N)

            # no ocm specific endpoint to get principals per tenant

            # make header with tenant specified
            response = self.client.get(
                f"/_private/api/v1/principals/?external_tenant=ocm",
                HEADERS,
                follow=True,
            )
            
            principals = Principal.objects.filter(tenant=t)
            for p in principals:
                response = self.client.get(
                    f"/_private/api/v1/integrations/tenant/{t.org_id}/principal/{p.username}/groups/?external_tenant=ocm",
                    HEADERS,
                    follow=True,
                )

                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(response.data.get("meta").get("count"), GROUPS_PER_TENANT)

        timerStop(start, num_requests)

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

# ---------------------------
# a couple of logging helpers
# ---------------------------
def timerStart(test_title):
    """Start timer."""
    start = time.perf_counter()

    print(f"Starting test for {test_title}...")

    return start

def timerStop(start, num_requests):
    """Stop timer."""
    request_time = time.perf_counter() - start

    average = request_time / num_requests

    print(f"Total request time: {request_time} seconds")
    print("Average time: {} seconds".format(average))
    
    return request_time