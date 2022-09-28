# Baseline tests for OCM performance
#
# 1 request for each tenant (to get tenant's groups)
# 1 request for each group (to get roles)
# 1 request for each tenant (to get the principles)
# 1 request for each principle in each org (to get the principles' groups)

# Populate the database with a large number of tenants, groups, principles, and roles
# ~20k requests = ~2k tenants ~10 principle per tenant
# optional req: 2 groups per principle, 5 roles per group with 10 permissions each

from concurrent.futures import ThreadPoolExecutor, as_completed

from django.db.models import Q

from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant
from management.models import Group, Principal

import logging
import time

HEADERS = {
    "HTTP_X_RH_IDENTITY": {
        "account_number": "10001",
        "org_id": "11111",
        "type": "Internal",
                "user": {
                    "username": "user_dev",
                    "email": "user_dev@foo.com",
                    "is_org_admin": True,
                    "is_internal": True,
                    "user_id": "51736777",
                },
        "internal": {"cross_access": False},
    }
}

THREADS = 10

client = APIClient()

logger = logging.getLogger(__name__)

def test_tenant_groups():
    """Test tenant groups with /integrations/tenant/{tenant_id}/groups/ endpoint."""
    # 1 request for each tenant (to get tenant's groups)

    tenants = Tenant.objects.filter(Q(group__system=False) | Q(role__system=False)).prefetch_related('group_set', 'role_set').distinct()

    name = "Tenant Groups"
    start = timerStart(name)

    num_requests = tenants.count()

    def tenant_groups(tenant):
        response = client.get(
            f"/_private/api/v1/integrations/tenant/{tenant.org_id}/groups/?external_tenant=ocm",
            HEADERS,
            follow=True,
        )

        return response

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = []
        for t in tenants:
            futures.append(executor.submit(tenant_groups, tenant=t))
        for future in as_completed(futures):
            response = future.result()
            if (response.status_code != status.HTTP_200_OK):
                Exception("Recieved an error status\n")

    request_time, average = timerStop(start, num_requests)

    write_to_logger(
        name,
        "/api/v1/integrations/tenant/org_id/groups/",
        num_requests,
        request_time,
        average)

def test_tenant_roles():
    """Test tenant roles with /integrations/tenant/{tenant_id}/roles/ endpoint."""
    tenants = Tenant.objects.filter(Q(group__system=False) | Q(role__system=False)).prefetch_related('group_set', 'role_set').distinct()
    # 1 request for each tenant (to get the tenant's roles)

    name = "Tenant Roles"
    start = timerStart(name)

    num_requests = tenants.count()

    def tenant_roles(tenant):
        response = client.get(
            f"/_private/api/v1/integrations/tenant/{t.org_id}/roles/?external_tenant=ocm",
            HEADERS,
            follow=True,
        )

        return response

    with ThreadPoolExecutor(max_workers=1) as executor:
        futures = []
        for t in tenants:
            futures.append(executor.submit(tenant_roles, tenant=t))
        for future in as_completed(futures):
            response = future.result()
            if (response.status_code != status.HTTP_200_OK):
                Exception("Recieved an error status\n")

    request_time, average = timerStop(start, num_requests)

    write_to_logger(
        name,
        "/api/v1/integrations/tenant/{org_id}/roles/",
        num_requests,
        request_time,
        average
    )

def test_group_roles():
    """Test group roles with /integrations/tenant/{tenant_id}/groups/{group_id}/roles/ endpoint."""
    # 1 request for each group (to get roles)
    tenants = Tenant.objects.filter(Q(group__system=False) | Q(role__system=False)).prefetch_related('group_set', 'role_set').distinct()

    num_requests = tenants.count()

    name = "Group Roles"
    start = timerStart(name)

    def group_roles(t, g):
        response = client.get(
            f"/_private/api/v1/integrations/tenant/{t.org_id}/groups/{g.uuid}/roles/?external_tenant=ocm",
            HEADERS,
            follow=True,
        )

        return response

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = []
        for t in tenants:
            groups = Group.objects.filter(tenant=t)
            for g in groups:
                futures.append(executor.submit(group_roles, t=t, g=g))
        for future in as_completed(futures):
            response = future.result()
            if (response.status_code != status.HTTP_200_OK):
                Exception("Recieved an error status\n")

    request_time, average = timerStop(start, num_requests)

    write_to_logger(
        name,
        "/api/v1/integrations/tenant/{org_id}/groups/{g_uuid}/roles/",
        num_requests,
        request_time,
        average
    )

def test_principals_groups():
    """Test tenant principals groups with /integrations/tenant/{tenant_id}/principal/{principal_id}/groups/ endpoint."""
    # 1 request for each tenant (to get the principles)

    tenants = Tenant.objects.filter(Q(group__system=False) | Q(role__system=False)).prefetch_related('group_set', 'role_set').distinct()

    name = "Principals Groups"
    start = timerStart(name)

    num_requests = 0

    def principals_groups(t, p):
        response = client.get(
            f"/_private/api/v1/integrations/tenant/{t.org_id}/principal/{p.username}/groups/?external_tenant=ocm",
            HEADERS,
            follow=True,
        )

        return response

    for t in tenants:
        principals = Principal.objects.filter(tenant=t)

        for p in principals:
            num_requests += 1
            response = client.get(
                f"/_private/api/v1/integrations/tenant/{t.org_id}/principal/{p.username}/groups/?external_tenant=ocm",
                HEADERS,
                follow=True,
            )

            if (response.status_code != status.HTTP_200_OK):
                Exception("Recieved an error status\n")

    request_time, average = timerStop(start, num_requests)

    write_to_logger(
        name,
        "/api/v1/integrations/tenant/{org_id}/principal/{username}/groups/",
        num_requests,
        request_time,
        average
    )

def test_principals_roles():
    """Test tenant principals roles with /integrations/tenant/{tenant_id}/principal/{principal_id}/groups/{group_id}/roles/ endpoint."""
    # 1 request for each tenant (to get the principles)
    tenants = Tenant.objects.filter(Q(group__system=False) | Q(role__system=False)).prefetch_related('group_set', 'role_set').distinct()

    name = "Principals Roles"
    start = timerStart(name)

    num_requests = 0

    for t in tenants:
        principals = Principal.objects.filter(tenant=t)

        for p in principals:
            groups = Group.objects.filter(tenant=t)

            for g in groups:
                response = client.get(
                    f"/_private/api/v1/integrations/tenant/{t.org_id}/principal/{p.username}/groups/{g.uuid}/roles/?external_tenant=ocm",
                    HEADERS,
                    follow=True,
                )
                if (response.status_code != status.HTTP_200_OK):
                    Exception("Recieved an error status\n")

                num_requests += 1

    request_time, average = timerStop(start, num_requests)

    write_to_logger(
        name,
        "/api/v1/integrations/tenant/{org_id}/principal/{username}/groups/{g_uuid}/roles/",
        num_requests,
        request_time,
        average
    )

def test_full_sync():
    """Test full sync with /integrations/tenant/{tenant_id}/sync/ endpoint."""
    tenants = Tenant.objects.filter(Q(group__system=False) | Q(role__system=False)).prefetch_related('group_set', 'role_set').distinct()

    name = "Full Sync"
    start = timerStart(name)

    num_requests = 0

    for t in tenants:
        num_requests += 1
        # tenant groups, get orgs groups
        response = client.get(
            f"/_private/api/v1/integrations/tenant/{t.org_id}/groups/?external_tenant=ocm",
            HEADERS,
            follow=True,
        )
        if (response.status_code != status.HTTP_200_OK):
            Exception("Recieved an error status\n")

        groups = response.data.get("data")

        for g in groups:
            num_requests += 2
            g_uuid = g.get("uuid")
            # tenant groups rolesk, get orgs groups roles
            response = client.get(
                f"/_private/api/v1/integrations/tenant/{t.org_id}/groups/{g_uuid}/roles/?external_tenant=ocm",
                HEADERS,
                follow=True,
            )

            if (response.status_code != status.HTTP_200_OK):
                Exception("Recieved an error status\n")

            response = client.get(
                f"/_private/api/v1/integrations/tenant/{t.org_id}/groups/{g_uuid}/principals/?external_tenant=ocm",
                HEADERS,
                follow=True,
            )

            if (response.status_code != status.HTTP_200_OK):
                Exception("Recieved an error status\n")

    request_time, average = timerStop(start, num_requests)

    write_to_logger(name, "", num_requests, request_time, average)

# ---------------------------
# A couple of logging helpers
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

    return request_time, average

def write_to_logger(name, url, num_requests, request_time, average):
    """Write data to excel sheet."""

    logger.info(f"Test: {name}")
    logger.info(f"URL: {url}")
    logger.info(f"Number of requests: {num_requests}")
    logger.info(f"Total request time: {request_time} seconds")
    logger.info(f"Average time: {average} seconds")
    logger.info(f"Requests per second: {1 / average}")