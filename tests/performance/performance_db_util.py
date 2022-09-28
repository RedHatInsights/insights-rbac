from http.client import REQUEST_TIMEOUT
from multiprocessing.pool import ThreadPool
import time

import concurrent
from concurrent.futures import ThreadPoolExecutor, as_completed
from faker import Faker

from base64 import b64encode
from json import dumps as json_dumps
from urllib import request, response

from django.core.management.base import BaseCommand
import unittest

from django.test import SimpleTestCase, TestCase
from management.role.model import ExtRoleRelation, ExtTenant
from rbac.settings import DATABASES

from rest_framework import status

from api.models import Tenant, User
from api.serializers import create_tenant_name
from rbac.middleware import HttpResponseUnauthorizedRequest, IdentityHeaderMiddleware, TENANTS
from management.models import Access, Group, Permission, Principal, Policy, ResourceDefinition, Role

N_TENANTS = 2
GROUPS_PER_TENANT = 1

N = 1  # number of roles per group, number of principals per group
PRINCIPLES_PER_TENANT = 1

def setUp():
    """Set up the test data."""
    print("Setting up test data...")
    tenants = []

    if ExtTenant.objects.filter(name="ocm").exists():
        ext_tenant = ExtTenant.objects.get(name="ocm")
    else:
        ext_tenant = ExtTenant.objects.create(name="ocm")

    def create_tenant(i):
        account = i

        if (Tenant.objects.filter(tenant_name=f"ocm_acct{account}").exists()):
            t = Tenant.objects.get(tenant_name=f"ocm_acct{account}")
        else:
            t = Tenant.objects.create(
                org_id=i,
                account_id=account,
                tenant_name=f"ocm_acct{account}",
            )
            t.ready = True
            t.save()

        return t

    # create 2k tenants locally (so 2k different orgs)
    for i in range(N_TENANTS):
        tenants.append(create_tenant(i))

    def create_principal(tenant, i, j):
        username = f"ocm_principal_{i}_{j}"
        if (Principal.objects.filter(username=username).exists()):
            Principal.objects.get(username=username)
        else:
            Principal.objects.create(
                username=username,
                tenant=tenant,
            )

    # for each org, create 10 principals
    for i in range(N_TENANTS):
        for j in range(PRINCIPLES_PER_TENANT):
            create_principal(tenants[i], i, j)

    def create_group(tenant, i, j):
        name = f"ocm_group_{i}_{j}"
        group = None
        if (Group.objects.filter(name=name).exists()):
            group = Group.objects.get(name=name)
        else:
            group = Group.objects.create(
                name=name,
                tenant=tenant,
            )

        name = f"ocm_policy_{i}_{j}"
        policy = None
        if (Policy.objects.filter(name=name).exists()):
            policy = Policy.objects.get(name=name)
        else:
            policy = Policy.objects.create(
                name=name,
                tenant=tenant,
            )

        # for each group, add "n" number of roles (should be OCM roles, so those with an external tenant)
        for k in range(N):
            name = f"ocm_role_{i}_{j}_{k}"
            role = None
            if (Role.objects.filter(name=name).exists()):
                role = Role.objects.get(name=name)
            else:
                role = Role.objects.create(
                    name=name,
                    tenant=tenant,
                )

                ExtRoleRelation.objects.create(
                    ext_id=f"ocm_r_r{i}_{j}_{k}",
                    ext_tenant=ext_tenant,
                    role=role,
                )

            policy.roles.add(role)

        policy.save()
        group.policies.add(policy)

        # for each group, assign "n" number of principals to the group
        for k in range(N):
            group.principals.add(Principal.objects.get(username=f"ocm_principal_{i}_{k}"))

        group.save()

    for i in range(N_TENANTS):
        for j in range(GROUPS_PER_TENANT):
            create_group(tenants[i], i, j)

    print("Finished setting up test data")

def tearDown():
    """Delete the test data."""
    print("Deleting test data...")

    Principal.objects.filter(username=r'^ocm_principal_.+').delete()
    print(f"Deleted {Group.objects.filter(name=r'^ocm_group_.+').count()} groups")
    Group.objects.filter(name=r"^ocm_group_0_0").delete()
    print(f"Deleted {Group.objects.filter(name=r'^ocm_group_.+').count()} groups")
    Policy.objects.filter(name=r"^ocm_policy_.+").delete()
    Role.objects.filter(name=r"^ocm_role_.+").delete()
    ExtRoleRelation.objects.filter(ext_id=r"^ocm_r_r_.+").delete()
    Tenant.objects.filter(tenant_name=r"^ocm_acct.+").delete()

    print("Finished deleting test data")