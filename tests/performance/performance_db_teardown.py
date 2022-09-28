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

class OCMPerformanceTeardown():
    def tearDown(self):
        """Delete the test data."""
        print("Deleting test data...")
        Tenant.objects.filter(tenant_name=r"^ocm_acct+").delete()

        assert(Tenant.objects.filter(account_id="account_id").count() == 0)
        assert(Tenant.objects.filter(tenant_name=r"^ocm_acct+").count() == 0)
        # Principal.objects.filter(username=r'^ocm_principal_+').delete()
        # Group.objects.filter(name=r"^ocm_group_+").delete()
        # Policy.objects.filter(name=r"^ocm_policy_+").delete()
        # Role.objects.filter(name=r"^ocm_role_+").delete()
        # ExtRoleRelation.objects.filter(ext_id=r"^ocm_role_relation_+").delete()
        # Tenant.objects.filter(tenant_name=r"^ocm_acct+").delete()
        # ExtTenant.objects.filter(name="ocm").delete()

        print("Finished deleting test data")
    
    tearDown()