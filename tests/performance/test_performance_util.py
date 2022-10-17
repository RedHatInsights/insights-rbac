import time

from base64 import b64encode
from json import dumps as json_dumps
from unittest.mock import Mock
from management.role.model import ExtRoleRelation, ExtTenant

from api.models import Tenant
from api.common import RH_IDENTITY_HEADER
from management.models import Group, Principal, Policy, Role

N_TENANTS = 1000
GROUPS_PER_TENANT = 10

N = 10  # number of roles per group, number of principals per group
PRINCIPALS_PER_TENANT = 10

PREFIX = "perf_test"

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

        if Tenant.objects.filter(tenant_name=f"{PREFIX}_acct{account}").exists():
            t = Tenant.objects.get(tenant_name=f"{PREFIX}_acct{account}")
        else:
            t = Tenant.objects.create(
                org_id=i,
                account_id=account,
                tenant_name=f"{PREFIX}_acct{account}",
            )
            t.ready = True
            t.save()

        return t

    # create 2k tenants locally (so 2k different orgs)
    for i in range(N_TENANTS):
        tenants.append(create_tenant(i))

    def create_principal(tenant, i, j):
        username = f"{PREFIX}_principal_{i}_{j}"
        if Principal.objects.filter(username=username).exists():
            Principal.objects.get(username=username)
        else:
            Principal.objects.create(
                username=username,
                tenant=tenant,
            )

    # for each org, create 10 principals
    for i in range(N_TENANTS):
        for j in range(PRINCIPALS_PER_TENANT):
            create_principal(tenants[i], i, j)

    def create_group(tenant, i, j):
        name = f"{PREFIX}_group_{i}_{j}"
        group = None
        if Group.objects.filter(name=name).exists():
            group = Group.objects.get(name=name)
        else:
            group = Group.objects.create(
                name=name,
                tenant=tenant,
            )

        name = f"{PREFIX}_policy_{i}_{j}"
        policy = None
        if Policy.objects.filter(name=name).exists():
            policy = Policy.objects.get(name=name)
        else:
            policy = Policy.objects.create(
                name=name,
                tenant=tenant,
            )

        # for each group, add "n" number of roles (should be OCM roles, so those with an external tenant)
        for k in range(N):
            name = f"{PREFIX}_role_{i}_{j}_{k}"
            role = None
            if Role.objects.filter(name=name).exists():
                role = Role.objects.get(name=name)
            else:
                role = Role.objects.create(
                    name=name,
                    tenant=tenant,
                )

                ExtRoleRelation.objects.create(
                    ext_id=f"{PREFIX}_r_r{i}_{j}_{k}",
                    ext_tenant=ext_tenant,
                    role=role,
                )

            policy.roles.add(role)

        policy.save()
        group.policies.add(policy)

        # for each group, assign "n" number of principals to the group
        for k in range(N):
            group.principals.add(Principal.objects.get(username=f"{PREFIX}_principal_{i}_{k}"))

        group.save()

    for i in range(N_TENANTS):
        for j in range(GROUPS_PER_TENANT):
            create_group(tenants[i], i, j)

    print("Finished setting up test data")


def tearDown():
    """Delete the test data."""
    print("Deleting test data...")

    Principal.objects.filter(username__regex=r"^perf_test_principal_.+").delete()
    Group.objects.filter(name__regex=r"^perf_test_group_0_0").delete()
    Policy.objects.filter(name__regex=r"^perf_test_policy_.+").delete()
    Role.objects.filter(name__regex=r"^perf_test_role_.+").delete()
    ExtRoleRelation.objects.filter(ext_id__regex=r"^perf_test_r_r_.+").delete()
    Tenant.objects.filter(tenant_name__regex=r"^perf_test_acct.+").delete()

    print("Finished deleting test data")


# ------------------------
# Identity builder helpers
# ------------------------
def build_identity():
    """Build identity."""
    identity = {
        "identity": {
            "account_number": "10001",
            "org_id": "11111",
            "user": {
                "username": "user_dev",
                "email": "user_dev@foo.com",
                "is_org_admin": True,
                "is_internal": True,
                "user_id": "51736777",
            },
        }
    }
    identity["identity"]["type"] = "Associate"
    identity["identity"]["associate"] = identity.get("identity").get("user")
    identity["identity"]["user"]["is_internal"] = True

    json_identity = json_dumps(identity)
    mock_header = b64encode(json_identity.encode("utf-8"))
    request = Mock()
    request.META = {RH_IDENTITY_HEADER: mock_header}
    request.scope = {}
    request_context = {"request": request}

    return request_context["request"]


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
    print("Number of requests: {}".format(num_requests))
    print("---------------------------\n")

    return request_time, average


def write_to_logger(logger, name, url, num_requests, request_time, average):
    """Write data to excel sheet."""

    logger.info(f"Test: {name}")
    logger.info(f"URL: {url}")
    logger.info(f"Number of requests: {num_requests}")
    logger.info(f"Total request time: {request_time} seconds")
    logger.info(f"Average time: {average} seconds")
    logger.info(f"Requests per second: {1 / average}")
