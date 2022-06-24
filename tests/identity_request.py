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
"""Test Case extension to collect common test data."""
from base64 import b64encode
from json import dumps as json_dumps
from unittest.mock import Mock

from django.db import connection
from django.conf import settings
from django.test import TestCase
from faker import Faker

from api.models import Tenant
from api.serializers import create_tenant_name
from api.common import RH_IDENTITY_HEADER


class IdentityRequest(TestCase):
    """Parent Class for IAM test cases."""

    fake = Faker()

    @classmethod
    def setUpClass(cls):
        """Set up each test class."""
        super().setUpClass()
        cls.customer_data = cls._create_customer_data()
        cls.user_data = cls._create_user_data()
        cls.request_context = cls._create_request_context(cls.customer_data, cls.user_data)
        cls.tenant_name = cls.customer_data.get("tenant_name")
        cls.tenant = Tenant(
            tenant_name=cls.tenant_name,
            account_id=cls.customer_data["account_id"],
            org_id=cls.customer_data["org_id"],
            ready=True,
        )
        cls.tenant.save()
        cls.headers = cls.request_context["request"].META

    @classmethod
    def tearDownClass(cls):
        """Tear down the class."""
        cls.tenant.delete()
        super().tearDownClass()

    @classmethod
    def _create_customer_data(cls):
        """Create customer data."""
        if settings.AUTHENTICATE_WITH_ORG_ID:
            account = ""
        else:
            account = cls.fake.ean8()
        tenant = f"acct{account}"
        org_id = cls.fake.ean8()
        customer = {"account_id": account, "tenant_name": tenant, "org_id": org_id}
        return customer

    @classmethod
    def _create_user_data(cls):
        """Create user data."""
        user_data = {"username": cls.fake.user_name(), "email": cls.fake.email()}
        return user_data

    @classmethod
    def _create_customer(cls, account, create_tenant=False, org_id=None):
        """Create a customer.

        Args:
            account (str): The account identifier

        Returns:
            (Customer) The created customer

        """
        tenant_name = create_tenant_name(account)
        tenant = None
        if create_tenant:
            tenant = Tenant(tenant_name=tenant_name, account_id=account, org_id=org_id)
            tenant.save()
        return tenant

    @classmethod
    def _create_request_context(
        cls,
        customer_data,
        user_data,
        create_customer=True,
        create_tenant=False,
        is_org_admin=True,
        is_internal=False,
        cross_account=False,
    ):
        """Create the request context for a user."""
        customer = customer_data
        account = customer.get("account_id")
        org_id = customer.get("org_id", None)
        if create_customer:
            cls.customer = cls._create_customer(account, create_tenant=create_tenant, org_id=org_id)

        identity = cls._build_identity(user_data, account, org_id, is_org_admin, is_internal)
        if cross_account:
            identity["identity"]["internal"] = {"cross_access": True}
        json_identity = json_dumps(identity)
        mock_header = b64encode(json_identity.encode("utf-8"))
        request = Mock()
        request.META = {RH_IDENTITY_HEADER: mock_header}
        request.scope = {}
        request_context = {"request": request}
        return request_context

    @classmethod
    def _build_identity(cls, user_data, account, org_id, is_org_admin, is_internal):
        identity = {"identity": {"account_number": account, "org_id": org_id}}
        if user_data is not None:
            identity["identity"]["user"] = {
                "username": user_data.get("username"),
                "email": user_data.get("email"),
                "is_org_admin": is_org_admin,
                "user_id": "1111111",
            }

        if is_internal:
            identity["identity"]["type"] = "Associate"
            identity["identity"]["associate"] = identity.get("identity").get("user")
            identity["identity"]["user"]["is_internal"] = True
        else:
            identity["identity"]["type"] = "User"

        return identity
