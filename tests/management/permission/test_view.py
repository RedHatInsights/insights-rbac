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
"""Test the permission viewset."""

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from tenant_schemas.utils import tenant_context

from api.models import User
from management.models import Permission
from tests.identity_request import IdentityRequest


class PermissionViewsetTests(IdentityRequest):
    """Test the permission viewset."""

    def setUp(self):
        """Set up the permission viewset tests."""
        super().setUp()
        request = self.request_context["request"]
        user = User()
        user.username = self.user_data["username"]
        user.account = self.customer_data["account_id"]
        request.user = user

        self.display_fields = {"application", "resource_type", "verb", "permission"}

        with tenant_context(self.tenant):
            self.permissionA = Permission.objects.create(permission="rbac:roles:read")
            self.permissionB = Permission.objects.create(permission="rbac:*:*")
            self.permissionC = Permission.objects.create(permission="acme:*:*")
            self.permissionD = Permission.objects.create(permission="acme:*:write")

    def tearDown(self):
        """Tear down permission viewset tests."""
        with tenant_context(self.tenant):
            Permission.objects.all().delete()

    def test_read_permission_list_success(self):
        """Test that we can read a list of permissions."""
        url = reverse("permission-list")
        client = APIClient()
        response = client.get(url, **self.headers)

        # three parts in response: meta, links and data
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ["meta", "links", "data"]:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get("data"), list)
        self.assertEqual(len(response.data.get("data")), 4)

        for perm in response.data.get("data"):
            self.assertIsNotNone(perm.get("application"))
            self.assertIsNotNone(perm.get("resource_type"))
            self.assertIsNotNone(perm.get("verb"))
            self.assertIsNotNone(perm.get("permission"))
            self.assertEqual(self.display_fields, set(perm.keys()))

    def test_read_permission_list_application_filter(self):
        """Test that we can filter a list of permissions by application."""
        url = reverse("permission-list")
        url = f"{url}?application=rbac"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)

    def test_read_permission_list_resource_type_filter(self):
        """Test that we can filter a list of permissions by resource_type."""
        url = reverse("permission-list")
        url = f"{url}?resource_type=roles"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0].get("permission"), self.permissionA.permission)

    def test_read_permission_list_verb_filter(self):
        """Test that we can filter a list of permissions by verb."""
        url = reverse("permission-list")
        url = f"{url}?verb=read"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0].get("permission"), self.permissionA.permission)

    def test_read_permission_list_permission_filter(self):
        """Test that we can filter a list of permissions by permission."""
        url = reverse("permission-list")
        url = f"{url}?permission=rbac:*:*"
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 1)
        self.assertEqual(response.data.get("data")[0].get("permission"), self.permissionB.permission)

    def test_get_list_is_the_only_valid_method(self):
        """Test GET on /permissions/ is the only valid method."""
        url = reverse("permission-list")
        client = APIClient()
        response = client.post(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        response = client.put(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_filters_multiple_appliation_values(self):
        """Test that we can filter permissions with multiple application values."""
        with tenant_context(self.tenant):
            expected_permissions = list(Permission.objects.values_list("permission", flat=True))

        url = reverse("permission-list")
        url = f"{url}?application=rbac,acme"
        client = APIClient()
        response = client.get(url, **self.headers)
        response_permissions = [p.get("permission") for p in response.data.get("data")]

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 4)
        self.assertCountEqual(expected_permissions, response_permissions)

    def test_filters_multiple_resource_type_values(self):
        """Test that we can filter permissions with multiple resource_type values."""
        with tenant_context(self.tenant):
            expected_permissions = list(Permission.objects.values_list("permission", flat=True))

        url = reverse("permission-list")
        url = f"{url}?resource_type=roles,*"
        client = APIClient()
        response = client.get(url, **self.headers)
        response_permissions = [p.get("permission") for p in response.data.get("data")]

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 4)
        self.assertCountEqual(expected_permissions, response_permissions)

    def test_filters_multiple_verb_values(self):
        """Test that we can filter permissions with multiple verb values."""
        with tenant_context(self.tenant):
            expected_permissions = list(
                Permission.objects.values_list("permission", flat=True).filter(verb__in=["read", "write"])
            )

        url = reverse("permission-list")
        url = f"{url}?verb=read,write"
        client = APIClient()
        response = client.get(url, **self.headers)
        response_permissions = [p.get("permission") for p in response.data.get("data")]

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data.get("data")), 2)
        self.assertCountEqual(expected_permissions, response_permissions)


class PermissionViewsetTestsNonAdmin(IdentityRequest):
    """Test the permission viewset."""

    def setUp(self):
        """Set up the permission viewset tests."""
        super().setUp()

        self.user_data = self._create_user_data()
        self.customer = self._create_customer_data()
        self.request_context = self._create_request_context(self.customer, self.user_data, is_org_admin=False)

        request = self.request_context["request"]
        self.headers = request.META

        with tenant_context(self.tenant):
            self.permission = Permission.objects.create(permission="rbac:roles:read")
            self.permission.save()

    def tearDown(self):
        """Tear down permission viewset tests."""
        with tenant_context(self.tenant):
            Permission.objects.all().delete()

    def test_read_permission_list_fail(self):
        """Test that we can not read a list of permissions as a non-admin."""
        url = reverse("permission-list")
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
