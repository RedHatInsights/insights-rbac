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
"""Test the principal viewset."""

import random
from decimal import Decimal
from uuid import uuid4

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from tenant_schemas.utils import tenant_context

from api.models import User
from management.models import Principal
from tests.identity_request import IdentityRequest


class PrincipalViewsetTests(IdentityRequest):
    """Test the principal viewset."""

    def setUp(self):
        """Set up the principal viewset tests."""
        super().setUp()
        request = self.request_context['request']
        user = User(username=self.user_data['username'],
                    email=self.user_data['email'],
                    tenant=self.tenant)
        user.save()
        request.user = user

        with tenant_context(self.tenant):
            self.principal = Principal(username=self.user_data['username'],
                                       email=self.user_data['email'])
            self.principal.save()

    def tearDown(self):
        """Tear down principal viewset tests."""
        User.objects.all().delete()
        with tenant_context(self.tenant):
            Principal.objects.all().delete()

    def test_read_principal_success(self):
        """Test that we can read a principal."""
        url = reverse('principal-detail', kwargs={'username': self.principal.username})
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get('username'))
        self.assertEqual(self.principal.username, response.data.get('username'))

    def test_read_principal_invalid(self):
        """Test that reading an invalid principal returns an error."""
        url = reverse('principal-detail', kwargs={'username': uuid4()})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


    def test_read_principal_list_success(self):
        """Test that we can read a list of principals."""
        url = reverse('principal-list')
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ['meta', 'links', 'data']:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get('data'), list)
        self.assertEqual(len(response.data.get('data')), 1)

        principal = response.data.get('data')[0]
        self.assertIsNotNone(principal.get('username'))
        self.assertEqual(principal.get('username'), self.principal.username)
