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
"""Test the access view."""

import random
from decimal import Decimal
from uuid import uuid4

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from tenant_schemas.utils import tenant_context

from api.models import User
from management.models import Group, Principal, Policy, Role
from tests.identity_request import IdentityRequest


class AccessViewTests(IdentityRequest):
    """Test the access view."""

    def setUp(self):
        """Set up the access view tests."""
        super().setUp()
        request = self.request_context['request']
        user = User(username=self.user_data['username'],
                    email=self.user_data['email'],
                    tenant=self.tenant)
        user.save()
        request.user = user

        self.access_data = {
            'permission': 'app:*:*',
            'resourceDefinition': [
                {
                    'attributeFilter': {
                        'key': 'key1',
                        'operation': 'equal',
                        'value': 'value1'
                    }
                }
            ]
        }
        with tenant_context(self.tenant):
            self.principal = Principal(username=self.user_data['username'],
                                       email=self.user_data['email'])
            self.principal.save()
            self.group = Group(name='groupA')
            self.group.save()
            self.group.principals.add(self.principal)
            self.group.save()

    def tearDown(self):
        """Tear down access view tests."""
        User.objects.all().delete()
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Principal.objects.all().delete()
            Role.objects.all().delete()
            Policy.objects.all().delete()

    def create_role(self, role_name, in_access_data=None):
        """Create a role."""
        access_data = self.access_data
        if in_access_data:
            access_data = in_access_data
        test_data = {
            'name': role_name,
            'access': [access_data]
        }

        # create a role
        url = reverse('role-list')
        client = APIClient()
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        return response

    def create_policy(self, policy_name, group, roles, status=status.HTTP_201_CREATED):
        """Create a policy."""
        # create a policy
        test_data = {
            'name': policy_name,
            'group': group,
            'roles': roles
        }
        url = reverse('policy-list')
        client = APIClient()
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status)
        return response

    def test_get_access_success(self):
        """Test that we can obtain the expected access."""
        role_name = 'roleA'
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        role_uuid = response.data.get('uuid')
        policy_name = 'policyA'
        response = self.create_policy(policy_name, self.group.uuid, [role_uuid])

        # test that we can retrieve the principal access
        url = '{}?application={}&username={}'.format(reverse('access'),
                                                     'app',
                                                     self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get('access'))
        self.assertIsInstance(response.data.get('access'), list)
        self.assertEqual(len(response.data.get('access')), 1)
        self.assertEqual(self.access_data, response.data.get('access')[0])

    def test_missing_query_params(self):
        """Test that we get expected failure when missing required query params."""
        url = '{}?application={}'.format(reverse('access'), 'app')
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_invalid_username(self):
        """Test that we get expected failure when missing required query params."""
        url = '{}?application={}&username={}'.format(reverse('access'),
                                                     'app',
                                                     uuid4())
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
