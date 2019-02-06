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
"""Test the role viewset."""

import random
from decimal import Decimal
from uuid import uuid4

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from tenant_schemas.utils import tenant_context

from api.models import User
from management.models import Group, Principal, Role
from tests.identity_request import IdentityRequest


class RoleViewsetTests(IdentityRequest):
    """Test the role viewset."""

    def setUp(self):
        """Set up the role viewset tests."""
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
            self.group = Group(name='groupA')
            self.group.save()
            self.group.principals.add(self.principal)
            self.group.save()

    def tearDown(self):
        """Tear down role viewset tests."""
        User.objects.all().delete()
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Principal.objects.all().delete()
            Role.objects.all().delete()

    def create_role(self, role_name, in_access_data=None):
        """Create a role."""
        access_data = {
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

    def test_create_role_success(self):
        """Test that we can create a role."""
        role_name = 'roleA'
        access_data = {
            'permission': 'app:*:*',
            'resourceDefinition': [
                {
                    'attributeFilter': {
                          'key': 'keyA',
                          'operation': 'equal',
                        'value': 'valueA'
                    }
                }
            ]
        }
        response = self.create_role(role_name, access_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # test that we can retrieve the role
        url = reverse('role-detail', kwargs={'uuid': response.data.get('uuid')})
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertIsNotNone(response.data.get('uuid'))
        self.assertIsNotNone(response.data.get('name'))
        self.assertEqual(role_name, response.data.get('name'))
        self.assertIsInstance(response.data.get('access'), list)
        self.assertEqual(access_data, response.data.get('access')[0])

    def test_create_role_invalid(self):
        """Test that creating an invalid role returns an error."""
        test_data = {}
        url = reverse('role-list')
        client = APIClient()
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_role_invalid(self):
        """Test that reading an invalid role returns an error."""
        url = reverse('role-detail', kwargs={'uuid': uuid4()})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_read_role_list_success(self):
        """Test that we can read a list of roles."""
        role_name = 'roleA'
        response = self.create_role(role_name)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # list a roles
        url = reverse('role-list')
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ['meta', 'links', 'data']:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get('data'), list)
        self.assertEqual(len(response.data.get('data')), 1)

        role = response.data.get('data')[0]
        self.assertIsNotNone(role.get('name'))
        self.assertEqual(role.get('name'), role_name)

    def test_update_role_success(self):
        """Test that we can update an existing role."""
        role_name = 'roleA'
        response = self.create_role(role_name)
        updated_name = role_name + '_update'
        role_uuid = response.data.get('uuid')
        test_data = response.data
        test_data['name'] = updated_name
        del test_data['uuid']
        url = reverse('role-detail', kwargs={'uuid': role_uuid})
        client = APIClient()
        response = client.put(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIsNotNone(response.data.get('uuid'))
        self.assertEqual(updated_name, response.data.get('name'))

    def test_update_role_invalid(self):
        """Test that updating an invalid role returns an error."""
        url = reverse('role-detail', kwargs={'uuid': uuid4()})
        client = APIClient()
        response = client.put(url, {}, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_role_success(self):
        """Test that we can delete an existing role."""
        role_name = 'roleA'
        response = self.create_role(role_name)
        role_uuid = response.data.get('uuid')
        url = reverse('role-detail', kwargs={'uuid': role_uuid})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # verify the role no longer exists
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_role_invalid(self):
        """Test that deleting an invalid role returns an error."""
        url = reverse('role-detail', kwargs={'uuid': uuid4()})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
