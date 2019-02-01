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
"""Test the group viewset."""

import random
from decimal import Decimal
from uuid import uuid4

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from tenant_schemas.utils import tenant_context

from api.models import User
from management.models import Group, Principal
from tests.identity_request import IdentityRequest


class GroupViewsetTests(IdentityRequest):
    """Test the group viewset."""

    def setUp(self):
        """Set up the group viewset tests."""
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
        """Tear down group viewset tests."""
        User.objects.all().delete()
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Principal.objects.all().delete()

    def test_create_group_success(self):
        """Test that we can create a group."""
        group_name = 'groupB'
        test_data = {
            'name': group_name
        }

        # create a group
        url = reverse('group-list')
        client = APIClient()
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # test that we can retrieve the group
        url = reverse('group-detail', kwargs={'uuid': response.data.get('uuid')})
        response = client.get(url, **self.headers)

        self.assertIsNotNone(response.data.get('uuid'))
        self.assertIsNotNone(response.data.get('name'))
        self.assertEqual(group_name, response.data.get('name'))

    def test_create_group_invalid(self):
        """Test that creating an invalid group returns an error."""
        test_data = {}
        url = reverse('group-list')
        client = APIClient()
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_read_group_success(self):
        """Test that we can read a group."""
        url = reverse('group-detail', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get('name'))
        self.assertEqual(self.group.name, response.data.get('name'))

    def test_read_group_invalid(self):
        """Test that reading an invalid group returns an error."""
        url = reverse('group-detail', kwargs={'uuid': uuid4()})
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_read_group_list_success(self):
        """Test that we can read a list of groups."""
        url = reverse('group-list')
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for keyname in ['count', 'next', 'previous', 'results']:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get('results'), list)
        self.assertEqual(len(response.data.get('results')), 1)

        group = response.data.get('results')[0]
        self.assertIsNotNone(group.get('name'))
        self.assertEqual(group.get('name'), self.group.name)

    def test_update_group_success(self):
        """Test that we can update an existing group."""
        group = Group.objects.first()
        updated_name = group.name + '_update'
        test_data = {'name': updated_name}
        url = reverse('group-detail', kwargs={'uuid': group.uuid})
        client = APIClient()
        response = client.put(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertIsNotNone(response.data.get('uuid'))
        self.assertEqual(updated_name, response.data.get('name'))

    def test_update_group_invalid(self):
        """Test that updating an invalid group returns an error."""
        url = reverse('group-detail', kwargs={'uuid': uuid4()})
        client = APIClient()
        response = client.put(url, {}, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_group_success(self):
        """Test that we can delete an existing group."""
        group = Group.objects.first()
        url = reverse('group-detail', kwargs={'uuid': group.uuid})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        # verify the group no longer exists
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_group_invalid(self):
        """Test that deleting an invalid group returns an error."""
        url = reverse('group-detail', kwargs={'uuid': uuid4()})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_group_principals_invalid_method(self):
        """Test that using an unsupported REST method returns an error."""
        url = reverse('group-principals', kwargs={'uuid': uuid4()})
        client = APIClient()
        response = client.put(url, {}, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_add_group_principals_success(self):
        """Test that adding a principal to a group returns successfully."""
        url = reverse('group-principals', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        new_username = uuid4()
        test_data = [{'username': self.principal.username}, {'username': new_username}]
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_remove_group_principals_success(self):
        """Test that removing a principal to a group returns successfully."""
        url = reverse('group-principals', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        new_username = uuid4()
        test_data = [{'username': self.principal.username}, {'username': new_username}]
        response = client.delete(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_group_principals_invalid(self):
        """Test that removing a principal returns an error with invalid data format."""
        url = reverse('group-principals', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        test_data = {'username': self.principal.username}
        response = client.delete(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
