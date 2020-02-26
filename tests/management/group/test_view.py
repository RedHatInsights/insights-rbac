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
from unittest.mock import patch
from uuid import uuid4

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from tenant_schemas.utils import tenant_context

from api.models import User
from management.models import Group, Principal, Policy, Role
from tests.identity_request import IdentityRequest


class GroupViewsetTests(IdentityRequest):
    """Test the group viewset."""

    def setUp(self):
        """Set up the group viewset tests."""
        super().setUp()
        request = self.request_context['request']
        user = User(username=self.user_data['username'],
                    tenant=self.tenant)
        user.save()
        request.user = user
        self.dummy_role_id = uuid4()

        with tenant_context(self.tenant):
            self.principal = Principal(username=self.user_data['username'])
            self.principal.save()
            self.group = Group(name='groupA')
            self.group.save()
            self.role = Role.objects.create(name='roleA', description='A role for a group.')
            self.policy = Policy.objects.create(name='policyA', group=self.group)
            self.policy.roles.add(self.role)
            self.policy.save()
            self.group.policies.add(self.policy)
            self.group.principals.add(self.principal)
            self.group.save()

            self.defGroup = Group(name='groupDef', platform_default=True, system=True)
            self.defGroup.save()
            self.defGroup.principals.add(self.principal)
            self.defGroup.save()

            self.emptyGroup = Group(name='groupE')
            self.emptyGroup.save()

            self.groupB = Group.objects.create(name='groupB')
            self.groupB.principals.add(self.principal)
            self.policyB = Policy.objects.create(name='policyB', group=self.groupB)
            self.roleB = Role.objects.create(name='roleB')
            self.policyB.roles.add(self.roleB)
            self.policyB.save()

            # role that's not assigned to principal
            self.roleOrphan = Role.objects.create(name='roleOrphan')


    def tearDown(self):
        """Tear down group viewset tests."""
        User.objects.all().delete()
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Principal.objects.all().delete()
            Role.objects.all().delete()
            Policy.objects.all().delete()

    @patch('management.principal.proxy.PrincipalProxy.request_filtered_principals',
           return_value={'status_code': 200, 'data': []})
    def test_create_group_success(self, mock_request):
        """Test that we can create a group."""
        group_name = 'groupC'
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

    def test_create_default_group(self):
        """Test that system groups can be created."""
        group_name = 'groupDef'


        # test group retrieval
        client = APIClient()
        url = reverse('group-detail', kwargs={'uuid': self.defGroup.uuid})
        response = client.get(url, **self.headers)

        self.assertIsNotNone(response.data.get('uuid'))
        self.assertIsNotNone(response.data.get('name'))
        self.assertTrue(response.data.get('platform_default'))
        self.assertEqual(group_name, response.data.get('name'))

    def test_create_group_invalid(self):
        """Test that creating an invalid group returns an error."""
        test_data = {}
        url = reverse('group-list')
        client = APIClient()
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('management.principal.proxy.PrincipalProxy.request_filtered_principals',
           return_value={'status_code': 200, 'data': []})
    def test_read_group_success(self, mock_request):
        """Test that we can read a group."""
        url = reverse('group-detail', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get('name'))
        self.assertEqual(self.group.name, response.data.get('name'))
        self.assertEqual(len(response.data.get('roles')), 1)
        self.assertEqual(response.data.get('roles')[0]['uuid'], str(self.role.uuid))

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
        for keyname in ['meta', 'links', 'data']:
            self.assertIn(keyname, response.data)
        self.assertIsInstance(response.data.get('data'), list)
        self.assertEqual(len(response.data.get('data')), 4)

        group = response.data.get('data')[0]
        self.assertIsNotNone(group.get('name'))
        self.assertEqual(group.get('name'), self.group.name)

    @patch('management.principal.proxy.PrincipalProxy.request_filtered_principals',
           return_value={'status_code': 200, 'data': []})
    def test_update_group_success(self, mock_request):
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

    def test_update_default_group(self):
        """Test that platform_default groups are protected from updates"""
        url = reverse('group-detail', kwargs={'uuid': self.defGroup.uuid})
        test_data = {'name': self.defGroup.name + '_updated'}
        client = APIClient()
        response = client.put(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

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

    def test_delete_default_group(self):
        """Test that platform_default groups are protected from deletion"""
        url = reverse('group-detail', kwargs={'uuid': self.defGroup.uuid})
        client = APIClient()
        response = client.delete(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

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

    @patch('management.principal.proxy.PrincipalProxy.request_filtered_principals',
           return_value={'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR, 'errors': [{
               'detail': 'Unexpected error.',
               'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
               'source': 'principals'
          }]})
    def test_add_group_principals_failure(self, mock_request):
        """Test that adding a principal to a group returns has proper response when it is failed."""
        url = reverse('group-principals', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        new_username = uuid4()
        test_data = {'principals': [{'username': self.principal.username}, {'username': new_username}]}
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data[0]['detail'], 'Unexpected error.')
        self.assertEqual(response.data[0]['status'], 500)
        self.assertEqual(response.data[0]['source'], 'principals')

    @patch('management.principal.proxy.PrincipalProxy.request_filtered_principals',
           return_value={'status_code': 200, 'data': []})
    def test_add_group_principals_success(self, mock_request):
        """Test that adding a principal to a group returns successfully."""
        url = reverse('group-principals', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        new_username = uuid4()
        test_data = {'principals': [{'username': self.principal.username}, {'username': new_username}]}
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        url = reverse('group-list')
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('meta').get('count'), 4)
        self.assertEqual(response.data.get('data')[0].get('principalCount'), 1)
        self.assertEqual(response.data.get('data')[0].get('policyCount'), None)
        self.assertEqual(response.data.get('data')[0].get('roleCount'), 1)

    @patch('management.principal.proxy.PrincipalProxy.request_filtered_principals',
           return_value={'status_code': 200, 'data': []})
    def test_get_group_principals_empty(self, mock_request):
        """Test that getting principals from an empty group returns successfully."""
        client = APIClient()
        url = reverse('group-principals', kwargs={'uuid': self.emptyGroup.uuid})
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('meta').get('count'), 0)
        self.assertEqual(response.data.get('data'), [])

    @patch('management.principal.proxy.PrincipalProxy.request_filtered_principals',
           return_value={'status_code': 200, 'data': []})
    def test_get_group_principals_nonempty(self, mock_request):
        """Test that getting principals from a nonempty group returns successfully."""
        mock_request.return_value['data'] = [{'username': self.principal.username}]
        client = APIClient()
        url = reverse('group-principals', kwargs={'uuid': self.group.uuid})
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('meta').get('count'), 1)
        self.assertEqual(response.data.get('data')[0].get('username'), self.principal.username)

    def test_remove_group_principals_success(self):
        """Test that removing a principal to a group returns successfully."""
        url = reverse('group-principals', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        url = '{}?usernames={}'.format(url, self.principal.username)
        response = client.delete(url, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_group_principals_invalid(self):
        """Test that removing a principal returns an error with invalid data format."""
        url = reverse('group-principals', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        response = client.delete(url, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('management.principal.proxy.PrincipalProxy.request_filtered_principals',
           return_value={'status_code': 200, 'data': []})
    def test_get_group_by_username(self, mock_request):
        """Test that getting groups for a principalreturns successfully."""
        url = reverse('group-principals', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        new_username = uuid4()
        test_data = {'principals': [{'username': self.principal.username}, {'username': new_username}]}
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        url = reverse('group-list')
        url = '{}?username={}'.format(url, self.principal.username)
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get('meta').get('count'), 3)

        url = reverse('group-list')
        url = '{}?username={}'.format(url, uuid4())
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.data.get('meta').get('count'), 1)

    def test_get_group_roles_success(self):
        """Test that getting roles for a group returns successfully."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get('data')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get('uuid'), str(self.role.uuid))
        self.assertEqual(roles[0].get('name'), self.role.name)
        self.assertEqual(roles[0].get('description'), self.role.description)

    def test_get_group_roles_with_exclude_false_success(self):
        """Test that getting roles with 'exclude=false' for a group works as default."""
        url = "%s?exclude=FALSE" % (reverse('group-roles', kwargs={'uuid': self.group.uuid}))
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get('data')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get('uuid'), str(self.role.uuid))
        self.assertEqual(roles[0].get('name'), self.role.name)
        self.assertEqual(roles[0].get('description'), self.role.description)

    def test_get_group_roles_with_exclude_success(self):
        """Test that getting roles with 'exclude=True' for a group returns successfully."""
        url = "%s?exclude=True" % (reverse('group-roles', kwargs={'uuid': self.group.uuid}))
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get('data')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 2)
        self.assertTrue(role.uuid in [self.roleB.uuid, self.roleOrphan.uuid] for role in roles)

    def test_get_group_roles_with_exclude_in_principal_scope_success(self):
        """Test that getting roles with 'exclude=True' for a group in principal scope."""
        url = "%s?exclude=True&scope=principal" % (reverse('group-roles', kwargs={'uuid': self.group.uuid}))
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get('data')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get('uuid'), str(self.roleB.uuid))
        self.assertEqual(roles[0].get('name'), self.roleB.name)
        self.assertEqual(roles[0].get('description'), self.roleB.description)

    def test_exclude_input_invalid(self):
        """Test that getting roles with 'exclude=' for a group returns failed validation."""
        url = "%s?exclude=sth" % (reverse('group-roles', kwargs={'uuid': self.group.uuid}))
        client = APIClient()
        response = client.get(url, **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_role_name_filter_for_group_roles_no_match(self):
        """Test role_name filter for getting roles for a group."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        url = '{}?role_name=test'.format(url)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get('data')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 0)

    def test_role_name_filter_for_group_roles_match(self):
        """Test role_name filter for getting roles for a group."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        url = '{}?role_name={}'.format(url, self.role.name)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get('data')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get('uuid'), str(self.role.uuid))

    def test_role_description_filter_for_group_roles_no_match(self):
        """Test role_description filter for getting roles for a group."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        url = '{}?role_description=test'.format(url)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get('data')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 0)

    def test_role_description_filter_for_group_roles_match(self):
        """Test role_description filter for getting roles for a group."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        url = '{}?role_description={}'.format(url, self.role.description)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get('data')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get('uuid'), str(self.role.uuid))

    def test_all_role_filters_for_group_roles_no_match(self):
        """Test role filters for getting roles for a group."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        url = '{}?role_description=test&role_name=test'.format(url)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get('data')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 0)

    def test_all_role_filters_for_group_roles_match(self):
        """Test role filters for getting roles for a group."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        url = '{}?role_description={}&role_name={}'.format(url, self.role.description, self.role.name)
        client = APIClient()
        response = client.get(url, **self.headers)
        roles = response.data.get('data')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].get('uuid'), str(self.role.uuid))

    def test_add_group_roles_system_policy_create_success(self):
        """Test that adding a role to a group without a system policy returns successfully."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        test_data = {'roles': [self.roleB.uuid, self.dummy_role_id]}

        self.assertCountEqual([self.role], list(self.group.roles()))
        self.assertCountEqual([self.policy], list(self.group.policies.all()))

        response = client.post(url, test_data, format='json', **self.headers)

        roles = response.data.get('data')
        system_policies = Policy.objects.filter(system=True)
        system_policy = system_policies.get(group=self.group)

        self.assertEqual(len(system_policies), 1)
        self.assertCountEqual([system_policy, self.policy], list(self.group.policies.all()))
        self.assertCountEqual([self.roleB], list(system_policy.roles.all()))
        self.assertCountEqual([self.role], list(self.policy.roles.all()))
        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))
        self.assertEqual(len(roles), 2)
        self.assertEqual(roles[0].get('uuid'), str(self.role.uuid))
        self.assertEqual(roles[0].get('name'), self.role.name)
        self.assertEqual(roles[0].get('description'), self.role.description)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_system_flag_update_on_add(self):
        """Test that adding a role to a platform_default group flips the system flag."""
        url = reverse('group-roles', kwargs={'uuid': self.defGroup.uuid})
        client = APIClient()
        test_data = {'roles': [self.roleB.uuid, self.dummy_role_id]}

        self.assertTrue(self.defGroup.system)
        response = client.post(url, test_data, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.defGroup.refresh_from_db()
        self.assertEqual(self.defGroup.name, "Custom default user access")
        self.assertFalse(self.defGroup.system)

    def test_system_flag_update_on_remove(self):
        """Test that removing a role from a platform_default group flips the system flag."""
        url = reverse('group-roles', kwargs={'uuid': self.defGroup.uuid})
        client = APIClient()
        url = '{}?roles={}'.format(url, self.roleB.uuid)

        self.policy.roles.add(self.roleB)
        self.policy.save()

        self.assertTrue(self.defGroup.system)
        response = client.delete(url, format='json', **self.headers)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.defGroup.refresh_from_db()
        self.assertEqual(self.defGroup.name, "Custom default user access")
        self.assertFalse(self.defGroup.system)

    def test_add_group_roles_system_policy_create_new_group_success(self):
        """Test that adding a role to a group without a system policy returns successfully."""
        group_url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        groupB_url = reverse('group-roles', kwargs={'uuid': self.groupB.uuid})
        client = APIClient()
        test_data = {'roles': [self.roleB.uuid]}

        response = client.post(group_url, test_data, format='json', **self.headers)
        responseB = client.post(groupB_url, test_data, format='json', **self.headers)

        system_policies = Policy.objects.filter(system=True)
        system_policy = system_policies.get(group=self.group)
        system_policyB = system_policies.get(group=self.groupB)

        self.assertEqual(len(system_policies), 2)
        self.assertCountEqual([self.roleB], list(system_policy.roles.all()))
        self.assertCountEqual([self.roleB], list(system_policyB.roles.all()))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(responseB.status_code, status.HTTP_200_OK)

    def test_add_group_roles_system_policy_get_success(self):
        """Test that adding a role to a group with existing system policy returns successfully."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        test_data = {'roles': [self.roleB.uuid, self.dummy_role_id]}
        system_policy_name = 'System Policy for Group {}'.format(self.group.uuid)
        system_policy = Policy.objects.create(system=True, group=self.group, name=system_policy_name)

        self.assertCountEqual([self.role], list(self.group.roles()))
        self.assertCountEqual([system_policy, self.policy], list(self.group.policies.all()))

        response = client.post(url, test_data, format='json', **self.headers)

        roles = response.data.get('data')
        system_policies = Policy.objects.filter(system=True, group=self.group)
        system_policy = system_policies.first()

        self.assertEqual(len(system_policies), 1)
        self.assertCountEqual([system_policy, self.policy], list(self.group.policies.all()))
        self.assertCountEqual([self.roleB], list(system_policy.roles.all()))
        self.assertCountEqual([self.role], list(self.policy.roles.all()))
        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))
        self.assertEqual(len(roles), 2)
        self.assertEqual(roles[0].get('uuid'), str(self.role.uuid))
        self.assertEqual(roles[0].get('name'), self.role.name)
        self.assertEqual(roles[0].get('description'), self.role.description)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_add_group_multiple_roles_success(self):
        """Test that adding multiple roles to a group returns successfully."""
        with tenant_context(self.tenant):
            groupC = Group.objects.create(name='groupC')
            url = reverse('group-roles', kwargs={'uuid': groupC.uuid})
            client = APIClient()
            test_data = {'roles': [self.role.uuid, self.roleB.uuid]}

            self.assertCountEqual([], list(groupC.roles()))

            response = client.post(url, test_data, format='json', **self.headers)

            self.assertCountEqual([self.role, self.roleB], list(groupC.roles()))
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_add_group_multiple_roles_invalid(self):
        """Test that adding invalid roles to a group fails the request and does not add any."""
        with tenant_context(self.tenant):
            groupC = Group.objects.create(name='groupC')
            url = reverse('group-roles', kwargs={'uuid': groupC.uuid})
            client = APIClient()
            test_data = {'roles': ['abc123', self.roleB.uuid]}

            self.assertCountEqual([], list(groupC.roles()))

            response = client.post(url, test_data, format='json', **self.headers)

            self.assertCountEqual([], list(groupC.roles()))
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_add_group_multiple_roles_not_found_success(self):
        """Test that adding roles to a group skips ids not found, and returns success."""
        with tenant_context(self.tenant):
            groupC = Group.objects.create(name='groupC')
            url = reverse('group-roles', kwargs={'uuid': groupC.uuid})
            client = APIClient()
            test_data = {'roles': [self.dummy_role_id, self.roleB.uuid]}

            self.assertCountEqual([], list(groupC.roles()))

            response = client.post(url, test_data, format='json', **self.headers)

            self.assertCountEqual([self.roleB], list(groupC.roles()))
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_remove_group_roles_success(self):
        """Test that removing a role from a group returns successfully."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        url = '{}?roles={}'.format(url, self.role.uuid)

        self.policyB.roles.add(self.role)
        self.policyB.save()
        self.assertCountEqual([self.role], list(self.group.roles()))

        response = client.delete(url, format='json', **self.headers)

        self.assertCountEqual([], list(self.group.roles()))
        self.assertCountEqual([self.role, self.roleB], list(self.groupB.roles()))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_group_multiple_roles_success(self):
        """Test that removing multiple roles from a group returns successfully."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        url = '{}?roles={},{}'.format(url, self.role.uuid, self.roleB.uuid)

        self.policy.roles.add(self.roleB)
        self.policy.save()
        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))

        response = client.delete(url, format='json', **self.headers)

        self.assertCountEqual([], list(self.group.roles()))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_group_multiple_roles_invalid(self):
        """Test that removing invalid roles from a group fails the request and does not remove any."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        url = '{}?roles={},{}'.format(url, 'abc123', self.roleB.uuid)

        self.policy.roles.add(self.roleB)
        self.policy.save()
        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))

        response = client.delete(url, format='json', **self.headers)

        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_remove_group_multiple_roles_not_found_success(self):
        """Test that removing roles from a group skips ids not found, and returns success."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        client = APIClient()
        url = '{}?roles={},{},{}'.format(url, self.role.uuid, self.roleB.uuid, self.dummy_role_id)

        self.policy.roles.add(self.roleB)
        self.policy.save()
        self.assertCountEqual([self.role, self.roleB], list(self.group.roles()))

        response = client.delete(url, format='json', **self.headers)

        self.assertCountEqual([], list(self.group.roles()))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_remove_group_roles_invalid(self):
        """Test that removing a role returns an error with invalid data format."""
        url = reverse('group-roles', kwargs={'uuid': self.group.uuid})
        client = APIClient()

        response = client.delete(url, format='json', **self.headers)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_admin_RonR(self):
        """Test that a admin user can group RBAC resources"""
        url = '{}?application={}'.format(reverse('group-list'), 'rbac')
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class GroupViewNonAdminTests(IdentityRequest):
    """Test the group view for nonadmin user."""

    def setUp(self):
        """Set up the group view nonadmin tests."""
        super().setUp()

        self.user_data = self._create_user_data()
        self.customer = self._create_customer_data()
        self.request_context = self._create_request_context(self.customer,
                                                            self.user_data,
                                                            is_org_admin=False)


        request = self.request_context['request']
        self.headers = request.META
        self.access_data = {
            'permission': 'app:*:*',
            'resourceDefinitions': [
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
            self.principal = Principal(username=self.user_data['username'])
            self.principal.save()
            self.admin_principal = Principal(username="user_admin")
            self.admin_principal.save()
            self.group = Group(name='groupA')
            self.group.save()
            self.group.principals.add(self.principal)
            self.group.save()

    def tearDown(self):
        """Tear down group view tests."""
        User.objects.all().delete()
        with tenant_context(self.tenant):
            Group.objects.all().delete()
            Principal.objects.all().delete()
            Role.objects.all().delete()
            Policy.objects.all().delete()

    def test_nonadmin_RonR(self):
        """Test that a nonadmin user can't group RBAC resources"""
        url = '{}?application={}'.format(reverse('group-list'), 'rbac')
        client = APIClient()
        response = client.get(url, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

