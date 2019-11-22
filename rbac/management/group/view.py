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

"""View for group management."""
import logging

from django.core.exceptions import ValidationError
from django.db.models.aggregates import Count
from django.utils.translation import gettext as _
from django_filters import rest_framework as filters
from management.group.model import Group
from management.group.serializer import (GroupInputSerializer,
                                         GroupPrincipalInputSerializer,
                                         GroupRoleSerializer,
                                         GroupSerializer)
from management.permissions import GroupAccessPermission
from management.policy.model import Policy
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from management.querysets import get_group_queryset
from management.role.model import Role
from rest_framework import mixins, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter
from rest_framework.response import Response


USERNAMES_KEY = 'usernames'
ROLES_KEY = 'roles'
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class GroupFilter(filters.FilterSet):
    """Filter for group."""

    name = filters.CharFilter(field_name='name', lookup_expr='icontains')
    username = filters.CharFilter(field_name='principals', lookup_expr='username__icontains')

    class Meta:
        model = Group
        fields = ['name', 'principals']


class GroupViewSet(mixins.CreateModelMixin,
                   mixins.DestroyModelMixin,
                   mixins.ListModelMixin,
                   mixins.RetrieveModelMixin,
                   mixins.UpdateModelMixin,
                   viewsets.GenericViewSet):
    """Group View.

    A viewset that provides default `create()`, `destroy`, `retrieve()`,
    and `list()` actions.

    """

    queryset = Group.objects.annotate(principalCount=Count('principals', distinct=True),
                                      policyCount=Count('policies', distinct=True))
    permission_classes = (GroupAccessPermission,)
    lookup_field = 'uuid'
    filter_backends = (filters.DjangoFilterBackend, OrderingFilter)
    filterset_class = GroupFilter
    ordering_fields = ('name', 'modified', 'principalCount', 'policyCount')
    ordering = ('name',)
    proxy = PrincipalProxy()

    def get_queryset(self):
        """Obtain queryset for requesting user based on access."""
        return get_group_queryset(self.request)

    def get_serializer_class(self):
        """Get serializer based on route."""
        if 'principals' in self.request.path:
            return GroupPrincipalInputSerializer
        if ROLES_KEY in self.request.path:
            return GroupRoleSerializer
        if self.request.method in ('POST', 'PUT'):
            return GroupInputSerializer
        if self.request.path.endswith('groups/') and self.request.method == 'GET':
            return GroupInputSerializer
        return GroupSerializer

    def create(self, request, *args, **kwargs):
        """Create a group.

        @api {post} /api/v1/groups/   Create a group
        @apiName createGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Create a Group

        @apiHeader {String} token User authorization token

        @apiParam (Request Body) {String} name Group name
        @apiParamExample {json} Request Body:
            {
                "name": "GroupA"
            }

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 201 CREATED
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA",
                "principals": []
            }
        """
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of groups for the tenant.

        @api {get} /api/v1/groups/   Obtain a list of groups
        @apiName getGroups
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Obtain a list of groups

        @apiHeader {String} token User authorization token

        @apiParam (Query) {String} name Filter by group name.
        @apiParam (Query) {Number} offset Parameter for selecting the start of data (default is 0).
        @apiParam (Query) {Number} limit Parameter for selecting the amount of data (default is 10).

        @apiSuccess {Object} meta The metadata for pagination.
        @apiSuccess {Object} links  The object containing links of results.
        @apiSuccess {Object[]} data  The array of results.

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                'meta': {
                    'count': 2
                }
                'links': {
                    'first': /api/v1/groups/?offset=0&limit=10,
                    'next': None,
                    'previous': None,
                    'last': /api/v1/groups/?offset=0&limit=10
                },
                'data': [
                                {
                                    "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                                    "name": "GroupA"
                                },
                                {
                                    "uuid": "20ecdcd0-397c-4ede-8940-f3439bf40212",
                                    "name": "GroupB"
                                }
                            ]
            }

        """
        return super().list(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a group.

        @api {get} /api/v1/groups/:uuid   Get a group
        @apiName getGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Get a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier.

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} principals Array of principals
        @apiSuccess {Array} roles Array of roles
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA",
                "principals": [
                    { "username": "jsmith" }
                ],
                "roles": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15"
                    }
                ]
            }
        """
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a group.

        @api {delete} /api/v1/groups/:uuid   Delete a group
        @apiName deleteGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Delete a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} uuid Group unique identifier

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 204 NO CONTENT
        """
        return super().destroy(request=request, args=args, kwargs=kwargs)

    def update(self, request, *args, **kwargs):
        """Update a group.

        @api {post} /api/v1/groups/:uuid   Update a group
        @apiName updateGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Update a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA"
            }
        """
        return super().update(request=request, args=args, kwargs=kwargs)

    def add_principals(self, group, principals, account):
        """Process list of principals and add them to the group."""
        users = [principal.get('username') for principal in principals]
        resp = self.proxy.request_filtered_principals(users, account, limit=len(users))
        for item in resp.get('data', []):
            username = item['username']
            try:
                principal = Principal.objects.get(username__iexact=username)
            except Principal.DoesNotExist:
                principal = Principal.objects.create(username=username)
                logger.info('Created new principal %s for account_id %s.', username, account)
            group.principals.add(principal)
        group.save()
        return group

    def remove_principals(self, group, principals, account):
        """Process list of principals and remove them from the group."""
        for username in principals:
            try:
                principal = Principal.objects.get(username__iexact=username)
            except Principal.DoesNotExist:
                logger.info('No principal %s found for account %s.', username, account)
            if principal:
                group.principals.remove(principal)
        group.save()
        return group

    @action(detail=True, methods=['post', 'delete'])
    def principals(self, request, uuid=None):
        """Add or remove principals from a group."""
        """
        @api {post} /api/v1/groups/:uuid/principals/   Add principals to a group
        @apiName addPrincipals
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Add principals to a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiParam (Request Body) {String} username Principal username
        @apiParamExample {json} Request Body:
            {
                "principals": [
                    {
                        "username": "jsmith"
                    },
                    {
                        "username": "ksmith"
                    }
                ]
            }

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} principals Array of principals
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA",
                "principals": [
                    { "username": "jsmith" }
                ]
            }
        """
        """
        @api {delete} /api/v1/groups/:uuid/principals/   Remove principals from group
        @apiName removePrincipals
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Remove principals from a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiParam (Query) {String} usernames List of comma separated principal usernames

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 204 NO CONTENT
        """
        principals = []
        group = self.get_object()
        account = self.request.user.account
        if request.method == 'POST':
            serializer = GroupPrincipalInputSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                principals = serializer.data.pop('principals')
            group = self.add_principals(group, principals, account)
            output = GroupSerializer(group)
            return Response(status=status.HTTP_200_OK, data=output.data)
        else:
            if USERNAMES_KEY not in request.query_params:
                key = 'detail'
                message = 'Query parameter {} is required.'.format(USERNAMES_KEY)
                raise serializers.ValidationError({key: _(message)})
            username = request.query_params.get(USERNAMES_KEY, '')
            principals = [name.strip() for name in username.split(',')]
            self.remove_principals(group, principals, account)
            return Response(status=status.HTTP_204_NO_CONTENT)

    def add_roles(self, group, roles):
        """Process list of roles and add them to the group."""
        system_policy_name = 'System Policy for Group {}'.format(group.uuid)
        system_policy, system_policy_created = Policy.objects.get_or_create(system=True,
                                                                            group=group,
                                                                            name=system_policy_name)
        if system_policy_created:
            logger.info('Created new system policy for tenant.')

        for role_id in roles:
            try:
                role = Role.objects.get(uuid=role_id)
                system_policy.roles.add(role)
            except (Role.DoesNotExist, ValidationError):
                logger.info('No role with id %s to save to group.', role_id)

        system_policy.save()

    def remove_roles(self, group, role_ids):
        """Process list of roles and remove them from the group."""
        roles = []
        for role_id in role_ids:
            try:
                role = Role.objects.get(uuid=role_id)
                roles.append(role)
            except (Role.DoesNotExist, ValidationError):
                logger.info('No role with id %s to delete from group.', role_id)

        for policy in group.policies.all():
            policy.roles.remove(*roles)
            policy.save()

    @action(detail=True, methods=['get', 'post', 'delete'])
    def roles(self, request, uuid=None):
        """Get, add or remove roles from a group."""
        """
        @api {get} /api/v1/groups/:uuid/roles/   Get roles for a group
        @apiName getRoles
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Get roles for a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier.

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} roles Array of roles
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "roles": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15",
                        "description": "RoleA Description"
                    }
                ]
            }
        """
        """
        @api {post} /api/v1/groups/:uuid/roles/   Add roles to a group
        @apiName addRoles
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Add roles to a group
        @apiHeader {String} token User authorization token
        @apiParam (Path) {String} id Group unique identifier
        @apiParam (Request Body) {Array} roles Array of role UUIDs
        @apiParamExample {json} Request Body:
            {
                "roles": [
                    "4df211e0-2d88-49a4-8802-728630224d15"
                ]
            }
        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} roles Array of roles
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "roles": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15",
                        "description": "RoleA Description"
                    }
                ]
            }
        """
        """
        @api {delete} /api/v1/groups/:uuid/roles/   Remove roles from group
        @apiName removeRoles
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Remove roles from a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiParam (Query) {String} roles List of comma separated role UUIDs

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 204 NO CONTENT
        """
        roles = []
        group = self.get_object()
        if request.method == 'POST':
            serializer = GroupRoleSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                roles = request.data.pop(ROLES_KEY, [])
            self.add_roles(group, roles)
            response_data = GroupRoleSerializer(group)
        elif request.method == 'GET':
            response_data = GroupRoleSerializer(group)
        else:
            if ROLES_KEY not in request.query_params:
                key = 'detail'
                message = 'Query parameter {} is required.'.format(ROLES_KEY)
                raise serializers.ValidationError({key: _(message)})

            role_ids = request.query_params.get(ROLES_KEY, '').split(',')
            serializer = GroupRoleSerializer(data={'roles': role_ids})
            if serializer.is_valid(raise_exception=True):
                self.remove_roles(group, role_ids)

            return Response(status=status.HTTP_204_NO_CONTENT)

        return Response(status=status.HTTP_200_OK, data=response_data.data)
