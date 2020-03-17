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
from uuid import UUID

from django.db.models.aggregates import Count
from django.utils.translation import gettext as _
from django_filters import rest_framework as filters
from management.group.definer import add_roles, remove_roles, set_system_flag_post_update
from management.group.model import Group
from management.group.serializer import (GroupInputSerializer,
                                         GroupPrincipalInputSerializer,
                                         GroupRoleSerializerIn,
                                         GroupRoleSerializerOut,
                                         GroupSerializer,
                                         RoleMinimumSerializer)
from management.permissions import GroupAccessPermission
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from management.principal.serializer import PrincipalSerializer
from management.querysets import get_group_queryset, get_object_principal_queryset
from management.role.model import Role
from management.role.view import RoleViewSet
from rest_framework import mixins, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter
from rest_framework.response import Response


USERNAMES_KEY = 'usernames'
ROLES_KEY = 'roles'
EXCLUDE_KEY = 'exclude'
ORDERING_PARAM = 'order_by'
VALID_ROLE_ORDER_FIELDS = list(RoleViewSet.ordering_fields)
ROLE_DISCRIMINATOR_KEY = 'role_discriminator'
VALID_EXCLUDE_VALUES = ['true', 'false']
VALID_GROUP_ROLE_FILTERS = ['role_name', 'role_description']
VALID_GROUP_PRINCIPAL_FILTERS = ['principal_username']
VALID_ROLE_ROLE_DISCRIMINATOR = ['all', 'any']

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class GroupFilter(filters.FilterSet):
    """Filter for group."""

    def username_filter(self, queryset, field, value):
        """Filter for group username lookup."""
        filters = {'{}__username__icontains'.format(field): value}
        filtered_set = queryset.filter(**filters)
        return filtered_set | Group.platform_default_set()

    def uuid_filter(self, queryset, field, values):
        """Filter for group uuid lookup."""
        uuids = values.split(',')
        for uuid in uuids:
            try:
                UUID(uuid)
            except ValueError:
                key = 'groups uuid filter'
                message = f'{uuid} is not a valid UUID.'
                raise serializers.ValidationError({key: _(message)})
        filters = {f'{field}__in': uuids}
        filtered_set = queryset.filter(**filters)
        return filtered_set

    def roles_filter(self, queryset, field, values):
        """Filter for group to lookup list of role name."""
        if not values:
            key = 'groups_filter'
            message = 'No value of roles provided to filter groups!'
            error = {
                key: [_(message)]
            }
            raise serializers.ValidationError(error)
        roles_list = [value.lower() for value in values.split(',')]

        discriminator = validate_and_get_key(
            self.request.query_params,
            ROLE_DISCRIMINATOR_KEY,
            VALID_ROLE_ROLE_DISCRIMINATOR,
            'any')

        if discriminator == 'any':
            return queryset.filter(policies__roles__name__iregex=r'(' + '|'.join(roles_list) + ')')

        for role_name in roles_list:
            queryset = queryset.filter(policies__roles__name__icontains=role_name)
        return queryset

    name = filters.CharFilter(field_name='name', lookup_expr='icontains')
    username = filters.CharFilter(field_name='principals', method='username_filter')
    role_names = filters.CharFilter(field_name='role_names', method='roles_filter')
    uuid = filters.CharFilter(field_name='uuid', method='uuid_filter')

    class Meta:
        model = Group
        fields = ['name', 'principals', 'role_names', 'uuid']


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
        if ROLES_KEY in self.request.path and self.request.method == 'GET':
            return GroupRoleSerializerOut
        if ROLES_KEY in self.request.path:
            return GroupRoleSerializerIn
        if self.request.method in ('POST', 'PUT'):
            return GroupInputSerializer
        if self.request.path.endswith('groups/') and self.request.method == 'GET':
            return GroupInputSerializer
        return GroupSerializer

    def protect_default_groups(self, action):
        """Deny modifications on platform_default groups."""
        group = self.get_object()
        if group.platform_default:
            key = 'group'
            message = '{} cannot be performed on platform default groups.'.format(action.upper())
            error = {
                key: [_(message)]
            }
            raise serializers.ValidationError(error)

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
        @apiParam (Query) {array} uuid Filter by comma separated list of uuids
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
        self.protect_default_groups('delete')
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
        self.protect_default_groups('update')
        return super().update(request=request, args=args, kwargs=kwargs)

    def add_principals(self, group, principals, account):
        """Process list of principals and add them to the group."""
        users = [principal.get('username') for principal in principals]
        resp = self.proxy.request_filtered_principals(users, account, limit=len(users))
        if 'errors' in resp:
            return resp
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

    @action(detail=True, methods=['get', 'post', 'delete'])
    def principals(self, request, uuid=None):
        """Get, add or remove principals from a group."""
        """
        @api {get} /api/v1/groups/:uuid/principals/    Get principals for a group
        @apiName getPrincipals
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Get principals for a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} principals Array of principals
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "principals": [
                    { "username": "jsmith" }
                ]
            }
        """
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
            resp = self.add_principals(group, principals, account)
            if isinstance(resp, dict) and 'errors' in resp:
                return Response(status=resp['status_code'], data=resp['errors'])
            output = GroupSerializer(resp)
            response = Response(status=status.HTTP_200_OK, data=output.data)
        elif request.method == 'GET':
            principals_from_params = self.filtered_principals(group, request)
            page = self.paginate_queryset(principals_from_params)
            serializer = PrincipalSerializer(page, many=True)
            principal_data = serializer.data
            if principal_data:
                username_list = [principal['username'] for principal in principal_data]
            else:
                username_list = []
            proxy = PrincipalProxy()
            resp = proxy.request_filtered_principals(username_list, account)
            if isinstance(resp, dict) and 'errors' in resp:
                return Response(status=resp.get('status_code'), data=resp.get('errors'))
            response = self.get_paginated_response(resp.get('data'))
        else:
            if USERNAMES_KEY not in request.query_params:
                key = 'detail'
                message = 'Query parameter {} is required.'.format(USERNAMES_KEY)
                raise serializers.ValidationError({key: _(message)})
            username = request.query_params.get(USERNAMES_KEY, '')
            principals = [name.strip() for name in username.split(',')]
            self.remove_principals(group, principals, account)
            response = Response(status=status.HTTP_204_NO_CONTENT)
        return response

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

        @apiParam (Query) {String} order_by Determine ordering of returned roles.

        @apiSuccess {Array} data Array of roles
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "data": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15",
                        "description": "RoleA Description",
                        "policyCount: 0,
                        "applications": [],
                        "system": false,
                        "platform_default": false
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
                "data": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15",
                        "description": "RoleA Description",
                        "policyCount: 0,
                        "applications": [],
                        "system": false,
                        "platform_default": false
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
            serializer = GroupRoleSerializerIn(data=request.data)
            if serializer.is_valid(raise_exception=True):
                roles = request.data.pop(ROLES_KEY, [])
            add_roles(group, roles)
            set_system_flag_post_update(group)
            response_data = GroupRoleSerializerIn(group)
        elif request.method == 'GET':
            serialized_roles = self.obtain_roles(request, group)
            page = self.paginate_queryset(serialized_roles)
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        else:
            if ROLES_KEY not in request.query_params:
                key = 'detail'
                message = 'Query parameter {} is required.'.format(ROLES_KEY)
                raise serializers.ValidationError({key: _(message)})

            role_ids = request.query_params.get(ROLES_KEY, '').split(',')
            serializer = GroupRoleSerializerIn(data={'roles': role_ids})
            if serializer.is_valid(raise_exception=True):
                remove_roles(group, role_ids)
                set_system_flag_post_update(group)

            return Response(status=status.HTTP_204_NO_CONTENT)

        return Response(status=status.HTTP_200_OK, data=response_data.data)

    def order_queryset(self, queryset, valid_fields, order_field):
        """Return queryset ordered according to order_by query param."""
        all_valid_fields = valid_fields + ['-' + field for field in valid_fields]
        if order_field in all_valid_fields:
            return queryset.order_by(order_field)
        else:
            key = 'detail'
            message = f'{order_field} is not a valid ordering field. Valid values are {all_valid_fields}'
            raise serializers.ValidationError({key: _(message)})

    def filtered_roles(self, roles, request):
        """Return filtered roles for group from query params."""
        role_filters = self.filters_from_params(VALID_GROUP_ROLE_FILTERS, 'role', request)
        return roles.filter(**role_filters)

    def filtered_principals(self, group, request):
        """Return filtered principals for group from query params."""
        principal_filters = self.filters_from_params(VALID_GROUP_PRINCIPAL_FILTERS, 'principal', request)
        return group.principals.filter(**principal_filters)

    def filters_from_params(self, valid_filters, model_name, request):
        """Build filters from group params."""
        filters = {}
        for param_name, param_value in request.query_params.items():
            if param_name in valid_filters:
                attr_filter_name = param_name.replace(f'{model_name}_', '')
                filters[f'{attr_filter_name}__icontains'] = param_value
        return filters

    def obtain_roles(self, request, group):
        """Obtain roles based on request, supports exclusion."""
        exclude = validate_and_get_key(
            request.query_params,
            EXCLUDE_KEY,
            VALID_EXCLUDE_VALUES,
            'false')

        roles = (group.roles_with_access() if exclude == 'false'
                 else self.obtain_roles_with_exclusion(request, group))

        filtered_roles = self.filtered_roles(roles, request)

        annotated_roles = filtered_roles.annotate(policyCount=Count('policies', distinct=True))

        if ORDERING_PARAM in request.query_params:
            ordered_roles = self.order_queryset(annotated_roles, VALID_ROLE_ORDER_FIELDS,
                                                request.query_params.get(ORDERING_PARAM))

            return [RoleMinimumSerializer(role).data for role in ordered_roles]
        return [RoleMinimumSerializer(role).data for role in annotated_roles]

    def obtain_roles_with_exclusion(self, request, group):
        """Obtain the queryset for roles based on scope."""
        scope = request.query_params.get('scope', 'account')
        # Get roles in principal or account scope
        roles = (get_object_principal_queryset(request, scope, Role) if scope == 'principal'
                 else Role.objects.all().prefetch_related('access'))

        # Exclude the roles in the group
        roles_for_group = group.roles().values('uuid')
        return roles.exclude(uuid__in=roles_for_group)


def validate_and_get_key(params, query_key, valid_values, default_value):
    """Validate the key."""
    value = params.get(query_key, default_value).lower()
    if value not in valid_values:
        key = 'detail'
        message = '{} query parameter value {} is invalid. {} are valid inputs.'.format(
            query_key,
            value,
            valid_values)
        raise serializers.ValidationError({key: _(message)})
    return value
