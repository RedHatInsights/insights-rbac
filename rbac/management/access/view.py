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

"""View for principal access."""
from django.utils.translation import gettext as _
from management.models import Access, Principal
from management.role.serializer import AccessSerializer
from rest_framework import serializers, status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.views import APIView

APPLICATION_KEY = 'application'
USERNAME_KEY = 'username'


def _policies_for_groups(groups):
    """Gathers all policies for the given groups."""
    policies = []
    for group in set(groups):
        group_policies = set(group.policies.all())
        policies += group_policies
    return policies


def _roles_for_policies(policies):
    """Gathers all roles for the given policies."""
    roles = []
    for policy in set(policies):
        policy_roles = set(policy.roles.all())
        roles += policy_roles
    return roles


def _access_for_roles(roles, application):
    """Gathers all access for the given roles and application."""
    access = []
    for role in set(roles):
        role_access = set(role.access.all())
        for access_item in role_access:
            if application in access_item.permission:
                access.append(access_item)
    return access


class AccessView(APIView):
    """Obtain principal access list.

    @api {get} /api/v1/access/   Obtain principal access list
    @apiName getPrincipalAccess
    @apiGroup Access
    @apiVersion 1.0.0
    @apiDescription Obtain principal access list

    @apiHeader {String} token User authorization token

    @apiParam (Query) {String} application Application name
    @apiParam (Query) {Number} page Parameter for selecting the page of data (default is 1)
    @apiParam (Query) {Number} page_size Parameter for selecting the amount of data in a page (default is 10)

    @apiSuccess {Array} access Array of principal access objects
    @apiSuccessExample {json} Success-Response:
        HTTP/1.1 20O OK
        {
            'meta': {
                'count': 1
            }
            'links': {
                'first': /api/v1/access/?page=1&application=app,
                'next': None,
                'previous': None,
                'last': /api/v1/groups/?page=1&application=app
            },
            "data": [
                {
                    "permission": "app:*:read",
                    "resourceDefinition": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.condition",
                                "value": "value1",
                                "operation": "equal"
                            }
                        }
                    ]
                }
            ]
        }
    """

    serializer_class = AccessSerializer
    pagination_class = api_settings.DEFAULT_PAGINATION_CLASS
    permission_classes = (AllowAny,)

    def get_queryset(self):
        """Define the query set."""
        principal = None
        required_parameters = [APPLICATION_KEY]
        have_parameters = all(param in self.request.query_params for param in required_parameters)

        if not have_parameters:
            key = 'detail'
            message = 'Query parameters [{}] are required.'.format(', '.join(required_parameters))
            raise serializers.ValidationError({key: _(message)})

        current_user = self.request.user.username
        username = self.request.query_params.get(USERNAME_KEY, current_user)
        app = self.request.query_params.get(APPLICATION_KEY)

        try:
            principal = Principal.objects.get(username=username)
        except Principal.DoesNotExist:
            key = 'detail'
            message = 'No access found for principal with username {}.'.format(username)
            raise serializers.ValidationError({key: _(message)})

        groups = set(principal.group.all())
        policies = _policies_for_groups(groups)
        roles = _roles_for_policies(policies)
        access = _access_for_roles(roles, app)
        wanted_ids = [obj.id for obj in access]
        return Access.objects.filter(id__in=wanted_ids)

    def get(self, request):
        """Provide access data for prinicpal."""
        page = self.paginate_queryset(self.get_queryset())
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @property
    def paginator(self):
        """Return the paginator instance associated with the view, or `None`."""
        if not hasattr(self, '_paginator'):
            if self.pagination_class is None:
                self._paginator = None
            else:
                self._paginator = self.pagination_class()
        return self._paginator

    def paginate_queryset(self, queryset):
        """Return a single page of results, or `None` if pagination is disabled."""
        if self.paginator is None:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)

    def get_paginated_response(self, data):
        """Return a paginated style `Response` object for the given output data."""
        assert self.paginator is not None
        return self.paginator.get_paginated_response(data)
