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
from django.core.exceptions import PermissionDenied
from django.utils.translation import gettext as _
from management.models import Principal
from management.role.serializer import AccessSerializer, RoleSerializer
from rest_framework import serializers, status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.views import APIView

from management.access.utils import PERMISSION_TYPE, ROLE_TYPE, access_for_principal  # noqa: I100, I202

APPLICATION_KEY = 'application'
USERNAME_KEY = 'username'
TYPE_KEY = 'type'
VALID_TYPES = [ROLE_TYPE, PERMISSION_TYPE]


class AccessView(APIView):
    """Obtain principal access list.

    @api {get} /api/v1/access/   Obtain principal access list
    @apiName getPrincipalAccess
    @apiGroup Access
    @apiVersion 1.0.0
    @apiDescription Obtain principal access list

    @apiHeader {String} token User authorization token

    @apiParam (Query) {String} application Application name
    @apiParam (Query) {Number} offset Parameter for selecting the start of data (default is 0).
    @apiParam (Query) {Number} limit Parameter for selecting the amount of data (default is 10).

    @apiSuccess {Object} meta The metadata for pagination.
    @apiSuccess {Object} links  The object containing links of results.
    @apiSuccess {Object[]} data  The array of results.
    @apiSuccessExample {json} Success-Response:
        HTTP/1.1 20O OK
        {
            'meta': {
                'count': 1
            }
            'links': {
                'first': /api/v1/access/?offset=0&limit=10&application=app,
                'next': None,
                'previous': None,
                'last': /api/v1/groups/?offset=0&limit=10&application=app
            },
            "data": [
                {
                    "permission": "app:*:read",
                    "resourceDefinitions": [
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

    pagination_class = api_settings.DEFAULT_PAGINATION_CLASS
    permission_classes = (AllowAny,)

    def get_serializer_class(self):
        """Define the serializer to use based on type query."""
        object_type = self.request.query_params.get(TYPE_KEY, PERMISSION_TYPE)
        if object_type.lower() == ROLE_TYPE:
            return RoleSerializer
        return AccessSerializer

    def get_queryset(self):
        """Define the query set."""
        principal = None
        object_type = self.request.query_params.get(TYPE_KEY, PERMISSION_TYPE)
        if object_type not in VALID_TYPES:
            key = 'detail'
            message = 'Invalid value for {} parameter. Valid values are [{}].'.format(TYPE_KEY,
                                                                                      ','.join(VALID_TYPES))
            raise serializers.ValidationError({key: _(message)})

        if object_type == PERMISSION_TYPE:
            required_parameters = [APPLICATION_KEY]
            have_parameters = all(param in self.request.query_params for param in required_parameters)
            if not have_parameters:
                key = 'detail'
                message = 'Query parameters [{}] are required.'.format(', '.join(required_parameters))
                raise serializers.ValidationError({key: _(message)})

        current_user = self.request.user.username
        username = self.request.query_params.get(USERNAME_KEY)
        app = self.request.query_params.get(APPLICATION_KEY)

        if username and not self.request.user.admin:
            raise PermissionDenied()
        if not username:
            username = current_user

        try:
            principal = Principal.objects.get(username__iexact=username)
        except Principal.DoesNotExist:
            key = 'detail'
            message = 'No access found for principal with username {}.'.format(username)
            raise serializers.ValidationError({key: _(message)})

        return access_for_principal(principal, app, object_type)

    def get(self, request):
        """Provide access data for prinicpal."""
        page = self.paginate_queryset(self.get_queryset())
        if page is not None:
            serializer = self.get_serializer_class()(page, many=True)
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
