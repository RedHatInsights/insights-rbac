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
from management.cache import AccessCache
from management.models import Access
from management.querysets import get_access_queryset
from management.role.serializer import AccessSerializer
from management.utils import (
    APPLICATION_KEY,
    get_principal_from_request,
    validate_and_get_key,
    validate_key,
)
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.views import APIView

ORDER_FIELD = "order_by"
VALID_ORDER_VALUES = ["application", "resource_type", "verb", "-application", "-resource_type", "-verb"]
STATUS_KEY = "status"
VALID_STATUS_VALUE = ["enabled", "disabled", "all"]


class AccessView(APIView):
    """Obtain principal access list."""

    """
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

    serializer_class = AccessSerializer
    pagination_class = api_settings.DEFAULT_PAGINATION_CLASS
    permission_classes = (AllowAny,)

    def get_access_queryset_unique_by_column(self, *columns):
        """Define the access query set with DISTINCT ON clause to get unique records."""
        access_queryset = get_access_queryset(self.request)
        return access_queryset.distinct(*columns).order_by(*columns)

    def get_queryset(self, ordering):
        """Define the query set."""
        unique_columns = ["permission_id", "resourceDefinitions__attributeFilter"]
        access_queryset = Access.objects.filter(id__in=self.get_access_queryset_unique_by_column(*unique_columns))

        if ordering:
            if ordering[0] == "-":
                order_sign = "-"
                field = ordering[1:]
            else:
                order_sign = ""
                field = ordering
            return access_queryset.order_by(f"{order_sign}permission__{field}")
        return access_queryset

    def get(self, request):
        """Provide access data for principal."""
        # Parameter extraction and validation
        try:
            sub_key, ordering = self.validate_and_get_param(request.query_params)
            validate_key(request.query_params, STATUS_KEY, VALID_STATUS_VALUE, "enabled")
        except ValueError as e:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=e)

        principal = get_principal_from_request(request)
        cache = AccessCache(request.tenant.org_id)
        access_policy = cache.get_policy(principal.uuid, sub_key)
        if access_policy is None:
            queryset = self.get_queryset(ordering)
            access_policy = self.serializer_class(queryset, many=True).data
            cache.save_policy(principal.uuid, sub_key, access_policy)

        page = self.paginate_queryset(access_policy)
        if page is not None:
            return self.get_paginated_response(page)
        return Response({"data": access_policy})

    @property
    def paginator(self):
        """Return the paginator instance associated with the view, or `None`."""
        if not hasattr(self, "_paginator"):
            self._paginator = self.pagination_class()
            self._paginator.max_limit = None
        return self._paginator

    def paginate_queryset(self, queryset):
        """Return a single page of results, or `None` if pagination is disabled."""
        if self.paginator is None:
            return None
        if "limit" not in self.request.query_params:
            self.paginator.default_limit = len(queryset)
        return self.paginator.paginate_queryset(queryset, self.request, view=self)

    def get_paginated_response(self, data):
        """Return a paginated style `Response` object for the given output data."""
        assert self.paginator is not None
        return self.paginator.get_paginated_response(data)

    def validate_and_get_param(self, params):
        """Validate input parameters and get ordering and sub_key."""
        app = params.get(APPLICATION_KEY)
        sub_key = app
        ordering = validate_and_get_key(params, ORDER_FIELD, VALID_ORDER_VALUES, required=False)
        if ordering:
            sub_key = f"{app}&order:{ordering}"
        return sub_key, ordering
