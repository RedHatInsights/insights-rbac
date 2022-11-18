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
from django.conf import settings
from management.cache import AccessCache
from management.querysets import get_access_queryset
from management.role.serializer import AccessSerializer
from management.utils import (
    APPLICATION_KEY,
    get_principal_from_request,
    validate_and_get_key,
    validate_limit_and_offset,
)
from opentelemetry import trace
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.views import APIView

ORDER_FIELD = "order_by"
VALID_ORDER_VALUES = ["application", "resource_type", "verb", "-application", "-resource_type", "-verb"]


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

    def get_queryset(self, ordering):
        """Define the query set."""
        access_queryset = get_access_queryset(self.request)
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
        # Parameter extraction

        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span("access-get"):
            span = trace.get_current_span()
            sub_key, ordering = self.validate_and_get_param(request.query_params)

            principal = get_principal_from_request(request)
            span.add_event("principal", {"principal": principal})
            if settings.AUTHENTICATE_WITH_ORG_ID:
                cache = AccessCache(request.tenant.org_id)
            else:
                cache = AccessCache(request.tenant.tenant_name)
            access_policy = cache.get_policy(principal.uuid, sub_key)
            span.add_event("access_policy", {"policy": '-none-' if access_policy is None else access_policy})
            if access_policy is None:
                # Wrap in a span of its own
                with tracer.start_as_current_span("access-policy-none"):
                    queryset = self.get_queryset(ordering)
                    trace.get_current_span().add_event("Got queryset")
                    access_policy = self.serializer_class(queryset, many=True).data
                    cache.save_policy(principal.uuid, sub_key, access_policy)

            page = self.paginate_queryset(access_policy)
            span.add_event("page", {"page": page})
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
        validate_limit_and_offset(params)
        app = params.get(APPLICATION_KEY)
        sub_key = app
        ordering = validate_and_get_key(params, ORDER_FIELD, VALID_ORDER_VALUES, required=False)
        if ordering:
            sub_key = f"{app}&order:{ordering}"
        return sub_key, ordering
