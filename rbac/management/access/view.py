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
from django.db.models import Prefetch
from management.cache import AccessCache
from management.models import Access, ResourceDefinition, Workspace
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
        distinct_queryset = self.get_access_queryset_unique_by_column(*unique_columns)
        access_queryset = (
            Access.objects.filter(id__in=distinct_queryset)
            .select_related("permission")
            .prefetch_related(
                Prefetch(
                    "resourceDefinitions", queryset=ResourceDefinition.objects.select_related("access__permission")
                )
            )
        )

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
            access_policy = self.serializer_class(queryset, many=True, context={"for_access": True}).data
            cache.save_policy(principal.uuid, sub_key, access_policy)

        page = self.paginate_queryset(access_policy)
        response = Response({"data": access_policy}) if page is None else self.get_paginated_response(page)

        self.add_ungrouped_hosts_id(response, request.tenant)

        return response

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

    def add_ungrouped_hosts_id(self, response, tenant):
        """Add ungrouped hosts id to the data."""
        if not settings.ADD_UNGROUPED_HOSTS_ID:
            return
        ungrouped_hosts_id = None
        queried = False
        for access in response.data["data"]:
            for resource_def in access.get("resourceDefinitions", []):
                attribute_filter = resource_def.get("attributeFilter", {})
                if attribute_filter.get("key") == "group.id" and None in attribute_filter.get("value"):
                    if not ungrouped_hosts_id and not queried:
                        ungrouped_workspace = Workspace.objects.filter(
                            type=Workspace.Types.UNGROUPED_HOSTS, tenant=tenant
                        ).first()
                        queried = True
                    if ungrouped_workspace:
                        ungrouped_hosts_id = str(ungrouped_workspace.id)
                        if ungrouped_hosts_id not in attribute_filter["value"]:
                            attribute_filter["value"].append(ungrouped_hosts_id)
                        if settings.REMOVE_NULL_VALUE:
                            attribute_filter["value"].remove(None)
        return response
