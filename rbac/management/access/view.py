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
from django.core.exceptions import ObjectDoesNotExist
from management.cache import AccessCache
from management.models import Access, Permission, Workspace, ResourceDefinition
from management.querysets import get_access_queryset
from management.role.serializer import AccessSerializer
from management.utils import (
    APPLICATION_KEY,
    access_for_principal,
    get_principal_from_request,
    validate_and_get_key,
    validate_limit_and_offset,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework.views import APIView

ORDER_FIELD = "order_by"
VALID_ORDER_VALUES = ["application", "resource_type", "verb", "-application", "-resource_type", "-verb"]



def get_individual_asset_access(individual_asset_key, individual_asset_value, access_for_request):
    """Get Access from Resource definitions if individual asset access is specified.
    If key & value are specified, return whether or not access exists.
    If only key is specified, return values for that key.
    """
    access_objects = [access_object.id for access_object in access_for_request]
    RDs = ResourceDefinition.objects.filter(access_id__in=access_objects)
    individual_asset_values = []
    response = {
        "individual_asset_values": individual_asset_values,
    }
    if individual_asset_value is not None:
        response = {
            "has_access": False,
            "individual_asset_key": individual_asset_key,
            "individual_asset_value": individual_asset_value,
        }
    for RD in RDs:
        attributeFilter = RD.attributeFilter
        if attributeFilter:
            if attributeFilter["key"] == individual_asset_key:
                if individual_asset_value:
                    # if a value was passed in check for access
                    # scorecard line 11 (continued more finegrained)
                    if attributeFilter["value"]== individual_asset_value:
                        response["has_access"] = True
                        break
                else:
                    # if a value wasn't passed in - check for asset values for the type
                    # scorecard line 23 minus a verb
                    individual_asset_values.append(attributeFilter["value"])
    return Response(response)
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
        # Parameter extraction
        sub_key, ordering = self.validate_and_get_param(request.query_params)

        principal = get_principal_from_request(request)

        ### PDP SPIKE ### # noqa: E266
        query_params = request.query_params
        pdp = query_params.get("pdp")
        if pdp == "true":
            workspace = query_params.get("workspace")
            application = query_params.get("application")
            resource_type = query_params.get("resource_type")
            verb = query_params.get("verb")
            individual_asset_key = query_params.get("individual_asset_key")
            individual_asset_value = query_params.get("individual_asset_value")
            if workspace:
                workspace_obj = Workspace.objects.filter(name=workspace).first()
                if not workspace_obj:
                    return Response({"error": "workspace does not exist"})
                ancestor_workspaces = workspace_obj.get_ancestors()
                ancestor_names = [ancestor.name for ancestor in ancestor_workspaces]
                ancestor_names.append(workspace)
            try:
                permission = Permission.objects.get(workspace__name__in=ancestor_names, application=application, resource_type=resource_type, verb=verb)
            except ObjectDoesNotExist:
                # return Response({"error": "permission does not exist"})
                return Response(
                    {
                        "has_access": False,
                        "permission": "Permission does not exist in this workspace.",
                        "workspace": workspace,
                        "service": application,
                        "asset_type": resource_type,
                        "verb": verb,
                    }
                )

            # not the most performant because we query Access again since
            # access_for_principal returns a set vs queryset
            access = access_for_principal(principal, request.tenant)
            pks = [a.id for a in access]
            access_for_request = Access.objects.filter(id__in=pks, permission=permission)
            if access_for_request.exists():
                if individual_asset_key:
                    return get_individual_asset_access(individual_asset_key, individual_asset_value, access_for_request)

            return Response(
                {
                    "has_access": access_for_request.exists(),
                    "permission": permission.permission,
                    "workspace": workspace,
                    "service": application,
                    "asset_type": resource_type,
                    "verb": verb,
                }
            )
        ### PDP SPIKE ### # noqa: E266

        # would need to fix policy caching for PDP endpoint
        if settings.AUTHENTICATE_WITH_ORG_ID:
            cache = AccessCache(request.tenant.org_id)
        else:
            cache = AccessCache(request.tenant.tenant_name)
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
        validate_limit_and_offset(params)
        app = params.get(APPLICATION_KEY)
        sub_key = app
        ordering = validate_and_get_key(params, ORDER_FIELD, VALID_ORDER_VALUES, required=False)
        if ordering:
            sub_key = f"{app}&order:{ordering}"
        return sub_key, ordering
