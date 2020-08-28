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

"""View for permission management."""
from django_filters import rest_framework as filters
from management.filters import CommonFilters
from management.models import Permission
from management.permission.serializer import PermissionSerializer
from management.permissions.admin_access import AdminAccessPermission
from management.utils import validate_and_get_key
from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter

PERMISSION_FIELD_KEYS = {"application", "resource_type", "verb"}
QUERY_FIELD = "field"


class PermissionFilter(CommonFilters):
    """Filter for role."""

    application = filters.CharFilter(field_name="application", method="multiple_values_in")
    resource_type = filters.CharFilter(field_name="resource_type", method="multiple_values_in")
    verb = filters.CharFilter(field_name="verb", method="multiple_values_in")
    permission = filters.CharFilter(field_name="permission", lookup_expr="icontains")


class PermissionViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """Permission View.

    A viewset that provides the default `list()` action.

    """

    queryset = Permission.objects.all()
    permission_classes = (AdminAccessPermission,)
    filter_backends = (filters.DjangoFilterBackend, OrderingFilter)
    serializer_class = PermissionSerializer
    filterset_class = PermissionFilter
    ordering_fields = ("application", "resource_type", "verb", "permission")
    ordering = ("application",)

    def list(self, request, *args, **kwargs):
        """Obtain the list of permissions for the tenant.

        @api {get} /api/v1/permissions/   Obtain a list of permissions
        @apiName getPermissions
        @apiGroup Permission
        @apiVersion 1.0.0
        @apiDescription Obtain a list of permissions

        @apiHeader {String} token User authorization token

        @apiParam (Query) {String} application Filter by permission name.
        @apiParam (Query) {String} resource_type Filter by permission name.
        @apiParam (Query) {String} verb Filter by permission name.
        @apiParam (Query) {Number} offset Parameter for selecting the start of data (default is 0).
        @apiParam (Query) {Number} limit Parameter for selecting the amount of data (default is 10).

        @apiSuccess {Object} meta The metadata for pagination.
        @apiSuccess {Object} links  The object containing links of results.
        @apiSuccess {Object[]} data  The array of results.

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
        {
          "meta": {
            "count": 2
          },
          "links": {
            "first": "/api/v1/permissions/?offset=0&limit=10",
            "next": null,
            "previous": null,
            "last": "/api/v1/permissions/?offset=0&limit=10"
          },
          "data": [
            {
              "application": "rbac",
              "resource_type": "*",
              "verb": "read",
              "permission": "rbac:*:read"
            }
          ]
        }
        """
        return super().list(request=request, args=args, kwargs=kwargs)

    @action(detail=False)
    def options(self, request):
        """Get options of applications."""
        """
        @api {get} /api/v1/permissions/options/   Get option of permission
        @apiName getPermissionOption
        @apiGroup Permission
        @apiVersion 1.0.0
        @apiDescription Get option of permission

        @apiHeader {String} token User authorization token

        @apiParam (Query) {String} field The field to return.

        @apiParam (Query) {String} application Filter by permission name.
        @apiParam (Query) {String} resource_type Filter by resource_type.
        @apiParam (Query) {String} verb Filter by verb.

        @apiSuccess {Object[]} data  The array of results.

            HTTP/1.1 200 OK
        {
          "data": [
            catalog, approval
          ]
        }
        """
        filters = {}
        query_field = validate_and_get_key(request.query_params, QUERY_FIELD, PERMISSION_FIELD_KEYS, None)

        for key in PERMISSION_FIELD_KEYS:
            context = request.query_params.get(key)
            if context:
                filters[f"{key}__in"] = context.split(",")

        query_set = Permission.objects.distinct(query_field).filter(**filters).values_list(query_field, flat=True)

        if "limit" not in self.request.query_params:
            self.paginator.default_limit = self.paginator.max_limit
        page = self.paginate_queryset(query_set)
        return self.get_paginated_response(page)
