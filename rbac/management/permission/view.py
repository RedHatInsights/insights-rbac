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
from management.models import Permission
from management.permission.serializer import PermissionSerializer
from management.permissions.admin_access import AdminAccessPermission
from rest_framework import mixins, viewsets
from rest_framework.filters import OrderingFilter


class PermissionFilter(filters.FilterSet):
    """Filter for role."""

    application = filters.CharFilter(field_name="application", lookup_expr="icontains")
    resource_type = filters.CharFilter(field_name="resource_type", lookup_expr="icontains")
    verb = filters.CharFilter(field_name="verb", lookup_expr="icontains")
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
