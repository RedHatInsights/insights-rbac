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

"""View for role management."""
import json
import os
import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.db.models.aggregates import Count
from django.http import Http404
from django.utils.translation import gettext as _
from django_filters import rest_framework as filters
from management.filters import CommonFilters
from management.models import Permission
from management.permissions import RoleAccessPermission
from management.querysets import get_role_queryset
from management.role.serializer import AccessSerializer, RoleDynamicSerializer, RolePatchSerializer
from management.utils import validate_uuid
from rest_framework import mixins, serializers, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter

from .model import Role
from .serializer import RoleSerializer

TESTING_APP = os.getenv("TESTING_APPLICATION")
ADDITIONAL_FIELDS_KEY = "add_fields"
VALID_FIELD_VALUES = ["groups_in_count", "groups_in"]
LIST_ROLE_FIELDS = [
    "uuid",
    "name",
    "display_name",
    "description",
    "created",
    "modified",
    "policyCount",
    "accessCount",
    "applications",
    "system",
    "platform_default",
]
VALID_PATCH_FIELDS = ["name", "display_name", "description"]

if TESTING_APP:
    settings.ROLE_CREATE_ALLOW_LIST.append(TESTING_APP)


class RoleFilter(CommonFilters):
    """Filter for role."""

    def application_filter(self, queryset, field, values):
        """Filter to lookup role by application(s) in permissions."""
        applications = values.split(",")
        query = Q()
        for application in applications:
            query = query | Q(access__permission__permission__istartswith=f"{application}:")
        return queryset.distinct().filter(query)

    def permission_filter(self, queryset, field, values):
        """Filter to lookup role by application(s) in permissions."""
        permissions = values.split(",")

        return queryset.filter(access__permission__permission__in=permissions).distinct()

    def display_name_filter(self, queryset, field, value):
        """Filter to lookup display_name, partial or exact."""
        return self.name_filter(queryset, field, value, "display_name")

    name = filters.CharFilter(field_name="name", method="name_filter")
    display_name = filters.CharFilter(field_name="display_name", method="display_name_filter")
    application = filters.CharFilter(field_name="application", method="application_filter")
    permission = filters.CharFilter(field_name="permission", method="permission_filter")

    class Meta:
        model = Role
        fields = ["name"]


class RoleViewSet(
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Role View.

    A viewset that provides default `create()`, `destroy`, `retrieve()`,
    and `list()` actions.

    """

    queryset = Role.objects.annotate(policyCount=Count("policies", distinct=True))
    serializer_class = RoleSerializer
    permission_classes = (RoleAccessPermission,)
    lookup_field = "uuid"
    filter_backends = (filters.DjangoFilterBackend, OrderingFilter)
    filterset_class = RoleFilter
    ordering_fields = ("name", "display_name", "modified", "policyCount")
    ordering = ("name",)

    def get_queryset(self):
        """Obtain queryset for requesting user based on access."""
        return get_role_queryset(self.request)

    def get_serializer_class(self):
        """Get serializer class based on route."""
        if self.request.path.endswith("roles/") and self.request.method == "GET":
            return RoleDynamicSerializer
        if self.request.method == "PATCH" and re.match(".*/roles/.*/$", self.request.path):
            return RolePatchSerializer
        return RoleSerializer

    def get_serializer(self, *args, **kwargs):
        """Get serializer."""
        serializer_class = self.get_serializer_class()
        kwargs["context"] = self.get_serializer_context()

        if self.action == "list":
            kwargs["fields"] = self.validate_and_get_additional_field_key(self.request.query_params)

        return serializer_class(*args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Create a roles.

        @api {post} /api/v1/roles/   Create a role
        @apiName createRole
        @apiGroup Role
        @apiVersion 1.0.0
        @apiDescription Create a role

        @apiHeader {String} token User authorization token

        @apiParam (Request Body) {String} name Role name
        @apiParam (Request Body) {Array} access Access definition
        @apiParamExample {json} Request Body:
            {
                "name": "RoleA",
                "access": [
                    {
                    "permission": "app:*:read",
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.case",
                                "operation": "equal",
                                "value": "thevalue"
                            }
                        }
                    ]
                    }
                ]
            }

        @apiSuccess {String} uuid Role unique identifier
        @apiSuccess {String} name Role name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 201 CREATED
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "RoleA",
                "display_name": "RoleA",
                "access": [
                    {
                    "permission": "app:*:read",
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.case",
                                "operation": "equal",
                                "value": "thevalue"
                            }
                        }
                    ]
                    }
                ]
            }
        """
        self.validate_role(request)
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of roles for the tenant.

        @api {get} /api/v1/roles/   Obtain a list of roles
        @apiName getRoles
        @apiGroup Role
        @apiVersion 1.0.0
        @apiDescription Obtain a list of roles

        @apiHeader {String} token User authorization token

        @apiParam (Query) {String} name Filter by role name.
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
                    'first': /api/v1/roles/?offset=0&limit=10,
                    'next': None,
                    'previous': None,
                    'last': /api/v1/roles/?offset=0&limit=10
                },
                'data': [
                            {
                                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                                "name": "RoleA"
                            },
                            {
                                "uuid": "20ecdcd0-397c-4ede-8940-f3439bf40212",
                                "name": "RoleB"
                            }
                        ]
            }

        """
        return super().list(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a role.

        @api {get} /api/v1/roles/:uuid   Get a role
        @apiName getRole
        @apiGroup Role
        @apiVersion 1.0.0
        @apiDescription Get a role

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Role unique identifier.

        @apiSuccess {String} uuid Role unique identifier
        @apiSuccess {String} name Role name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "RoleA",
                "display_name": "RoleA",
                "access": [
                    {
                    "permission": "app:*:read",
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.case",
                                "operation": "equal",
                                "value": "thevalue"
                            }
                        }
                    ]
                    }
                ]
            }
        """
        validate_uuid(kwargs.get("uuid"), "role uuid validation")
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a role.

        @api {delete} /api/v1/roles/:uuid   Delete a role
        @apiName deleteRole
        @apiGroup Role
        @apiVersion 1.0.0
        @apiDescription Delete a role

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} uuid Role unique identifier

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 204 NO CONTENT
        """
        validate_uuid(kwargs.get("uuid"), "role uuid validation")
        role = self.get_object()
        if role.system or role.platform_default:
            key = "role"
            message = "System roles cannot be deleted."
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
        with transaction.atomic():
            policies = role.policies.all()
            for policy in policies:
                if policy.roles.count() == 1:
                    policy.delete()
            return super().destroy(request=request, args=args, kwargs=kwargs)

    def partial_update(self, request, *args, **kwargs):
        """Patch a role."""
        validate_uuid(kwargs.get("uuid"), "role uuid validation")
        payload = json.loads(request.body)
        for field in payload:
            if field not in VALID_PATCH_FIELDS:
                key = "role"
                message = f"Field '{field}' is not supported. Please use one or more of: {VALID_PATCH_FIELDS}."
                error = {key: [_(message)]}
                raise serializers.ValidationError(error)
        return super().update(request=request, args=args, kwargs=kwargs)

    def update(self, request, *args, **kwargs):
        """Update a role.

        @api {post} /api/v1/roles/:uuid   Update a role
        @apiName updateRole
        @apiGroup Role
        @apiVersion 1.0.0
        @apiDescription Update a role

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Role unique identifier

        @apiParam (Request Body) {String} name Role name
        @apiParam (Request Body) {Array} access Access definition
        @apiParamExample {json} Request Body:
            {
                "name": "RoleA",
                "access": [
                    {
                    "permission": "app:*:read",
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.case",
                                "operation": "equal",
                                "value": "change_value"
                            }
                        }
                    ]
                    }
                ]
            }

        @apiSuccess {String} uuid Role unique identifier
        @apiSuccess {String} name Role name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "RoleA",
                "display_name": "RoleA",
                "access": [
                    {
                    "permission": "app:*:read",
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.case",
                                "operation": "equal",
                                "value": "change_value"
                            }
                        }
                    ]
                    }
                ]
            }
        """
        validate_uuid(kwargs.get("uuid"), "role uuid validation")
        self.validate_role(request)
        return super().update(request=request, args=args, kwargs=kwargs)

    @action(detail=True, methods=["get"])
    def access(self, request, uuid=None):
        """Return access objects for specified role."""
        validate_uuid(uuid, "role uuid validation")
        try:
            role = Role.objects.get(uuid=uuid)
        except (Role.DoesNotExist, ValidationError):
            raise Http404()

        access = AccessSerializer(role.access, many=True).data
        page = self.paginate_queryset(access)
        return self.get_paginated_response(page)

    def validate_and_get_access_list(self, data):
        """Validate if input data contains valid access list and return."""
        access_list = data.get("access")
        if not isinstance(access_list, list):
            key = "access"
            message = "A list of access is expected, but {} is found.".format(type(access_list).__name__)
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
        for access in access_list:
            AccessSerializer(data=access).is_valid(raise_exception=True)
        return access_list

    def validate_and_get_additional_field_key(self, params):
        """Validate the add field key."""
        fields = params.get(ADDITIONAL_FIELDS_KEY)
        if fields is None:
            return LIST_ROLE_FIELDS

        field_list = fields.split(",")
        for field in field_list:
            if field not in VALID_FIELD_VALUES:
                key = "detail"
                message = "{} query parameter value {} is invalid. Valid inputs are {}.".format(
                    ADDITIONAL_FIELDS_KEY, field, VALID_FIELD_VALUES
                )
                raise serializers.ValidationError({key: _(message)})

        return LIST_ROLE_FIELDS + field_list

    def validate_role(self, request):
        """Validate the role request data."""
        access_list = self.validate_and_get_access_list(request.data)
        if access_list:
            for perm in access_list:
                app, resource_type, verb = perm.get("permission").split(":")
                if app not in settings.ROLE_CREATE_ALLOW_LIST:
                    key = "role"
                    message = "Custom roles cannot be created for {}".format(app)
                    error = {key: [_(message)]}
                    raise serializers.ValidationError(error)

                db_permission = Permission.objects.filter(
                    application=app, resource_type=resource_type, verb=verb
                ).exists()

                if not db_permission:
                    key = "role"
                    message = f"Permission does not exist: {perm.get('permission')}"
                    error = {key: [_(message)]}
                    raise serializers.ValidationError(error)
