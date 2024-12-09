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
import logging
import os
import re
import traceback

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import F, Q
from django.db.models.aggregates import Count
from django.http import Http404
from django.utils.translation import gettext as _
from django_filters import rest_framework as filters
from management.filters import CommonFilters
from management.models import AuditLog, Permission
from management.notifications.notification_handlers import role_obj_change_notification_handler
from management.permissions import RoleAccessPermission
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from management.querysets import get_role_queryset, user_has_perm
from management.relation_replicator.relation_replicator import DualWriteException, ReplicationEventType
from management.role.relation_api_dual_write_handler import (
    RelationApiDualWriteHandler,
)
from management.role.serializer import AccessSerializer, RoleDynamicSerializer, RolePatchSerializer
from management.utils import validate_uuid
from rest_framework import mixins, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter
from rest_framework.response import Response

from api.common.pagination import StandardResultsSetPagination
from api.models import Tenant, User
from rbac.env import ENVIRONMENT
from .model import ExtTenant, Role
from .serializer import RoleSerializer

TESTING_APP = os.getenv("TESTING_APPLICATION")
ADDITIONAL_FIELDS_KEY = "add_fields"
VALID_FIELD_VALUES = ["groups_in_count", "groups_in", "access"]
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
    "admin_default",
    "external_role_id",
    "external_tenant",
]
VALID_PATCH_FIELDS = ["name", "display_name", "description"]
DUPLICATE_KEY_ERROR_MSG = "duplicate key value violates unique constraint"

if TESTING_APP:
    settings.ROLE_CREATE_ALLOW_LIST.append(TESTING_APP)

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RoleFilter(CommonFilters):
    """Filter for role."""

    def application_filter(self, queryset, field, values):
        """Filter to lookup role by application(s) in permissions."""
        applications = values.split(",")
        query = Q()
        for application in applications:
            app_permission_filter = Q(access__permission__permission__istartswith=f"{application}:")
            app_external_tenant_filter = Q(ext_relation__ext_tenant__name__iexact=application)
            query = query | app_permission_filter | app_external_tenant_filter
        return queryset.distinct().filter(query)

    def permission_filter(self, queryset, field, values):
        """Filter to lookup role by application(s) in permissions."""
        permissions = values.split(",")

        return queryset.filter(access__permission__permission__in=permissions).distinct()

    def display_name_filter(self, queryset, field, value):
        """Filter to lookup display_name, partial or exact."""
        return self.name_filter(queryset, field, value, "display_name")

    def external_tenant_filter(self, queryset, field, value):
        """Filter to lookup external tenant name, partial or exact."""
        return queryset.filter(ext_relation__ext_tenant__name__iexact=value)

    name = filters.CharFilter(field_name="name", method="name_filter")
    display_name = filters.CharFilter(field_name="display_name", method="display_name_filter")
    application = filters.CharFilter(field_name="application", method="application_filter")
    permission = filters.CharFilter(field_name="permission", method="permission_filter")
    system = filters.BooleanFilter(field_name="system")
    external_tenant = filters.CharFilter(field_name="external_tenant", method="external_tenant_filter")

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
    default_limit = StandardResultsSetPagination.default_limit

    def get_queryset(self):
        """Obtain queryset for requesting user based on access and action."""
        # NOTE: partial_update intentionally omitted because it does not update access or policy.
        if self.action not in ["update", "destroy"]:
            return get_role_queryset(self.request)
        else:
            # Update queryset differs from normal role queryset in a few ways:
            # - Remove counts; those are not returned in updates
            #   and they prevent us from being able to lock the result
            #   (postgres does not allow select for update with 'group by')
            # - No scope checks since these are not relevant to updates
            # - We also lock the role
            # - We don't bother including system roles because they are not updated this way

            # This lock is necessary to ensure the mapping is always based on the current role
            # state which requires we prevent concurrent modifications to
            # policy, access, and the mappings themselves.
            # Because this does not lock binding_mapping, policy, and access,
            # the role must always be locked for those edits also.

            # It is important that the lock is here.
            # Because we reuse this Role object when reading and
            # determining current relations to remove,
            # this lock prevents any accidental and non-obvious race conditions from occuring.
            # (such as if this was innocently changed to select related access or policy rows)

            # NOTE: If we want to try REPEATABLE READ isolation instead of READ COMMITTED,
            # this should work with that as well.
            # You would be able to remove `select_for_update` here,
            # and instead rely on REPEATABLE READ's lost update detection to abort the tx.
            # Nothing else should need to change.
            public_tenant = Tenant.objects.get(tenant_name="public")
            base_query = Role.objects.filter(tenant__in=[self.request.tenant, public_tenant]).select_for_update()

            # TODO: May be redundant with RolePermissions check but copied from querysets.py for safety
            if ENVIRONMENT.get_value("ALLOW_ANY", default=False, cast=bool):
                return base_query

            if self.request.user.admin:
                return base_query

            access = user_has_perm(self.request, "role")

            if access == "All":
                return base_query

            if access == "None":
                return Role.objects.none()

            return base_query.filter(uuid__in=access)

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
        try:
            with transaction.atomic():
                return super().create(request=request, args=args, kwargs=kwargs)
        except IntegrityError as e:
            if DUPLICATE_KEY_ERROR_MSG in e.args[0]:
                raise serializers.ValidationError(
                    {"role": f"Role '{request.data.get('name')}' already exists for a tenant."}
                )
            raise serializers.ValidationError({"role": "An unexpected database error occurred."}) from e
        except DualWriteException as e:
            return self.dual_write_exception_response(e)

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
        public_tenant = Tenant.objects.get(tenant_name="public")
        base_queryset = (
            Role.objects.only("name", "uuid")
            .filter(tenant__in=[request.tenant, public_tenant])
            .annotate(policyCount=Count("policies", distinct=True), accessCount=Count("access", distinct=True))
        )

        # Filtering
        query_params = {
            "external_tenant": request.query_params.get("external_tenant", None),
            "system": request.query_params.get("system", None),
            "application": request.query_params.get("application", None),
            "display_name": request.query_params.get("display_name", None),
            "name_match": request.query_params.get("name_match", None),
            "permission": request.query_params.get("permission", None),
            "name": request.query_params.get("name", None),
            "platform_default": request.query_params.get("platform_default", None),
            "admin_default": request.query_params.get("admin_default", None),
            "username": request.query_params.get("username", None),
            "limit": request.query_params.get("limit", 10),
            "offset": request.query_params.get("offset", 0),
            "add_fields": request.query_params.get("add_fields", None),
        }

        filters = []
        limit = query_params["limit"]
        offset = int(query_params["offset"])
        path = request.path

        previous_offset = 0
        if offset - limit > 0:
            previous_offset = offset - limit

        if query_params:
            filtered_queryset = base_queryset
            system_value = str(query_params["system"]).lower()

            # Check if "add_fields" is a valid field
            additional_fields = ["access", "groups_in", "groups_in_count"]
            if query_params["add_fields"]:
                split_fields = query_params["add_fields"].split(",")
                invalid_field = [field for field in split_fields if field not in additional_fields]
                if invalid_field:
                    return Response(
                        status=status.HTTP_400_BAD_REQUEST,
                        data={
                            "errors": [
                                {
                                    "detail": "Invalid additional field passed in query",
                                    "source": "add_fields invalid parameter",
                                    "status": status.HTTP_400_BAD_REQUEST,
                                }
                            ]
                        },
                    )

            # Username filter
            if query_params["username"]:
                try:
                    princ = Principal.objects.get(username=query_params["username"])
                except Principal.DoesNotExist:
                    return Response(
                        status=status.HTTP_400_BAD_REQUEST,
                        data={
                            "errors": [
                                {
                                    "detail": "Principal not found for this username",
                                    "source": "Invalid username query parameter",
                                    "status": status.HTTP_400_BAD_REQUEST,
                                }
                            ]
                        },
                    )

                proxy = PrincipalProxy
                results = proxy.request_filtered_principals(
                    query_params["username"],
                    org_id=request.user.org_id,
                )
                results_exist = results["data"]
                if results_exist:
                    principal = results["data"][0]

                    # Convert from principal to User Model to add to request object
                    org_id = principal.get("org_id")
                    user_id = principal.get("user_id")
                    username = principal.get("username")
                    account_number = principal.get("account_number")
                    is_active = principal.get("is_active")

                    # Map principal fields to User fields
                    user = User()
                    user.org_id = org_id
                    user.user_id = user_id
                    user.username = username
                    user.account = account_number
                    user.is_active = is_active
                    request.user_from_query = user

            # External tenant filter
            if query_params["external_tenant"]:
                ext_tenant = ExtTenant.objects.get(name=query_params["external_tenant"])
                if ext_tenant:
                    filters.append(Q(ext_relation__ext_tenant=ext_tenant))
            # System value filter
            if system_value == "false":
                filters.append(Q(system=False))
            elif system_value == "true":
                filters.append(Q(system=True))
            # Application filter
            if query_params["application"]:
                applications = query_params["application"].split(",")

                external_tenant = ExtTenant.objects.filter(name=query_params["application"]).first()

                filtered_queryset = filtered_queryset.filter(access__permission__application__in=applications)
                # If a external tenant exists with the name passed to application query parameter
                # return the roles for that external tenant
                if external_tenant:
                    ext_tenant = ExtTenant.objects.get(name=query_params["application"])
                    filtered_queryset = base_queryset.filter(ext_relation__ext_tenant=ext_tenant).annotate(
                        external_tenant=F("ext_relation__ext_tenant__name")
                    )
            # Display_name & name_match filter
            if query_params["display_name"]:
                if query_params["name_match"] == "partial":
                    filters.append(Q(display_name__contains=query_params["display_name"]))
                elif query_params["name_match"] == "exact":
                    filters.append(Q(display_name__exact=query_params["display_name"]))
                elif not query_params["name_match"]:
                    filters.append(Q(display_name__contains=query_params["display_name"]))
                else:
                    return Response(
                        status=status.HTTP_400_BAD_REQUEST,
                        data={
                            "errors": [
                                {
                                    "detail": "Invalid name match value provided",
                                    "source": "name_match query parameter",
                                    "status": status.HTTP_400_BAD_REQUEST,
                                }
                            ]
                        },
                    )
            # name & name_match filter
            if query_params["name"]:
                if query_params["name_match"] == "partial":
                    filters.append(Q(name__contains=query_params["name"]))
                elif query_params["name_match"] == "exact":
                    filters.append(Q(name__exact=query_params["name"]))
                elif not query_params["name_match"]:
                    filters.append(Q(name__contains=query_params["name"]))
                else:
                    return Response(
                        status=status.HTTP_400_BAD_REQUEST,
                        data={
                            "errors": [
                                {
                                    "detail": "Invalid name match value provided",
                                    "source": "name_match query parameter",
                                    "status": status.HTTP_400_BAD_REQUEST,
                                }
                            ]
                        },
                    )
            # Permission filter
            if query_params["permission"]:
                permissions = query_params["permission"].split(",")
                filters.append(Q(access__permission__permission__in=permissions))

            # Apply the filters
            filtered_queryset = filtered_queryset.filter(*filters)

            # Serialize the queryset for response
            serializer = RoleSerializer(filtered_queryset, many=True, context={"request": request})

            # Metadata
            meta = {}
            if query_params.get("username"):
                meta["count"] = sum(len(group.roles()) for group in princ.group.all())
            else:
                meta["count"] = filtered_queryset.count()

            count = filtered_queryset.count()

            # Pagination
            links = {
                "first": f"{path}?limit={limit}&offset=0",
                "next": f"{path}?limit={limit}&offset={offset + limit}",
                "previous": f"{path}?limit={limit}&offset={previous_offset}",
                "last": f"{path}?limit={limit}&offset={count - limit if (count - limit) >= 0 else 0}",
            }

            return Response({"meta": meta, "links": links, "data": serializer.data})

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

        try:
            with transaction.atomic():
                return super().destroy(request=request, args=args, kwargs=kwargs)
        except DualWriteException as e:
            return self.dual_write_exception_response(e)

    def partial_update(self, request, *args, **kwargs):
        """Patch a role."""
        validate_uuid(kwargs.get("uuid"), "role uuid validation")
        payload = json.loads(request.body or "{}")
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

        try:
            with transaction.atomic():
                return super().update(request=request, args=args, kwargs=kwargs)
        except DualWriteException as e:
            return self.dual_write_exception_response(e)

    def perform_create(self, serializer):
        """
        Create the role and publish outbox, notification, and audit events.

        Assumes concurrent updates are prevented (e.g. with atomic block and locks).
        """
        role = serializer.save()

        dual_write_handler = RelationApiDualWriteHandler(role, ReplicationEventType.CREATE_CUSTOM_ROLE)
        dual_write_handler.replicate_new_or_updated_role(role)

        role_obj_change_notification_handler(role, "created", self.request.user)

        auditlog = AuditLog()
        auditlog.log_create(self.request, AuditLog.ROLE)

    def perform_update(self, serializer):
        """
        Update the role and publish outbox, notification, and audit events.

        Assumes concurrent updates are prevented (e.g. with atomic block and locks).
        """
        if self.action != "partial_update":
            dual_write_handler = RelationApiDualWriteHandler(
                serializer.instance, ReplicationEventType.UPDATE_CUSTOM_ROLE
            )
            dual_write_handler.prepare_for_update()

        role = serializer.save()

        if self.action != "partial_update":
            dual_write_handler.replicate_new_or_updated_role(role)
            role_obj_change_notification_handler(role, "updated", self.request.user)

        auditlog = AuditLog()
        auditlog.log_edit(self.request, AuditLog.ROLE, role)

    def perform_destroy(self, instance: Role):
        """
        Delete the role and publish outbox, notification, and audit events.

        Assumes concurrent updates are prevented (e.g. with atomic block and locks).
        """
        if instance.tenant_id == Tenant.objects.get(tenant_name="public").id:
            key = "role"
            message = "System roles cannot be deleted."
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)

        dual_write_handler = RelationApiDualWriteHandler(instance, ReplicationEventType.DELETE_CUSTOM_ROLE)
        dual_write_handler.prepare_for_update()

        self.delete_policies_if_no_role_attached(instance)
        instance.delete()

        dual_write_handler.replicate_deleted_role()
        role_obj_change_notification_handler(instance, "deleted", self.request.user)

        # Audit in perform_destroy because it needs access to deleted instance
        auditlog = AuditLog()
        auditlog.log_delete(self.request, AuditLog.ROLE, instance)

    def dual_write_exception_response(self, e):
        """Dual write exception response."""
        logging.error(traceback.format_exc())
        return Response(
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            data={
                "errors": [
                    {
                        "detail": "Dual Write Exception:" + str(e),
                        "source": "role",
                        "status": str(status.HTTP_500_INTERNAL_SERVER_ERROR),
                    }
                ]
            },
        )

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
            sent_permissions = [access["permission"] for access in access_list]
            for perm in access_list:
                app, resource_type, verb = perm.get("permission").split(":")
                if app not in settings.ROLE_CREATE_ALLOW_LIST:
                    key = "role"
                    message = "Custom roles cannot be created for {}".format(app)
                    error = {key: [_(message)]}
                    raise serializers.ValidationError(error)

                db_permission = Permission.objects.filter(
                    application=app, resource_type=resource_type, verb=verb
                ).first()

                if not db_permission:
                    key = "role"
                    message = f"Permission does not exist: {perm.get('permission')}"
                    error = {key: [_(message)]}
                    raise serializers.ValidationError(error)

                required_permissions = list(db_permission.permissions.all().values_list("permission", flat=True))
                if required_permissions:
                    all_required_permissions_sent = all(perm in sent_permissions for perm in required_permissions)
                    if not all_required_permissions_sent:
                        key = "role"
                        message = f"Permission '{db_permission.permission}' requires: '{required_permissions}'"
                        error = {key: [_(message)]}
                        raise serializers.ValidationError(error)

    def delete_policies_if_no_role_attached(self, role):
        """Delete policy if there is no role attached to it."""
        policies = role.policies.all()
        for policy in policies:
            if policy.roles.count() == 1:
                policy.delete()
