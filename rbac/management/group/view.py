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

"""View for group management."""
import logging

import requests
from django.conf import settings
from django.db import connection
from django.db import transaction
from django.db.models.aggregates import Count
from django.utils.translation import gettext as _
from django_filters import rest_framework as filters
from management.filters import CommonFilters
from management.group.definer import add_roles, remove_roles, set_system_flag_before_update
from management.group.model import Group
from management.group.serializer import (
    GroupInputSerializer,
    GroupPrincipalInputSerializer,
    GroupRoleSerializerIn,
    GroupRoleSerializerOut,
    GroupSerializer,
    RoleMinimumSerializer,
)
from management.notifications.notification_handlers import (
    group_obj_change_notification_handler,
    group_principal_change_notification_handler,
)
from management.permissions import GroupAccessPermission
from management.principal.it_service import ITService
from management.principal.model import Principal
from management.principal.proxy import PrincipalProxy
from management.principal.serializer import PrincipalSerializer
from management.principal.view import ADMIN_ONLY_KEY, USERNAME_ONLY_KEY, VALID_BOOLEAN_VALUE
from management.querysets import get_group_queryset, get_role_queryset
from management.role.view import RoleViewSet
from management.utils import validate_and_get_key, validate_group_name, validate_uuid
from rest_framework import mixins, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter
from rest_framework.response import Response

from api.common.pagination import StandardResultsSetPagination
from api.models import Tenant, User
from .insufficient_privileges import InsufficientPrivilegesError
from .service_account_not_found_error import ServiceAccountNotFoundError
from ..authorization.token_validator import ITSSOTokenValidator, InvalidTokenError, MissingAuthorizationError
from ..authorization.token_validator import UnableMeetPrerequisitesError
from ..principal.unexpected_status_code_from_it import UnexpectedStatusCodeFromITError

USERNAMES_KEY = "usernames"
SERVICE_ACCOUNTS_KEY = "service-accounts"
ROLES_KEY = "roles"
EXCLUDE_KEY = "exclude"
ORDERING_PARAM = "order_by"
PRINCIPAL_TYPE_KEY = "principal_type"
PRINCIPAL_USERNAME_KEY = "principal_username"
VALID_ROLE_ORDER_FIELDS = list(RoleViewSet.ordering_fields)
ROLE_DISCRIMINATOR_KEY = "role_discriminator"
SERVICE_ACCOUNT_USERNAME_FORMAT = "service-account-{clientID}"
TYPE_SERVICE_ACCOUNT = "service-account"
VALID_EXCLUDE_VALUES = ["true", "false"]
VALID_GROUP_ROLE_FILTERS = ["role_name", "role_description", "role_display_name", "role_system"]
VALID_GROUP_PRINCIPAL_FILTERS = ["principal_username"]
VALID_PRINCIPAL_ORDER_FIELDS = ["username"]
VALID_PRINCIPAL_TYPE_VALUE = ["service-account", "user"]
VALID_ROLE_ROLE_DISCRIMINATOR = ["all", "any"]
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class GroupFilter(CommonFilters):
    """Filter for group."""

    def uuid_filter(self, queryset, field, values):
        """Filter for group uuid lookup."""
        uuids = values.split(",")
        for uuid in uuids:
            validate_uuid(uuid, "groups uuid filter")
        return CommonFilters.multiple_values_in(self, queryset, field, values)

    def roles_filter(self, queryset, field, values):
        """Filter for group to lookup list of role name."""
        if not values:
            key = "groups_filter"
            message = "No value of roles provided to filter groups!"
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
        roles_list = [value.lower() for value in values.split(",")]

        discriminator = validate_and_get_key(
            self.request.query_params, ROLE_DISCRIMINATOR_KEY, VALID_ROLE_ROLE_DISCRIMINATOR, "any"
        )

        if discriminator == "any":
            return queryset.filter(policies__roles__name__iregex=r"(" + "|".join(roles_list) + ")")

        for role_name in roles_list:
            queryset = queryset.filter(policies__roles__name__icontains=role_name)
        return queryset

    def principal_filter(self, queryset, field, values):
        """Filter for groups containing principals."""
        if not values:
            key = "groups_filter"
            message = "No principals provided to filter groups!"
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)
        principals = [value.lower() for value in values.split(",")]

        for principal in principals:
            queryset = queryset.filter(principals__username__iexact=principal)

        return queryset

    name = filters.CharFilter(field_name="name", method="name_filter")
    role_names = filters.CharFilter(field_name="role_names", method="roles_filter")
    uuid = filters.CharFilter(field_name="uuid", method="uuid_filter")
    principals = filters.CharFilter(field_name="principals", method="principal_filter")
    system = filters.BooleanFilter(field_name="system")
    platform_default = filters.BooleanFilter(field_name="platform_default")
    admin_default = filters.BooleanFilter(field_name="admin_default")

    class Meta:
        model = Group
        fields = ["name", "role_names", "uuid", "principals"]


class GroupViewSet(
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Group View.

    A viewset that provides default `create()`, `destroy`, `retrieve()`,
    and `list()` actions.

    """

    queryset = Group.objects.annotate(
        principalCount=Count("principals", distinct=True), policyCount=Count("policies", distinct=True)
    )
    permission_classes = (GroupAccessPermission,)
    lookup_field = "uuid"
    filter_backends = (filters.DjangoFilterBackend, OrderingFilter)
    filterset_class = GroupFilter
    ordering_fields = ("name", "modified", "principalCount", "policyCount")
    ordering = ("name",)
    proxy = PrincipalProxy()

    def get_queryset(self):
        """Obtain queryset for requesting user based on access."""
        return get_group_queryset(self.request, self.args, self.kwargs)

    def get_serializer_class(self):
        """Get serializer based on route."""
        if "principals" in self.request.path:
            return GroupPrincipalInputSerializer
        if ROLES_KEY in self.request.path and self.request.method == "GET":
            return GroupRoleSerializerOut
        if ROLES_KEY in self.request.path:
            return GroupRoleSerializerIn
        if self.request.method in ("POST", "PUT"):
            return GroupInputSerializer
        if self.request.path.endswith("groups/") and self.request.method == "GET":
            return GroupInputSerializer
        return GroupSerializer

    def protect_system_groups(self, action):
        """Deny modifications on system groups."""
        group = self.get_object()
        if group.system:
            key = "group"
            message = "{} cannot be performed on system groups.".format(action.upper())
            error = {key: [_(message)]}
            raise serializers.ValidationError(error)

    def protect_default_admin_group_roles(self, group):
        """Disallow default admin access roles from being updated."""
        if group.admin_default:
            error = {"group": [_("Default admin access cannot be modified.")]}
            raise serializers.ValidationError(error)

    def create(self, request, *args, **kwargs):
        """Create a group.

        @api {post} /api/v1/groups/   Create a group
        @apiName createGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Create a Group

        @apiHeader {String} token User authorization token

        @apiParam (Request Body) {String} name Group name
        @apiParamExample {json} Request Body:
            {
                "name": "GroupA"
            }

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 201 CREATED
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA",
                "principals": []
            }
        """
        validate_group_name(request.data.get("name"))
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of groups for the tenant.

        @api {get} /api/v1/groups/   Obtain a list of groups
        @apiName getGroups
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Obtain a list of groups

        @apiHeader {String} token User authorization token

        @apiParam (Query) {String} name Filter by group name.
        @apiParam (Query) {array} uuid Filter by comma separated list of uuids
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
                    'first': /api/v1/groups/?offset=0&limit=10,
                    'next': None,
                    'previous': None,
                    'last': /api/v1/groups/?offset=0&limit=10
                },
                'data': [
                                {
                                    "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                                    "name": "GroupA"
                                },
                                {
                                    "uuid": "20ecdcd0-397c-4ede-8940-f3439bf40212",
                                    "name": "GroupB"
                                }
                            ]
            }

        """
        return super().list(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a group.

        @api {get} /api/v1/groups/:uuid   Get a group
        @apiName getGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Get a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier.

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} principals Array of principals
        @apiSuccess {Array} roles Array of roles
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA",
                "principals": [
                    { "username": "jsmith" }
                ],
                "roles": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15"
                    }
                ]
            }
        """
        validate_uuid(kwargs.get("uuid"), "group uuid validation")
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a group.

        @api {delete} /api/v1/groups/:uuid   Delete a group
        @apiName deleteGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Delete a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} uuid Group unique identifier

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 204 NO CONTENT
        """
        validate_uuid(kwargs.get("uuid"), "group uuid validation")
        self.protect_system_groups("delete")
        group = self.get_object()
        response = super().destroy(request=request, args=args, kwargs=kwargs)
        if response.status_code == status.HTTP_204_NO_CONTENT:
            group_obj_change_notification_handler(request.user, group, "deleted")
        return response

    def update(self, request, *args, **kwargs):
        """Update a group.

        @api {post} /api/v1/groups/:uuid   Update a group
        @apiName updateGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Update a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA"
            }
        """
        validate_uuid(kwargs.get("uuid"), "group uuid validation")
        self.protect_system_groups("update")
        return super().update(request=request, args=args, kwargs=kwargs)

    def add_principals(self, group, principals, account=None, org_id=None):
        """Process list of principals and add them to the group."""
        tenant = self.request.tenant

        users = [principal.get("username") for principal in principals]
        if settings.AUTHENTICATE_WITH_ORG_ID:
            resp = self.proxy.request_filtered_principals(users, org_id=org_id, limit=len(users))
        else:
            resp = self.proxy.request_filtered_principals(users, account=account, limit=len(users))
        if "errors" in resp:
            return resp
        if len(resp.get("data", [])) == 0:
            return {
                "status_code": status.HTTP_404_NOT_FOUND,
                "errors": [{"detail": "User(s) {} not found.".format(users), "status": "404", "source": "principals"}],
            }
        for item in resp.get("data", []):
            username = item["username"]
            try:
                principal = Principal.objects.get(username__iexact=username, tenant=tenant)
            except Principal.DoesNotExist:
                principal = Principal.objects.create(username=username, tenant=tenant)
                if settings.AUTHENTICATE_WITH_ORG_ID:
                    logger.info("Created new principal %s for org_id %s.", username, org_id)
                else:
                    logger.info("Created new principal %s for account_id %s.", username, account)
            group.principals.add(principal)
            group_principal_change_notification_handler(self.request.user, group, username, "added")
        return group

    def add_service_accounts(
        self,
        user: User,
        group: Group,
        bearer_token: str,
        service_acounts: [dict],
        account_name: str = None,
        org_id: str = None,
    ) -> Group:
        """Process the list of service accounts and add them to the group."""
        # Fetch all the user's service accounts from IT. If we are on a development or testing environment, we might
        # want to skip calling IT
        it_service = ITService()
        if not settings.IT_BYPASS_IT_CALLS:
            it_service_accounts = it_service.request_service_accounts(bearer_token=bearer_token)

            # Organize them by their client ID.
            it_service_accounts_by_client_ids: dict[str, dict] = {}
            for it_sa in it_service_accounts:
                it_service_accounts_by_client_ids[it_sa["clientID"]] = it_sa

            # Make sure that the service accounts the user specified are visible by them.
            it_sa_client_ids = it_service_accounts_by_client_ids.keys()
            invalid_service_accounts: set = set()
            for specified_sa in service_acounts:
                if specified_sa["clientID"] not in it_sa_client_ids:
                    invalid_service_accounts.add(specified_sa["clientID"])

            # If we have any invalid service accounts, notify the user.
            if len(invalid_service_accounts) > 0:
                raise ServiceAccountNotFoundError(f"Service account(s) {invalid_service_accounts} not found.")

        # Get the tenant in order to fetch or store the service account in the database.
        tenant: Tenant = self.request.tenant

        # Fetch the service account from our database to add it to the group. If it doesn't exist, we create
        # it.
        for specified_sa in service_acounts:
            self.user_has_permission_act_on_service_account(user=user, service_account=specified_sa)

            client_id = specified_sa["clientID"]
            try:
                principal = Principal.objects.get(
                    username__iexact=SERVICE_ACCOUNT_USERNAME_FORMAT.format(clientID=client_id),
                    tenant=tenant,
                )
            except Principal.DoesNotExist:
                principal = Principal.objects.create(
                    username=SERVICE_ACCOUNT_USERNAME_FORMAT.format(clientID=client_id),
                    service_account_id=client_id,
                    type=TYPE_SERVICE_ACCOUNT,
                    tenant=tenant,
                )

                if settings.AUTHENTICATE_WITH_ORG_ID:
                    logger.info("Created new service account %s for org_id %s.", client_id, org_id)
                else:
                    logger.info("Created new principal %s for account_id %s.", client_id, account_name)

            group.principals.add(principal)
            group_principal_change_notification_handler(
                self.request.user,
                group,
                SERVICE_ACCOUNT_USERNAME_FORMAT.format(clientID=client_id),
                "added",
            )

        return group

    def remove_principals(self, group, principals, account=None, org_id=None):
        """Process list of principals and remove them from the group."""
        req_id = getattr(self.request, "req_id", None)
        log_prefix = f"[Request_id:{req_id}]"
        logger.info(f"{log_prefix} remove_principals({principals}),Group:{group.name},OrgId:{org_id},Acct:{account}")

        if settings.AUTHENTICATE_WITH_ORG_ID:
            tenant = Tenant.objects.get(org_id=org_id)
        else:
            tenant = Tenant.objects.get(tenant_name=f"acct{account}")

        valid_principals = Principal.objects.filter(group=group, tenant=tenant, type="user", username__in=principals)
        valid_usernames = valid_principals.values_list("username", flat=True)
        usernames_diff = set(principals) - set(valid_usernames)
        if usernames_diff:
            if settings.AUTHENTICATE_WITH_ORG_ID:
                logger.info(f"Principals {usernames_diff} not found for org id {org_id}.")
            else:
                logger.info(f"Principals {usernames_diff} not found for account {account}.")
            return {
                "status_code": status.HTTP_404_NOT_FOUND,
                "errors": [
                    {
                        "detail": f"User(s) {usernames_diff} not found in the group '{group.name}'.",
                        "status": status.HTTP_404_NOT_FOUND,
                        "source": "principals",
                    }
                ],
            }

        with transaction.atomic():
            for principal in valid_principals:
                group.principals.remove(principal)

        logger.info(f"[Request_id:{req_id}] {valid_usernames} removed from group {group.name} for org id {org_id}.")
        for username in principals:
            group_principal_change_notification_handler(self.request.user, group, username, "removed")
        return group

    @action(detail=True, methods=["get", "post", "delete"])
    def principals(self, request, uuid=None):
        """Get, add or remove principals from a group."""
        """
        @api {get} /api/v1/groups/:uuid/principals/    Get principals for a group
        @apiName getPrincipals
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Get principals for a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier
        @apiParam (Query) {String} principal_type Parameter for selecting the type of principal to be returned (either
                                                  "service-account" or "user").

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} principals Array of principals
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "principals": [
                    { "username": "jsmith" }
                ]
            }
        """
        """
        @api {post} /api/v1/groups/:uuid/principals/   Add principals to a group
        @apiName addPrincipals
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Add principals to a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiParam (Request Body) {String} username Principal username
        @apiParamExample {json} Request Body:
            {
                "principals": [
                    {
                        "username": "jsmith"
                    },
                    {
                        "username": "ksmith"
                    }
                ]
            }

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} principals Array of principals
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA",
                "principals": [
                    { "username": "jsmith" }
                ]
            }
        """
        """
        @api {delete} /api/v1/groups/:uuid/principals/   Remove principals from group
        @apiName removePrincipals
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Remove principals from a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiParam (Query) {String} usernames List of comma separated principal usernames

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 204 NO CONTENT
        """
        validate_uuid(uuid, "group uuid validation")
        group = self.get_object()
        account = self.request.user.account
        org_id = self.request.user.org_id
        if request.method == "POST":
            self.protect_system_groups("add principals")
            if not request.user.admin:
                for role in group.roles_with_access():
                    for access in role.access.all():
                        if access.permission_application() == "rbac":
                            key = "add_principals"
                            message = "Non-admin users may not add principals to Groups with RBAC permissions."
                            raise serializers.ValidationError({key: _(message)})
            serializer = GroupPrincipalInputSerializer(data=request.data)

            # Serialize the payload and validate that it is correct.
            user_specified_principals = []
            if serializer.is_valid(raise_exception=True):
                user_specified_principals = serializer.data.pop("principals")

            # Extract the principals and the service accounts from the user's payload.
            principals = []
            service_accounts = []
            for specified_principal in user_specified_principals:
                if ("type" in specified_principal) and (specified_principal["type"] == "service-account"):
                    service_accounts.append(specified_principal)
                else:
                    principals.append(specified_principal)

            # Process the service accounts and add them to the group.
            if len(service_accounts) > 0:
                bearer_token: str = None
                try:
                    # Attempt validating the JWT token.
                    token_validator = ITSSOTokenValidator()
                    bearer_token = token_validator.validate_token(request=request)
                except MissingAuthorizationError:
                    return Response(
                        status=status.HTTP_401_UNAUTHORIZED,
                        data={
                            "errors": [
                                {
                                    "detail": "The authorization header is required for fetching service accounts.",
                                    "source": "groups",
                                    "status": str(status.HTTP_401_UNAUTHORIZED),
                                }
                            ]
                        },
                    )
                except InvalidTokenError:
                    return Response(
                        status=status.HTTP_401_UNAUTHORIZED,
                        data={
                            "errors": [
                                {
                                    "detail": "Invalid token provided.",
                                    "source": "groups",
                                    "status": str(status.HTTP_401_UNAUTHORIZED),
                                }
                            ]
                        },
                    )
                except UnableMeetPrerequisitesError:
                    return Response(
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        data={
                            "errors": [
                                {
                                    "detail": "Unable to validate token.",
                                    "source": "groups",
                                    "status": str(status.HTTP_500_INTERNAL_SERVER_ERROR),
                                }
                            ]
                        },
                    )

                try:
                    resp = self.add_service_accounts(
                        user=request.user,
                        group=group,
                        service_acounts=service_accounts,
                        bearer_token=bearer_token,
                        account_name=account,
                        org_id=org_id,
                    )
                except InsufficientPrivilegesError as ipe:
                    return Response(
                        status=status.HTTP_403_FORBIDDEN,
                        data={
                            "errors": [{"detail": str(ipe), "status": status.HTTP_403_FORBIDDEN, "source": "groups"}]
                        },
                    )
                except ServiceAccountNotFoundError as sanfe:
                    return Response(
                        status=status.HTTP_400_BAD_REQUEST,
                        data={
                            "errors": [
                                {"detail": str(sanfe), "source": "group", "status": str(status.HTTP_400_BAD_REQUEST)}
                            ]
                        },
                    )

            # Process user principals and add them to the group.
            if len(principals) > 0:
                if settings.AUTHENTICATE_WITH_ORG_ID:
                    resp = self.add_principals(group, principals, org_id=org_id)
                else:
                    resp = self.add_principals(group, principals, account=account)

            # Storing user principals might return an error structure instead of a group,
            # so we need to check that before returning a response.
            if isinstance(resp, dict) and "errors" in resp:
                return Response(status=resp["status_code"], data=resp["errors"])

            # Serialize the group...
            output = GroupSerializer(resp)

            # ... and return it.
            response = Response(status=status.HTTP_200_OK, data=output.data)
        elif request.method == "GET":
            # Get the "order_by" query parameter.
            all_valid_fields = VALID_PRINCIPAL_ORDER_FIELDS + ["-" + field for field in VALID_PRINCIPAL_ORDER_FIELDS]
            sort_order = None
            if request.query_params.get(ORDERING_PARAM):
                sort_field = validate_and_get_key(request.query_params, ORDERING_PARAM, all_valid_fields, "username")
                sort_order = "des" if sort_field == "-username" else "asc"

            # Get the "username_only" query parameter.
            username_only = validate_and_get_key(
                request.query_params, USERNAME_ONLY_KEY, VALID_BOOLEAN_VALUE, "false", required=False
            )

            # Build the options dict.
            options: dict = {"sort_order": sort_order, "username_only": username_only}

            # Attempt validating and obtaining the "principal type" query
            # parameter. It is important because we need to call BOP for
            # the users, and IT for the service accounts.
            principalType = validate_and_get_key(
                request.query_params, PRINCIPAL_TYPE_KEY, VALID_PRINCIPAL_TYPE_VALUE, required=False
            )

            # Store the principal type in the options dict.
            options[PRINCIPAL_TYPE_KEY] = principalType

            # Make sure we return early for service accounts.
            if principalType == "service-account":
                bearer_token: str = None
                try:
                    # Attempt validating the JWT token.
                    token_validator = ITSSOTokenValidator()
                    bearer_token = token_validator.validate_token(request=request)
                except MissingAuthorizationError:
                    return Response(
                        status=status.HTTP_401_UNAUTHORIZED,
                        data={
                            "errors": [
                                {
                                    "detail": "The authorization header is required for fetching service accounts.",
                                    "source": "groups",
                                    "status": str(status.HTTP_401_UNAUTHORIZED),
                                }
                            ]
                        },
                    )
                except InvalidTokenError:
                    return Response(
                        status=status.HTTP_401_UNAUTHORIZED,
                        data={
                            "errors": [
                                {
                                    "detail": "Invalid token provided.",
                                    "source": "groups",
                                    "status": str(status.HTTP_401_UNAUTHORIZED),
                                }
                            ]
                        },
                    )
                except UnableMeetPrerequisitesError:
                    return Response(
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        data={
                            "errors": [
                                {
                                    "detail": "Unable to validate token.",
                                    "source": "groups",
                                    "status": str(status.HTTP_500_INTERNAL_SERVER_ERROR),
                                }
                            ]
                        },
                    )

                # Get the principal username option parameter and the limit and offset parameters too.
                options[PRINCIPAL_USERNAME_KEY] = request.query_params.get(PRINCIPAL_USERNAME_KEY)
                options["limit"] = int(request.query_params.get("limit", StandardResultsSetPagination.default_limit))
                options["offset"] = int(request.query_params.get("offset", 0))

                # Fetch the group's service accounts.
                it_service = ITService()
                try:
                    service_accounts = it_service.get_service_accounts_group(
                        group=group, bearer_token=bearer_token, options=options
                    )
                except (requests.exceptions.ConnectionError, UnexpectedStatusCodeFromITError):
                    return Response(
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        data={
                            "errors": [
                                {
                                    "detail": "Unexpected internal error.",
                                    "source": "principals",
                                    "status": str(status.HTTP_500_INTERNAL_SERVER_ERROR),
                                }
                            ]
                        },
                    )

                # Prettify the output payload and return it.
                page = self.paginate_queryset(service_accounts)
                serializer = PrincipalSerializer(page, many=True)

                return self.get_paginated_response(service_accounts)

            principals_from_params = self.filtered_principals(group, request)
            page = self.paginate_queryset(principals_from_params)
            serializer = PrincipalSerializer(page, many=True)
            principal_data = serializer.data
            if principal_data:
                username_list = [principal["username"] for principal in principal_data]
            else:
                username_list = []
            proxy = PrincipalProxy()

            admin_only = validate_and_get_key(request.query_params, ADMIN_ONLY_KEY, VALID_BOOLEAN_VALUE, False, False)
            if admin_only == "true":
                options[ADMIN_ONLY_KEY] = True

            if settings.AUTHENTICATE_WITH_ORG_ID:
                resp = proxy.request_filtered_principals(username_list, org_id=org_id, options=options)
            else:
                resp = proxy.request_filtered_principals(username_list, account=account, options=options)
            if isinstance(resp, dict) and "errors" in resp:
                return Response(status=resp.get("status_code"), data=resp.get("errors"))
            response = self.get_paginated_response(resp.get("data"))
        else:
            self.protect_system_groups("remove principals")

            if SERVICE_ACCOUNTS_KEY not in request.query_params and USERNAMES_KEY not in request.query_params:
                key = "detail"
                message = "Query parameter {} or {} is required.".format(SERVICE_ACCOUNTS_KEY, USERNAMES_KEY)
                raise serializers.ValidationError({key: _(message)})

            # Remove the service accounts from the group.
            if SERVICE_ACCOUNTS_KEY in request.query_params:
                service_accounts_parameter = request.query_params.get(SERVICE_ACCOUNTS_KEY, "")
                service_accounts = [
                    service_account.strip() for service_account in service_accounts_parameter.split(",")
                ]

                try:
                    self.remove_service_accounts(
                        user=request.user,
                        service_accounts=service_accounts,
                        group=group,
                        account_name=account,
                        org_id=org_id,
                    )
                except InsufficientPrivilegesError as ipe:
                    return Response(
                        status=status.HTTP_403_FORBIDDEN,
                        data={
                            "errors": [{"detail": str(ipe), "status": status.HTTP_403_FORBIDDEN, "source": "groups"}]
                        },
                    )
                except ValueError as ve:
                    return Response(
                        status=status.HTTP_404_NOT_FOUND,
                        data={
                            "errors": [
                                {
                                    "detail": str(ve),
                                    "status": status.HTTP_404_NOT_FOUND,
                                    "source": "groups",
                                }
                            ],
                        },
                    )

                return Response(status=status.HTTP_204_NO_CONTENT)

            # Remove the users from the group too.
            if USERNAMES_KEY in request.query_params:
                username = request.query_params.get(USERNAMES_KEY, "")
                principals = [name.strip() for name in username.split(",")]
                if settings.AUTHENTICATE_WITH_ORG_ID:
                    resp = self.remove_principals(group, principals, org_id=org_id)
                else:
                    resp = self.remove_principals(group, principals, account=account)
                if isinstance(resp, dict) and "errors" in resp:
                    return Response(status=resp.get("status_code"), data={"errors": resp.get("errors")})
                response = Response(status=status.HTTP_204_NO_CONTENT)

        return response

    @action(detail=True, methods=["get", "post", "delete"])
    def roles(self, request, uuid=None, principals=None):
        """Get, add or remove roles from a group."""
        """
        @api {get} /api/v1/groups/:uuid/roles/   Get roles for a group
        @apiName getRoles
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Get roles for a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier.

        @apiParam (Query) {String} order_by Determine ordering of returned roles.

        @apiSuccess {Array} data Array of roles
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "data": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15",
                        "description": "RoleA Description",
                        "policyCount: 0,
                        "applications": [],
                        "system": false,
                        "platform_default": false
                    }
                ]
            }
        """
        """
        @api {post} /api/v1/groups/:uuid/roles/   Add roles to a group
        @apiName addRoles
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Add roles to a group
        @apiHeader {String} token User authorization token
        @apiParam (Path) {String} id Group unique identifier
        @apiParam (Request Body) {Array} roles Array of role UUIDs
        @apiParamExample {json} Request Body:
            {
                "roles": [
                    "4df211e0-2d88-49a4-8802-728630224d15"
                ]
            }
        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} roles Array of roles
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "data": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15",
                        "description": "RoleA Description",
                        "policyCount: 0,
                        "applications": [],
                        "system": false,
                        "platform_default": false
                    }
                ]
            }
        """
        """
        @api {delete} /api/v1/groups/:uuid/roles/   Remove roles from group
        @apiName removeRoles
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Remove roles from a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiParam (Query) {String} roles List of comma separated role UUIDs

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 204 NO CONTENT
        """
        roles = []
        validate_uuid(uuid, "group uuid validation")
        group = self.get_object()
        if request.method == "POST":
            self.protect_default_admin_group_roles(group)
            serializer = GroupRoleSerializerIn(data=request.data)
            if serializer.is_valid(raise_exception=True):
                roles = request.data.pop(ROLES_KEY, [])
            group = set_system_flag_before_update(group, request.tenant, request.user)
            add_roles(group, roles, request.tenant, user=request.user)
            response_data = GroupRoleSerializerIn(group)
        elif request.method == "GET":
            serialized_roles = self.obtain_roles(request, group)
            page = self.paginate_queryset(serialized_roles)
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        else:
            self.protect_default_admin_group_roles(group)
            if ROLES_KEY not in request.query_params:
                key = "detail"
                message = "Query parameter {} is required.".format(ROLES_KEY)
                raise serializers.ValidationError({key: _(message)})

            role_ids = request.query_params.get(ROLES_KEY, "").split(",")
            serializer = GroupRoleSerializerIn(data={"roles": role_ids})
            if serializer.is_valid(raise_exception=True):
                group = set_system_flag_before_update(group, request.tenant, request.user)
                remove_roles(group, role_ids, request.tenant, request.user)

            return Response(status=status.HTTP_204_NO_CONTENT)

        return Response(status=status.HTTP_200_OK, data=response_data.data)

    def order_queryset(self, queryset, valid_fields, order_field):
        """Return queryset ordered according to order_by query param."""
        all_valid_fields = valid_fields + ["-" + field for field in valid_fields]
        if order_field in all_valid_fields:
            return queryset.order_by(order_field)
        else:
            key = "detail"
            message = f"{order_field} is not a valid ordering field. Valid values are {all_valid_fields}"
            raise serializers.ValidationError({key: _(message)})

    def filtered_roles(self, roles, request):
        """Return filtered roles for group from query params."""
        role_filters = self.filters_from_params(VALID_GROUP_ROLE_FILTERS, "role", request)
        role_filters = self.add_role_external_tenant_filter(role_filters, request)
        return roles.filter(**role_filters)

    def add_role_external_tenant_filter(self, role_filters, request):
        """Add role external tenant filter if param is on the request."""
        role_external_tenant = request.query_params.get("role_external_tenant")
        if role_external_tenant:
            role_filters["ext_relation__ext_tenant__name__iexact"] = role_external_tenant
        return role_filters

    def filtered_principals(self, group, request):
        """Return filtered user principals for group from query params."""
        principal_filters = self.filters_from_params(VALID_GROUP_PRINCIPAL_FILTERS, "principal", request)
        # Make sure we only return users.
        return group.principals.filter(**principal_filters).filter(type="user")

    def filters_from_params(self, valid_filters, model_name, request):
        """Build filters from group params."""
        filters = {}
        for param_name, param_value in request.query_params.items():
            if param_name in valid_filters:
                attr_filter_name = param_name.replace(f"{model_name}_", "")
                filters[f"{attr_filter_name}__icontains"] = param_value
        return filters

    def obtain_roles(self, request, group):
        """Obtain roles based on request, supports exclusion."""
        exclude = validate_and_get_key(request.query_params, EXCLUDE_KEY, VALID_EXCLUDE_VALUES, "false")

        roles = group.roles_with_access() if exclude == "false" else self.obtain_roles_with_exclusion(request, group)
        filtered_roles = self.filtered_roles(roles, request)
        annotated_roles = filtered_roles.annotate(policyCount=Count("policies", distinct=True))
        # add default order by name
        order_field = "name"
        if ORDERING_PARAM in request.query_params:
            order_field = request.query_params.get(ORDERING_PARAM)
        ordered_roles = self.order_queryset(annotated_roles, VALID_ROLE_ORDER_FIELDS, order_field)
        return [RoleMinimumSerializer(role).data for role in ordered_roles]

    def obtain_roles_with_exclusion(self, request, group):
        """Obtain the queryset for roles based on scope."""
        # Get roles in principal or account scope
        roles = get_role_queryset(request)

        # Exclude the roles in the group
        roles_for_group = group.roles().values("uuid")
        return roles.exclude(uuid__in=roles_for_group)

    def remove_service_accounts(
        self, user: User, group: Group, service_accounts: [str], account_name: str = None, org_id: str = None
    ) -> None:
        """Remove the given service accounts from the tenant."""
        # Log our intention.
        request_id = getattr(self.request, "req_id", None)
        logger.info(
            f"[Request_id: {request_id}] remove_service_accounts({service_accounts}),"
            "Group:{group.name},OrgId:{org_id},Acct:{account_name}"
        )

        # Fetch the tenant from the database.
        if settings.AUTHENTICATE_WITH_ORG_ID:
            tenant = Tenant.objects.get(org_id=org_id)
        else:
            tenant = Tenant.objects.get(tenant_name=f"acct{account_name}")

        # Get the group's service accounts that match the service accounts that the user specified.
        valid_service_accounts = Principal.objects.filter(
            group=group, tenant=tenant, type="service-account", username__in=service_accounts
        )

        # Collect the usernames the user specified.
        valid_usernames = valid_service_accounts.values_list("username", flat=True)

        # If there is a difference in the sets, then we know that the user specified service accounts
        # that did not exist in the database.
        usernames_diff = set(service_accounts).difference(valid_usernames)
        if usernames_diff:
            if settings.AUTHENTICATE_WITH_ORG_ID:
                logger.info(f"Service accounts {usernames_diff} not found for org id {org_id}.")
            else:
                logger.info(f"Service account {usernames_diff} not found for account {account_name}.")

            raise ValueError(f"Service account(s) {usernames_diff} not found in the group '{group.name}'")

        # Remove service accounts from the group.
        with transaction.atomic():
            for service_account in valid_service_accounts:
                group.principals.remove(service_account)

        logger.info(
            f"[Request_id:{request_id}] {valid_usernames} removed from group {group.name} for org id {org_id}."
        )
        for username in service_accounts:
            group_principal_change_notification_handler(self.request.user, group, username, "removed")

    def user_has_permission_act_on_service_account(self, user: User, service_account: dict = {}):
        """Check if the user has permission to create or delete the service account.

        Only org admins, users with the "User Access administrator" or the owner of the service account can create or
        remove service accounts.
        """
        if settings.IT_BYPASS_PERMISSIONS_MODIFY_SERVICE_ACCOUNTS:
            return

        # Is the user an organization administrator?
        is_organization_admin: bool = user.admin

        # Is the user the owner of the service account?
        is_user_owner: bool = False

        owner = service_account.get("owner")
        if owner:
            is_user_owner = user.username == owner

        # Check if the user has the "User Access administrator" permission. Leaving the RAW query here
        username: str = user.username
        query = (
            "SELECT EXISTS ( "
            "SELECT "
            "1 "
            "FROM "
            '"management_principal" AS "mp" '
            "INNER JOIN "
            '"management_group_principals" AS "mgp" ON "mgp"."principal_id" = "mp"."id" '
            "INNER JOIN "
            '"management_policy" AS "mpolicy" ON "mpolicy"."group_id" = "mgp"."group_id" '
            "INNER JOIN "
            '"management_policy_roles" AS "mpr" ON "mpr"."policy_id" = "mpolicy"."id" '
            "INNER JOIN "
            '"management_role" AS "mr" ON "mr"."id" = "mpr"."role_id" '
            "WHERE "
            '"mp"."username" = %s '
            "AND "
            "mr.\"name\" = 'User Access administrator' "
            "LIMIT 1 "
            ') AS "user_has_user_access_administrator_permission"'
        )

        with connection.cursor() as cursor:
            cursor.execute(query, [username])

            row: tuple = cursor.fetchone()

        user_has_user_access_administrator_permission = row[0]

        if (not is_organization_admin) and (not user_has_user_access_administrator_permission) and (not is_user_owner):
            logger.debug(
                f"User {user} was denied altering service account {service_account} due to insufficient privileges."
            )

            raise InsufficientPrivilegesError(
                f"Unable to alter service account {service_account} due to insufficient privileges."
            )
