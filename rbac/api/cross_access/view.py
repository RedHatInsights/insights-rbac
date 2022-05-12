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

"""View for cross access request."""
from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from django_filters import rest_framework as filters
from management.filters import CommonFilters
from management.models import Role
from management.principal.proxy import PrincipalProxy
from management.utils import validate_and_get_key, validate_limit_and_offset, validate_uuid
from rest_framework import mixins, viewsets
from rest_framework import status as http_status
from rest_framework.filters import OrderingFilter
from rest_framework.response import Response
from rest_framework.serializers import ValidationError

from api.cross_access.access_control import CrossAccountRequestAccessPermission
from api.cross_access.serializer import CrossAccountRequestDetailSerializer, CrossAccountRequestSerializer
from api.cross_access.util import create_cross_principal
from api.models import CrossAccountRequest, Tenant
from api.serializers import create_tenant_name

QUERY_BY_KEY = "query_by"
ACCOUNT = "target_account"
ORG_ID = "target_org"
USER_ID = "user_id"
if settings.AUTHENTICATE_WITH_ORG_ID:
    PARAMS_FOR_CREATION = ["target_org", "start_date", "end_date", "roles"]
    VALID_QUERY_BY_KEY = [ORG_ID, USER_ID]
else:
    PARAMS_FOR_CREATION = ["target_account", "start_date", "end_date", "roles"]
    VALID_QUERY_BY_KEY = [ACCOUNT, USER_ID]
VALID_PATCH_FIELDS = ["start_date", "end_date", "roles", "status"]

PROXY = PrincipalProxy()


class CrossAccountRequestFilter(filters.FilterSet):
    """Filter for cross account request."""

    def org_id_filter(self, queryset, field, values):
        """Filter to lookup requests by target_org."""
        return CommonFilters.multiple_values_in(self, queryset, "target_org", values)

    def account_filter(self, queryset, field, values):
        """Filter to lookup requests by target_account."""
        accounts = values.split(",")
        return queryset.filter(target_account__in=accounts)

    def approved_filter(self, queryset, field, value):
        """Filter to lookup requests by status of approved."""
        if value:
            return queryset.filter(status="approved").filter(
                start_date__lt=timezone.now(), end_date__gt=timezone.now()
            )
        return queryset

    def status_filter(self, queryset, field, values):
        """Filter to lookup requests by status(es) in permissions."""
        statuses = values.split(",")
        query = Q()
        for status in statuses:
            query = query | Q(status__iexact=status)
        return queryset.distinct().filter(query)

    account = filters.CharFilter(field_name="target_account", method="account_filter")
    org_id = filters.CharFilter(field_name="target_org", method="org_id_filter")
    approved_only = filters.BooleanFilter(field_name="end_date", method="approved_filter")
    status = filters.CharFilter(field_name="status", method="status_filter")

    class Meta:
        model = CrossAccountRequest
        fields = ["account", "approved_only", "status"]


class CrossAccountRequestViewSet(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Cross Account Request view set.

    A viewset that provides default `create(), list(), and update()` actions.

    """

    permission_classes = (CrossAccountRequestAccessPermission,)
    filter_backends = (filters.DjangoFilterBackend, OrderingFilter)
    filterset_class = CrossAccountRequestFilter
    ordering_fields = ("request_id", "start_date", "end_date", "created", "modified", "status")

    def get_queryset(self):
        """Get query set based on the queryBy key word."""
        if self.request.method in ["PATCH", "PUT"]:
            return CrossAccountRequest.objects.all()

        if settings.AUTHENTICATE_WITH_ORG_ID:
            if validate_and_get_key(self.request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ORG_ID) == ORG_ID:
                return CrossAccountRequest.objects.filter(target_org=self.request.user.org_id)
        else:
            if validate_and_get_key(self.request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ACCOUNT) == ACCOUNT:
                return CrossAccountRequest.objects.filter(target_account=self.request.user.account)

        return CrossAccountRequest.objects.filter(user_id=self.request.user.user_id)

    def get_serializer_class(self):
        """Get serializer based on route."""
        if self.request.path.endswith("cross-account-requests/") and self.request.method == "GET":
            return CrossAccountRequestSerializer
        return CrossAccountRequestDetailSerializer

    def create(self, request, *args, **kwargs):
        """Create cross account requests for associate."""
        self.validate_and_format_input(request.data)
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """List cross account requests for account/user_id."""
        validate_limit_and_offset(self.request.query_params)

        result = super().list(request=request, args=args, kwargs=kwargs)
        # The approver's view requires requester's info such as first name, last name, email address.
        if settings.AUTHENTICATE_WITH_ORG_ID:
            if validate_and_get_key(self.request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ORG_ID) == ORG_ID:
                return self.replace_user_id_with_info(result)
        else:
            if validate_and_get_key(self.request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ACCOUNT) == ACCOUNT:
                return self.replace_user_id_with_info(result)
        return result

    def partial_update(self, request, *args, **kwargs):
        """Patch a cross-account request. Target account admin use it to update status of the request."""
        validate_uuid(kwargs.get("pk"), "cross-account request uuid validation")

        current = self.get_object()
        self.check_patch_permission(request, current)

        self.validate_and_format_patch_input(request.data)

        kwargs["partial"] = True
        response = super().update(request=request, *args, **kwargs)
        if response.status_code and response.status_code is http_status.HTTP_200_OK:
            if request.data.get("status"):
                self.update_status(current, request.data.get("status"))
                return Response(CrossAccountRequestDetailSerializer(current).data)
        return response

    def update(self, request, *args, **kwargs):
        """Update a cross-account request. TAM requestor use it to update their requesters."""
        validate_uuid(kwargs.get("pk"), "cross-account request uuid validation")

        current = self.get_object()
        self.check_update_permission(request, current)
        if settings.AUTHENTICATE_WITH_ORG_ID:
            request.data["target_org"] = current.target_org
        else:
            request.data["target_account"] = current.target_account

        self.validate_and_format_input(request.data)

        response = super().update(request=request, args=args, kwargs=kwargs)
        if response.status_code and response.status_code is http_status.HTTP_200_OK:
            if request.data.get("status"):
                self.update_status(current, request.data.get("status"))
                return Response(CrossAccountRequestDetailSerializer(current).data)
        return response

    def retrieve(self, request, *args, **kwargs):
        """Retrive cross account requests by request_id."""
        result = super().retrieve(request=request, args=args, kwargs=kwargs)

        if settings.AUTHENTICATE_WITH_ORG_ID:
            if validate_and_get_key(self.request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ORG_ID) == ORG_ID:
                user_id = result.data.pop("user_id")
                principal = PROXY.request_filtered_principals(
                    [user_id], account=None, org_id=None, options={"query_by": "user_id", "return_id": True}
                ).get("data")[0]

                # Replace the user_id with user's info
                result.data.update(
                    {
                        "first_name": principal["first_name"],
                        "last_name": principal["last_name"],
                        "email": principal["email"],
                    }
                )
        else:
            if validate_and_get_key(self.request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ACCOUNT) == ACCOUNT:
                user_id = result.data.pop("user_id")
                principal = PROXY.request_filtered_principals(
                    [user_id], account=None, org_id=None, options={"query_by": "user_id", "return_id": True}
                ).get("data")[0]

                # Replace the user_id with user's info
                result.data.update(
                    {
                        "first_name": principal["first_name"],
                        "last_name": principal["last_name"],
                        "email": principal["email"],
                    }
                )
        return result

    def replace_user_id_with_info(self, result):
        """Replace user id with user's info."""
        # Get principals through user_ids from BOP
        user_ids = [element["user_id"] for element in result.data["data"]]
        bop_resp = PROXY.request_filtered_principals(
            user_ids, account=None, org_id=None, options={"query_by": "user_id", "return_id": True}
        )

        # Make a mapping: user_id => principal
        principals = {
            str(principal["user_id"]): {
                "first_name": principal["first_name"],
                "last_name": principal["last_name"],
                "email": principal["email"],
            }
            for principal in bop_resp["data"]
        }

        # Replace the user_id with user's info
        for element in result.data["data"]:
            user_id = element.pop("user_id")
            requestor_info = principals[user_id]
            element.update(requestor_info)

        return result

    def throw_validation_error(self, source, message):
        """Construct a validation error and raise the error."""
        error = {source: [message]}
        raise ValidationError(error)

    def validate_and_format_input(self, request_data):
        """Validate the create api input."""
        for field in PARAMS_FOR_CREATION:
            if not request_data.__contains__(field):
                self.throw_validation_error("cross-account-request", f"Field {field} must be specified.")

        if settings.AUTHENTICATE_WITH_ORG_ID:
            target_org = request_data.get("target_org")
            if target_org == self.request.user.org_id:
                self.throw_validation_error(
                    "cross-account-request", "Creating a cross access request for your own org id is not allowed."
                )

            try:
                Tenant.objects.get(org_id=target_org)
            except Tenant.DoesNotExist:
                raise self.throw_validation_error("cross-account-request", f"Org ID '{target_org}' does not exist.")
        else:
            target_account = request_data.get("target_account")
            if target_account == self.request.user.account:
                self.throw_validation_error(
                    "cross-account-request", "Creating a cross access request for your own account is not allowed."
                )
            try:
                tenant_name = create_tenant_name(target_account)
                Tenant.objects.get(tenant_name=tenant_name)
            except Tenant.DoesNotExist:
                raise self.throw_validation_error(
                    "cross-account-request", f"Account '{target_account}' does not exist."
                )

        request_data["roles"] = self.format_roles(request_data.get("roles"))
        request_data["user_id"] = self.request.user.user_id

    def validate_and_format_patch_input(self, request_data):
        """Validate the create api input."""
        if "roles" in request_data:
            request_data["roles"] = self.format_roles(request_data.get("roles"))

    def format_roles(self, roles):
        """Format role list as expected for cross-account-request."""
        for role_name in roles:
            try:
                role = Role.objects.get(display_name=role_name)
                if not role.system:
                    self.throw_validation_error(
                        "cross-account-request", "Only system roles may be assigned to a cross-account-request."
                    )
            except Role.DoesNotExist:
                raise self.throw_validation_error("cross-account-request", f"Role '{role_name}' does not exist.")

        return [{"display_name": role} for role in roles]

    def update_status(self, car, status):
        """Update the status of a cross-account-request."""
        car.status = status
        if status == "approved":
            create_cross_principal(car.user_id, target_account=car.target_account, target_org=car.target_org)
        car.save()

    def check_patch_permission(self, request, update_obj):
        """Check if user has right to patch cross access request."""
        if (settings.AUTHENTICATE_WITH_ORG_ID and request.user.org_id == update_obj.target_org) or (
            not settings.AUTHENTICATE_WITH_ORG_ID and request.user.account == update_obj.target_account
        ):
            """For approvers updating requests coming to them, only org admins
            may update status from pending/approved/denied to approved/denied.
            """
            if not request.user.admin:
                self.throw_validation_error("cross-account partial update", "Only org admins may update status.")
            if update_obj.status not in ["pending", "approved", "denied"]:
                self.throw_validation_error(
                    "cross-account partial update", "Only pending/approved/denied requests may be updated."
                )
            if request.data.get("status") not in ["approved", "denied"]:
                self.throw_validation_error(
                    "cross-account partial update", "Request status may only be updated to approved/denied."
                )
            if len(request.data.keys()) > 1 or next(iter(request.data)) != "status":
                self.throw_validation_error("cross-account partial update", "Only status may be updated.")
        elif request.user.user_id == update_obj.user_id:
            """For requestors updating their requests, the request status may
            only be updated from pending to cancelled.
            """
            if update_obj.status != "pending" or request.data.get("status") != "cancelled":
                self.throw_validation_error(
                    "cross-account partial update", "Request status may only be updated from pending to cancelled."
                )
            for field in request.data:
                if field not in VALID_PATCH_FIELDS:
                    self.throw_validation_error(
                        "cross-account partial update",
                        f"Field '{field}' is not supported. Please use one or more of: {VALID_PATCH_FIELDS}",
                    )
        else:
            self.throw_validation_error(
                "cross-account partial update", "User does not have permission to update the request."
            )

    def check_update_permission(self, request, update_obj):
        """Check if user has permission to update cross access request."""
        # Only requestors could update the cross access request.
        if request.user.user_id != update_obj.user_id:
            self.throw_validation_error(
                "cross-account update", "Only the requestor may update the cross access request."
            )

        # Only pending request could be updated.
        if update_obj.status != "pending":
            self.throw_validation_error("cross-account update", "Only pending requests may be updated.")

        # Do not allow updating the status:
        if request.data.get("status") and str(request.data.get("status")) != "pending":
            self.throw_validation_error(
                "cross-account update",
                "The status may not be updated through PUT endpoint. "
                "Please use PATCH to update the status of the request.",
            )

        # Do not allow updating the target_account.
        if settings.AUTHENTICATE_WITH_ORG_ID:
            if request.data.get("target_org") and str(request.data.get("target_org")) != update_obj.target_org:
                self.throw_validation_error("cross-account-update", "Target account must stay the same.")
        else:
            if (
                request.data.get("target_account")
                and str(request.data.get("target_account")) != update_obj.target_account
            ):
                self.throw_validation_error("cross-account-update", "Target account must stay the same.")
