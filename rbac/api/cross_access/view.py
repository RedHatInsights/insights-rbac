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
from django.db.models import Q
from django.utils import timezone
from django_filters import rest_framework as filters
from management.models import Role
from management.principal.proxy import PrincipalProxy
from management.utils import validate_and_get_key, validate_limit_and_offset, validate_uuid
from rest_framework import mixins, viewsets
from rest_framework import status as http_status
from rest_framework.filters import OrderingFilter
from rest_framework.response import Response
from rest_framework.serializers import ValidationError
from tenant_schemas.utils import tenant_context

from api.cross_access.access_control import CrossAccountRequestAccessPermission
from api.cross_access.serializer import CrossAccountRequestDetailSerializer, CrossAccountRequestSerializer
from api.cross_access.util import create_cross_principal
from api.models import CrossAccountRequest, Tenant
from api.serializers import create_schema_name

QUERY_BY_KEY = "query_by"
ACCOUNT = "target_account"
USER_ID = "user_id"
VALID_QUERY_BY_KEY = [ACCOUNT, USER_ID]
PARAMS_FOR_CREATION = ["target_account", "start_date", "end_date", "roles"]
VALID_PATCH_FIELDS = ["start_date", "end_date", "roles", "status"]

PROXY = PrincipalProxy()


class CrossAccountRequestFilter(filters.FilterSet):
    """Filter for cross account request."""

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
        with tenant_context(Tenant.objects.get(schema_name="public")):
            self.validate_and_format_input(request.data)
            return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """List cross account requests for account/user_id."""
        validate_limit_and_offset(self.request.query_params)

        result = super().list(request=request, args=args, kwargs=kwargs)
        # The approver's view requires requester's info such as first name, last name, email address.
        if validate_and_get_key(self.request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ACCOUNT) == ACCOUNT:
            return self.replace_user_id_with_info(result)
        return result

    def partial_update(self, request, *args, **kwargs):
        """Patch a cross-account request."""
        validate_uuid(kwargs.get("pk"), "cross-account request uuid validation")
        for field in request.data:
            if field not in VALID_PATCH_FIELDS:
                self.throw_validation_error(
                    "cross-accont partial update",
                    f"Field '{field}' is not supported. Please use one or more of: {VALID_PATCH_FIELDS}",
                )

        with tenant_context(Tenant.objects.get(schema_name="public")):
            current = self.get_object()

            if current.status != "pending":
                self.throw_validation_error("cross-account partial update", "Only pending requests may be updated.")

            self.validate_and_format_input(request.data)

            kwargs["partial"] = True
            response = super().update(request=request, *args, **kwargs)
            if response.status_code and response.status_code is http_status.HTTP_200_OK:
                if request.data.get("status"):
                    self.update_status(current, request.data.get("status"))
                    return Response(CrossAccountRequestDetailSerializer(current).data)
            return response

    def update(self, request, *args, **kwargs):
        """Update a cross-account request."""
        validate_uuid(kwargs.get("pk"), "cross-account request uuid validation")

        with tenant_context(Tenant.objects.get(schema_name="public")):
            current = self.get_object()
            if current.status != "pending":
                self.throw_validation_error("cross-account update", "Only pending requests may be updated.")
            if "target_account" in request.data and str(request.data.get("target_account")) != current.target_account:
                self.throw_validation_error("cross-account-update", "Target account may not be updated.")

            self.validate_and_format_input(request.data)

            response = super().update(request=request, args=args, kwargs=kwargs)
            if response.status_code and response.status_code is http_status.HTTP_200_OK:
                if request.data.get("status"):
                    self.update_status(current, request.data.get("status"))
                    return Response(CrossAccountRequestDetailSerializer(current).data)
            return response

    def retrieve(self, request, *args, **kwargs):
        """Retrive cross account requests by request_id."""
        with tenant_context(Tenant.objects.get(schema_name="public")):
            result = super().retrieve(request=request, args=args, kwargs=kwargs)

        if validate_and_get_key(self.request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ACCOUNT) == ACCOUNT:
            user_id = result.data.pop("user_id")
            principal = PROXY.request_filtered_principals(
                [user_id], account=None, options={"query_by": "user_id", "return_id": True}
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
            user_ids, account=None, options={"query_by": "user_id", "return_id": True}
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

    def validate_and_format_input(self, request_data, partial=False):
        """Validate the create api input."""
        target_account = request_data.get("target_account")

        if target_account:
            try:
                tenant_schema_name = create_schema_name(target_account)
                Tenant.objects.get(schema_name=tenant_schema_name)
            except Tenant.DoesNotExist:
                raise self.throw_validation_error(
                    "cross-account-request", f"Account '{target_account}' does not exist."
                )

        request_data["user_id"] = self.request.user.user_id
        if "roles" in request_data:
            with tenant_context(Tenant.objects.get(schema_name="public")):
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
            create_cross_principal(car.target_account, car.user_id)
        car.save()
