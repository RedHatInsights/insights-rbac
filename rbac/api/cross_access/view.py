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
from datetime import datetime, timedelta

from django.utils import timezone
from django_filters import rest_framework as filters
from management.models import Role
from management.principal.proxy import PrincipalProxy
from management.utils import validate_and_get_key, validate_limit_and_offset
from rest_framework import mixins, viewsets
from rest_framework.serializers import ValidationError
from tenant_schemas.utils import tenant_context

from api.cross_access.access_control import CrossAccountRequestAccessPermission
from api.cross_access.serializer import CrossAccountRequestDetailSerializer, CrossAccountRequestSerializer
from api.models import CrossAccountRequest, Tenant

QUERY_BY_KEY = "query_by"
ACCOUNT = "target_account"
USER_ID = "user_id"
VALID_QUERY_BY_KEY = [ACCOUNT, USER_ID]
PARAMS_FOR_CREATION = ["target_account", "start_date", "end_date", "roles"]

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

    account = filters.CharFilter(field_name="target_account", method="account_filter")
    approved_only = filters.BooleanFilter(field_name="end_date", method="approved_filter")

    class Meta:
        model = CrossAccountRequest
        fields = ["account", "approved_only"]


class CrossAccountRequestViewSet(
    mixins.CreateModelMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet
):
    """Cross Account Request view set.

    A viewset that provides default `create(), list()` actions.

    """

    permission_classes = (CrossAccountRequestAccessPermission,)
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = CrossAccountRequestFilter

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
        self.validate_and_get_input_for_creation(request.data)

        with tenant_context(Tenant.objects.get(schema_name="public")):
            return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """List cross account requests for account/user_id."""
        validate_limit_and_offset(self.request.query_params)

        result = super().list(request=request, args=args, kwargs=kwargs)
        # The approver's view requires requester's info such as first name, last name, email address.
        if validate_and_get_key(self.request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ACCOUNT) == ACCOUNT:
            return self.replace_user_id_with_info(result)
        return result

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

    def validate_and_get_input_for_creation(self, request_data):
        """Validate the create api input."""
        target_account = request_data.get("target_account")
        start_date = request_data.get("start_date")
        end_date = request_data.get("end_date")
        roles = request_data.get("roles")
        if None in [target_account, start_date, end_date, roles]:
            self.throw_validation_error("cross-account-create", f"{PARAMS_FOR_CREATION} must be all specified.")

        try:
            start_date = datetime.strptime(start_date, "%m/%d/%Y")
            end_date = datetime.strptime(end_date, "%m/%d/%Y")
        except ValueError:
            raise self.throw_validation_error(
                "cross-account-create", f"start_date or end_date does not match format '%m/%d/%Y'."
            )

        if end_date - start_date > timedelta(365):
            raise self.throw_validation_error(
                "cross-account-create", f"Access duration could not be longer than one year."
            )

        with tenant_context(Tenant.objects.get(schema_name="public")):
            for role in roles:
                try:
                    Role.objects.get(display_name=role)
                except Role.DoesNotExist:
                    raise self.throw_validation_error(
                        "cross-account-create", f"Role {role} could not be found in public."
                    )

        request_data["start_date"] = start_date
        request_data["end_date"] = end_date
        request_data["user_id"] = self.request.user.user_id
        request_data["roles"] = [{"display_name": role} for role in roles]
