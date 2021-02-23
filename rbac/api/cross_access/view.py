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

import pytz
from django.db.models.query import QuerySet
from django.utils import timezone
from django.utils.translation import gettext as _
from django_filters import rest_framework as filters
from management.models import Principal, Role
from management.principal.proxy import PrincipalProxy
from management.utils import validate_and_get_key, validate_limit_and_offset, validate_uuid
from rest_framework import mixins, serializers, viewsets
from rest_framework.response import Response
from rest_framework.serializers import ValidationError
from tenant_schemas.utils import tenant_context

from api.cross_access.access_control import CrossAccountRequestAccessPermission
from api.cross_access.serializer import CrossAccountRequestDetailSerializer, CrossAccountRequestSerializer
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

    account = filters.CharFilter(field_name="target_account", method="account_filter")
    approved_only = filters.BooleanFilter(field_name="end_date", method="approved_filter")

    class Meta:
        model = CrossAccountRequest
        fields = ["account", "approved_only"]


class CrossAccountRequestViewSet(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet
):
    """Cross Account Request view set.

    A viewset that provides default `create(), list(), and update()` actions.

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

    def partial_update(self, request, *args, **kwargs):
        """Patch a cross-account request."""
        validate_uuid(kwargs.get("pk"), "cross-account request uuid validation")
        payload = request.data
        for field in payload:
            if field not in VALID_PATCH_FIELDS:
                key = "cross-account request"
                message = f"Field '{field}' is not supported. Please use one or more of: {VALID_PATCH_FIELDS}."
                error = {key: [_(message)]}
                raise serializers.ValidationError(error)

        with tenant_context(Tenant.objects.get(schema_name="public")):
            current = self.get_object()
            update_data = {
                "start_date": request.data.get("start_date", current.start_date),
                "end_date": request.data.get("end_date", current.end_date),
                "roles": request.data.get("roles", current.roles.all()),
                "status": request.data.get("status", current.status),
            }
            # Todo: This function is pretty messy, and basically just a rehash of the create version,
            #       can likely clean it up and maybe provide a partial flag
            self.validate_and_get_input_for_update(update_data)

            if current.status == "expired":
                update_data["target_account"] = current.target_account
                if isinstance(update_data.get("roles"), QuerySet):
                    update_data["roles"] = [role.display_name for role in update_data.get("roles")]
                request.data.update(update_data)
                return super().create(request=request, args=args, kwargs=kwargs)

            self.update_cross_account_request(current, update_data)
            return Response(CrossAccountRequestDetailSerializer(current).data)

    def update(self, request, *args, **kwargs):
        """Update a cross-account request."""
        validate_uuid(kwargs.get("pk"), "cross-account request uuid validation")

        with tenant_context(Tenant.objects.get(schema_name="public")):
            current = self.get_object()

            self.validate_and_get_input_for_creation(request.data)

            if current.status == "expired":
                return super().create(request=request, args=args, kwargs=kwargs)

            self.update_cross_account_request(current, request.data)
            return Response(CrossAccountRequestDetailSerializer(current).data)

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

    def update_cross_account_request(self, car, update_data):
        """Update cross-account-request with list of role names."""
        if car.status == "pending" and update_data.get("status").lower() == "approved":
            # create_principal_for_approved_request()
            pass
        for field in update_data:
            if field == "roles":
                car.roles.clear()
                for role in update_data.get("roles"):
                    car.roles.add(Role.objects.get(display_name=role.get("display_name")))
                car.save()
                continue
            setattr(car, field, update_data.get(field))
        car.save()

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
                "cross-account-create", "start_date or end_date does not match format: '%m/%d/%Y'."
            )

        if start_date > (datetime.now() + timedelta(60)):
            raise self.throw_validation_error("cross-account-create", "Start date must be within 60 days of today.")

        if end_date - start_date > timedelta(365):
            raise self.throw_validation_error(
                "cross-account-create", "Access duration may not be longer than one year."
            )

        with tenant_context(Tenant.objects.get(schema_name="public")):
            for role in roles:
                try:
                    Role.objects.get(display_name=role)
                except Role.DoesNotExist:
                    raise self.throw_validation_error("cross-account-create", f"Role '{role}' does not exist.")

        try:
            tenant_schema_name = create_schema_name(target_account)
            Tenant.objects.get(schema_name=tenant_schema_name)
        except Tenant.DoesNotExist:
            raise self.throw_validation_error("cross-account-create", f"Account '{target_account}' does not exist.")

        request_data["start_date"] = start_date
        request_data["end_date"] = end_date
        request_data["user_id"] = self.request.user.user_id
        request_data["roles"] = [{"display_name": role} for role in roles]

    def create_principal(self, target_account, user_id):
        """Create a cross account principal in the target account."""
        # Principal would have the pattern acctxxx-123456.
        principal_name = f"{target_account}-{user_id}"
        tenant_schema = create_schema_name(target_account)
        with tenant_context(Tenant.objects.get(schema_name=tenant_schema)):
            cross_account_principal = Principal.objects.get_or_create(username=principal_name, cross_account=True)

        return cross_account_principal

    def validate_and_get_input_for_update(self, request_data):
        """Validate the update api input."""
        target_account = request_data.get("target_account")
        start_date = request_data.get("start_date")
        end_date = request_data.get("end_date")
        roles = request_data.get("roles")

        try:
            if start_date and isinstance(start_date, str):
                start_date = pytz.utc.localize(datetime.strptime(start_date, "%m/%d/%Y"))
            if end_date and isinstance(end_date, str):
                end_date = pytz.utc.localize(datetime.strptime(end_date, "%m/%d/%Y"))
        except ValueError:
            raise self.throw_validation_error(
                "cross-account-update", "start_date or end_date does not match format: '%m/%d/%Y'."
            )

        if start_date and start_date > pytz.utc.localize(datetime.now() + timedelta(60)):
            raise self.throw_validation_error("cross-account-update", "Start date must be within 60 days of today.")

        if end_date and start_date and (end_date - start_date) > timedelta(365):
            raise self.throw_validation_error(
                "cross-account-update", "Access duration may not be longer than one year."
            )

        if isinstance(roles, QuerySet):
            roles = [role.display_name for role in roles]

        if roles:
            with tenant_context(Tenant.objects.get(schema_name="public")):
                for role in roles:
                    try:
                        Role.objects.get(display_name=role)
                    except Role.DoesNotExist:
                        raise self.throw_validation_error("cross-account-update", f"Role '{role}' does not exist.")

        if target_account:
            try:
                tenant_schema_name = create_schema_name(target_account)
                Tenant.objects.get(schema_name=tenant_schema_name)
            except Tenant.DoesNotExist:
                raise self.throw_validation_error("cross-account-update", f"Account '{target_account}' does not exist.")

        request_data["start_date"] = start_date
        request_data["end_date"] = end_date
        request_data["user_id"] = self.request.user.user_id
        if roles:
            request_data["roles"] = [{"display_name": role} for role in roles]
