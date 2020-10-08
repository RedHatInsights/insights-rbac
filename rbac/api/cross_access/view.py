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
from django.utils import timezone
from django_filters import rest_framework as filters
from management.principal.proxy import PrincipalProxy
from management.utils import validate_and_get_key, validate_limit_and_offset
from rest_framework import mixins, status, viewsets
from rest_framework.response import Response

from api.cross_access.access_control import CrossAccountRequestAccessPermission
from api.cross_access.model import CrossAccountRequest
from api.cross_access.serializer import CrossAccountRequestSerializer


QUERY_BY_KEY = "query_by"
ACCOUNT = "target_account"
USER_ID = "user_id"
VALID_QUERY_BY_KEY = [ACCOUNT, USER_ID]
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
            return queryset.filter(status="approved").filter(end_date__gt=timezone.now())
        return queryset

    account = filters.CharFilter(field_name="target_account", method="account_filter")
    approved_only = filters.BooleanFilter(field_name="end_date", method="approved_filter")

    class Meta:
        model = CrossAccountRequest
        fields = ["account", "approved_only"]


class CrossAccountRequestViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """Cross Account Request view set.

    A viewset that provides default `list()` actions.

    """

    queryset = CrossAccountRequest.objects.all()
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

    def list(self, request, *args, **kwargs):
        """List cross account requests for account/user_id."""
        errors = validate_limit_and_offset(self.request.query_params)
        if errors:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=errors)

        result = super().list(request=request, args=args, kwargs=kwargs)
        # The approver's view requires requester's info such as first name, last name, email address.
        if validate_and_get_key(self.request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ACCOUNT) == ACCOUNT:
            return self.replace_user_id_with_info(result)
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
