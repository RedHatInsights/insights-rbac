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

"""View for principal management."""
from management.utils import validate_and_get_key
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from api.common.pagination import StandardResultsSetPagination
from .proxy import PrincipalProxy
from ..permissions.admin_access import AdminAccessPermission

USERNAMES_KEY = "usernames"
EMAIL_KEY = "email"
SORTORDER_KEY = "sort_order"
VALID_SORTORDER_VALUE = ["asc", "desc"]
STATUS_KEY = "status"
VALID_STATUS_VALUE = ["enabled", "disabled", "all"]


class PrincipalView(APIView):
    """Obtain the list of principals for the tenant."""

    """
    @api {get} /api/v1/principals/   Obtain a list of principals
    @apiName getPrincipals
    @apiGroup Principal
    @apiVersion 1.0.0
    @apiDescription Obtain a list of principals

    @apiHeader {String} token User authorization token

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
                'first': /api/v1/principals/?offset=0&limit=10,
                'next': None,
                'previous': None,
                'last': None
            },
            'data': [
                            {
                                "username": "jsmith",
                                "email": "jsmith@company.com"
                            },
                            {
                                "username": "ksmith",
                                "email": "ksmith@company.com"
                            }
                        ]
        }

    """

    permission_classes = (AdminAccessPermission,)

    def get(self, request):
        """List principals for account."""
        proxy = PrincipalProxy()
        user = self.request.user
        path = self.request.path
        query_params = self.request.query_params
        default_limit = StandardResultsSetPagination.default_limit
        usernames = None
        usernames_filter = ""
        try:
            limit = int(query_params.get("limit", default_limit))
            offset = int(query_params.get("offset", 0))
            usernames = query_params.get(USERNAMES_KEY)
            email = query_params.get(EMAIL_KEY)
            sort_order = validate_and_get_key(query_params, SORTORDER_KEY, VALID_SORTORDER_VALUE, "asc")
            principal_status = validate_and_get_key(query_params, STATUS_KEY, VALID_STATUS_VALUE, "enabled")
        except ValueError:
            error = {
                "detail": "Values for limit and offset must be positive numbers.",
                "source": "principals",
                "status": str(status.HTTP_400_BAD_REQUEST),
            }
            errors = {"errors": [error]}
            return Response(status=status.HTTP_400_BAD_REQUEST, data=errors)

        previous_offset = 0
        if offset - limit > 0:
            previous_offset = offset - limit
        if usernames:
            principals = usernames.split(",")
            resp = proxy.request_filtered_principals(
                principals, account=user.account, limit=limit, offset=offset, sort_order=sort_order
            )
            usernames_filter = f"&usernames={usernames}"
        elif email:
            resp = proxy.request_principals(
                user.account, email=email, limit=limit, offset=offset, sort_order=sort_order
            )
        else:
            resp = proxy.request_principals(
                user.account, limit=limit, offset=offset, sort_order=sort_order, status=principal_status
            )
        status_code = resp.get("status_code")
        response_data = {}
        if status_code == status.HTTP_200_OK:
            data = resp.get("data", [])
            if isinstance(data, dict):
                count = data.get("userCount")
                data = data.get("users")
            elif isinstance(data, list):
                count = len(data)
            else:
                count = None
            response_data["meta"] = {"count": count}
            response_data["links"] = {
                "first": f"{path}?limit={limit}&offset=0{usernames_filter}",
                "next": f"{path}?limit={limit}&offset={offset + limit}{usernames_filter}",
                "previous": f"{path}?limit={limit}&offset={previous_offset}{usernames_filter}",
                "last": None,
            }
            response_data["data"] = data
        else:
            response_data = resp
            del response_data["status_code"]

        return Response(status=status_code, data=response_data)
