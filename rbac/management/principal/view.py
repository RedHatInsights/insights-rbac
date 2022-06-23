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
from ..permissions.principal_access import PrincipalAccessPermission

USERNAMES_KEY = "usernames"
EMAIL_KEY = "email"
SORTORDER_KEY = "sort_order"
VALID_SORTORDER_VALUE = ["asc", "desc"]
MATCH_CRITERIA_KEY = "match_criteria"
VALID_MATCH_VALUE = ["partial", "exact"]
STATUS_KEY = "status"
VALID_STATUS_VALUE = ["enabled", "disabled", "all"]
ADMIN_ONLY_KEY = "admin_only"
VALID_ADMIN_ONLY_VALUE = ["true", "false"]


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

    permission_classes = (PrincipalAccessPermission,)

    def get(self, request):
        """List principals for account."""
        user = request.user
        path = request.path
        query_params = request.query_params
        default_limit = StandardResultsSetPagination.default_limit
        usernames_filter = ""
        options = {}
        try:
            limit = int(query_params.get("limit", default_limit))
            offset = int(query_params.get("offset", 0))
            options["sort_order"] = validate_and_get_key(query_params, SORTORDER_KEY, VALID_SORTORDER_VALUE, "asc")
            options["status"] = validate_and_get_key(query_params, STATUS_KEY, VALID_STATUS_VALUE, "enabled")
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

        resp, usernames_filter = self.users_from_proxy(user, query_params, options, limit, offset)

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

    def users_from_proxy(self, user, query_params, options, limit, offset):
        """Format principal request for proxy and return prepped result."""
        proxy = PrincipalProxy()
        usernames = query_params.get(USERNAMES_KEY)
        email = query_params.get(EMAIL_KEY)
        match_criteria = validate_and_get_key(query_params, MATCH_CRITERIA_KEY, VALID_MATCH_VALUE, "exact")

        if not usernames and not email:
            options["admin_only"] = validate_and_get_key(query_params, ADMIN_ONLY_KEY, VALID_ADMIN_ONLY_VALUE, "false")
            resp = proxy.request_principals(
                account=user.account, org_id=user.org_id, limit=limit, offset=offset, options=options
            )
            return resp, ""
        proxyInput = {}
        resp = None
        if usernames:
            principals = usernames.split(",")
            if match_criteria != "partial":
                resp = proxy.request_filtered_principals(
                    principals,
                    account=user.account,
                    org_id=user.org_id,
                    limit=limit,
                    offset=offset,
                    options={"sort_order": options["sort_order"]},
                )
                usernames_filter = f"&usernames={usernames}"
                return resp, usernames_filter
            else:
                proxyInput["principalStartsWith"] = principals[0]
        if email:
            if match_criteria == "partial":
                proxyInput["emailStartsWith"] = email
            else:
                proxyInput["primaryEmail"] = email
        resp = proxy.request_principals(
            account=user.account, org_id=user.org_id, input=proxyInput, limit=limit, offset=offset, options=options
        )
        return resp, ""
