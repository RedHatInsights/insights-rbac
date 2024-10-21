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
import requests
from management.authorization.scope_claims import ScopeClaims
from management.authorization.token_validator import ITSSOTokenValidator
from management.utils import validate_and_get_key
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from api.common.pagination import StandardResultsSetPagination
from .it_service import ITService
from .proxy import PrincipalProxy
from .unexpected_status_code_from_it import UnexpectedStatusCodeFromITError
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
VALID_BOOLEAN_VALUE = ["true", "false"]
USERNAME_ONLY_KEY = "username_only"
PRINCIPAL_TYPE_KEY = "type"
VALID_PRINCIPAL_TYPE_VALUE = ["service-account", "user"]


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
    @apiParam (Query) {String} type Parameter for selecting the type of principal to be returned
                                    (either "service-account" or "user").

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
            if limit < 0 or offset < 0:
                raise ValueError
            options["limit"] = limit
            options["offset"] = offset
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
        # Attempt validating and obtaining the "principal type" query
        # parameter.
        principal_type = validate_and_get_key(
            query_params, PRINCIPAL_TYPE_KEY, VALID_PRINCIPAL_TYPE_VALUE, required=False
        )
        options["principal_type"] = principal_type

        # Get either service accounts or user principals, depending on what the user specified.
        if principal_type == "service-account":
            options["email"] = query_params.get(EMAIL_KEY)
            options["match_criteria"] = validate_and_get_key(
                query_params, MATCH_CRITERIA_KEY, VALID_MATCH_VALUE, required=False
            )
            options["username_only"] = validate_and_get_key(
                query_params, USERNAME_ONLY_KEY, VALID_BOOLEAN_VALUE, required=False
            )
            options["usernames"] = query_params.get(USERNAMES_KEY)

            # Fetch the service accounts from IT.
            token_validator = ITSSOTokenValidator()
            user.bearer_token = token_validator.validate_token(
                request=request, additional_scopes_to_validate=set[ScopeClaims]([ScopeClaims.SERVICE_ACCOUNTS_CLAIM])
            )

            try:
                it_service = ITService()
                service_accounts, sa_count = it_service.get_service_accounts(user=user, options=options)
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

            # Adapt the response object to reuse the code below.
            resp = {"status_code": status.HTTP_200_OK, "data": service_accounts}
        else:
            resp, usernames_filter = self.users_from_proxy(user, query_params, options, limit, offset)

        status_code = resp.get("status_code")
        response_data = {}
        if status_code == status.HTTP_200_OK:
            data = resp.get("data", [])
            if principal_type == "service-account":
                count = sa_count
            elif isinstance(data, dict):
                count = data.get("userCount")
                data = data.get("users")
            elif isinstance(data, list):
                count = len(data)
            else:
                count = None
            last_link = int(count) - int(limit) if (int(count) - int(limit)) >= 0 else 0
            response_data["meta"] = {"count": count, "limit": limit, "offset": offset}
            response_data["links"] = {
                "first": f"{path}?limit={limit}&offset=0{usernames_filter}",
                "next": f"{path}?limit={limit}&offset={offset + limit}{usernames_filter}",
                "previous": f"{path}?limit={limit}&offset={previous_offset}{usernames_filter}",
                "last": f"{path}?limit={limit}&offset={last_link}{usernames_filter}",
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
        options["username_only"] = validate_and_get_key(query_params, USERNAME_ONLY_KEY, VALID_BOOLEAN_VALUE, "false")

        if not usernames and not email:
            options["admin_only"] = validate_and_get_key(query_params, ADMIN_ONLY_KEY, VALID_BOOLEAN_VALUE, "false")
            resp = proxy.request_principals(org_id=user.org_id, limit=limit, offset=offset, options=options)
            return resp, ""
        proxyInput = {}
        if usernames:
            principals = usernames.split(",")
            if match_criteria != "partial":
                resp = proxy.request_filtered_principals(
                    principals,
                    org_id=user.org_id,
                    limit=limit,
                    offset=offset,
                    options=options,
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
            org_id=user.org_id, input=proxyInput, limit=limit, offset=offset, options=options
        )
        return resp, ""
