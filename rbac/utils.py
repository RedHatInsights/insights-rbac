#
# Copyright 2023 Red Hat, Inc.
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

"""Utilities for RBAC use."""

import logging

logger = logging.getLogger(__name__)


def log_request(request, response, is_internal=False):
    """Process responses for internal identity middleware."""
    query_string = ""
    is_admin = False
    is_system = False
    account = None
    org_id = None
    username = None
    req_id = getattr(request, "req_id", None)
    if request.META.get("QUERY_STRING"):
        query_string = "?{}".format(request.META.get("QUERY_STRING"))

    if hasattr(request, "user") and request.user:
        username = request.user.username
        if username:
            # rbac.api.models.User has these fields
            is_admin = request.user.admin
            account = request.user.account
            org_id = request.user.org_id
            is_system = request.user.system
        else:
            # django.contrib.auth.models.AnonymousUser does not
            is_admin = is_system = False
            account = None
            org_id = None

    # Todo: add some info back to logs
    """
    extras = {}

    if "ecs" in settings.LOGGING_HANDLERS:
        extras = {
            "http": {
                "request": {
                    "body": {"bytes": sys.getsizeof(request.body)},
                    "bytes": sys.getsizeof(request),
                    "method": request.method,
                },
                "response": {
                    "body": {"bytes": sys.getsizeof(response.content)},
                    "bytes": sys.getsizeof(response),
                    "status_code": response.status_code,
                },
            },
            "url": {
                "original": request.path + query_string,
                "path": request.path,
                "query": query_string,
                "port": request.get_port(),
            },
        }
    """

    log_object = {
        "method": request.method,
        "path": request.path + query_string,
        "status": response.status_code,
        "request_id": req_id,
        "account": account,
        "org_id": org_id,
        "username": username,
        "is_admin": is_admin,
        "is_system": is_system,
        "is_internal": is_internal,
    }
    logger.info(log_object)
