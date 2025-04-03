#
# Copyright 2025 Red Hat, Inc.
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

"""Common exception handler class."""
from rest_framework.views import Response
from typing import Any, Dict


class ProblemJsonResponse(Response):
    """Custom problem+json response wrapper."""

    CONTENT_TYPE = "application/problem+json"
    STATUS_MAP = {
        400: {
            "type": "https://console.redhat.com/api/rbac/v2/exceptions/bad-request",
            "title": "Bad Request",
            "detail": "There were validation errors with your request.",
        },
        403: {
            "type": "https://console.redhat.com/api/rbac/v2/exceptions/forbidden",
            "title": "Forbidden",
            "detail": "You do not have permission to perform this action.",
        },
        404: {
            "type": "https://console.redhat.com/api/rbac/v2/exceptions/not-found",
            "title": "Not Found",
            "detail": "Unable to find the resource.",
        },
        "default": {
            "type": "https://console.redhat.com/api/rbac/v2/exceptions/unknown-error",
            "title": "Unknown error",
            "detail": "There was an unknown error with your request.",
        },
    }

    def __init__(self, response: Response):
        """Initialize with a response and call super."""
        status = response.status_code
        errors = response.data if isinstance(response.data, dict) else {}
        body = self.body_from_status(status, errors)
        super().__init__(data=body, status=status, content_type=self.CONTENT_TYPE)

    def body_from_status(self, status: int, errors: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a problem+json body for the response."""
        mapping = self.STATUS_MAP.get(status, self.STATUS_MAP.get("default"))
        return {
            "type": mapping["type"],
            "title": mapping["title"],
            "status": status,
            "detail": mapping["detail"],
            "errors": errors,
        }
