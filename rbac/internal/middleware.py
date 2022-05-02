#
# Copyright 2020 Red Hat, Inc.
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

"""Custom Internal RBAC Middleware."""
import binascii
import logging
from json.decoder import JSONDecodeError

from django.conf import settings
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404
from django.urls import resolve
from django.utils.deprecation import MiddlewareMixin

from api.common import RH_IDENTITY_HEADER
from api.models import Tenant, User
from api.serializers import extract_header
from rbac.middleware import IdentityHeaderMiddleware


logger = logging.getLogger(__name__)


class InternalIdentityHeaderMiddleware(MiddlewareMixin):
    """Middleware for the internal identity header."""

    header = RH_IDENTITY_HEADER

    def process_request(self, request):
        """Process request for internal identity middleware."""
        if not any([request.path.startswith(prefix) for prefix in settings.INTERNAL_API_PATH_PREFIXES]):
            # We are not in an internal API section
            return
        try:
            _, json_rh_auth = extract_header(request, self.header)
        except (JSONDecodeError, binascii.Error):
            logger.exception("Invalid X-RH-Identity header.")
            return HttpResponseForbidden()

        user = User()
        try:
            if not json_rh_auth["identity"]["type"] == "Associate":
                return HttpResponseForbidden()
            user.username = json_rh_auth["identity"]["associate"]["email"]
            user.admin = True
        except KeyError:
            logger.error("Malformed X-RH-Identity header.")
            return HttpResponseForbidden()

        target = resolve(request.path)
        if target and "integration" in target:
            return IdentityHeaderMiddleware.process_request(self, request)

        request.user = user

    def process_response(self, request, response):
        """Process responses for internal identity middleware."""
        return response

    def get_tenant(self, request):
        """Ensure internal requests carry proper tenant id."""
        request.tenant = get_object_or_404(
            Tenant, tenant_name=self.tenant_re.match(request.path_info).group("tenant_id")
        )
