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

"""Custom RBAC Middleware."""
import binascii
import logging
from json.decoder import JSONDecodeError

from django.db import connections, transaction
from django.http import Http404, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from tenant_schemas.middleware import BaseTenantMiddleware

from api.common import RH_IDENTITY_HEADER, RH_INSIGHTS_REQUEST_ID, RH_RBAC_ACCOUNT, RH_RBAC_CLIENT_ID, RH_RBAC_PSK
from api.models import Tenant, User
from api.serializers import create_schema_name, extract_header

from management.group.definer import seed_group  # noqa: I100, I201
from management.role.definer import seed_permissions, seed_roles
from management.utils import validate_psk


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def is_no_auth(request):
    """Check condition for needing to authenticate the user."""
    no_auth_list = ["status", "apidoc", "metrics", "openapi.json"]
    no_auth = any(no_auth_path in request.path for no_auth_path in no_auth_list)
    return no_auth


class HttpResponseUnauthorizedRequest(HttpResponse):
    """A subclass of HttpResponse to return a 401.

    Used if identity header is not sent.
    """

    status_code = 401


TENANTS = dict()


class IdentityHeaderMiddleware(BaseTenantMiddleware):
    """A subclass of RemoteUserMiddleware.

    Processes the provided identity found on the request.
    """

    header = RH_IDENTITY_HEADER

    def get_tenant(self, model, hostname, request):
        """Override the tenant selection logic."""
        connections["default"].set_schema_to_public()
        if request.user.account not in TENANTS:
            if request.user.system:
                try:
                    tenant = Tenant.objects.get(schema_name=create_schema_name(request.user.account))
                except Tenant.DoesNotExist:
                    raise Http404()
            else:
                with transaction.atomic():
                    tenant, created = Tenant.objects.get_or_create(
                        schema_name=create_schema_name(request.user.account)
                    )
                    if created:
                        seed_permissions(tenant=tenant)
                        seed_roles(tenant=tenant, update=False)
                        seed_group(tenant=tenant)
            TENANTS[request.user.account] = tenant
        return TENANTS[request.user.account]

    def hostname_from_request(self, request):
        """Behold. The tenant_schemas expects to pivot schemas based on hostname. We're not."""
        return ""

    @staticmethod  # noqa: C901
    def _get_access_for_user():  # pylint: disable=too-many-locals,too-many-branches
        """Obtain access data for given username.

        Stubbed out to begin removal of RBAC on RBAC, with minimal disruption
        """
        access = {
            "group": {"read": [], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
        }

        return access

    def process_request(self, request):  # pylint: disable=R1710
        """Process request for identity middleware.

        Args:
            request (object): The request object

        """
        # Get request ID
        request.req_id = request.META.get(RH_INSIGHTS_REQUEST_ID)

        if is_no_auth(request):
            return
        user = User()
        try:
            _, json_rh_auth = extract_header(request, self.header)
            user.username = json_rh_auth.get("identity", {}).get("user", {})["username"]
            user.account = json_rh_auth.get("identity", {})["account_number"]
            user.admin = json_rh_auth.get("identity", {}).get("user", {}).get("is_org_admin")
            user.system = False
            if not user.admin:
                user.access = IdentityHeaderMiddleware._get_access_for_user()
        except (KeyError, JSONDecodeError):
            request_psk = request.META.get(RH_RBAC_PSK)
            account = request.META.get(RH_RBAC_ACCOUNT)
            client_id = request.META.get(RH_RBAC_CLIENT_ID)
            has_system_auth_headers = request_psk and account and client_id

            if has_system_auth_headers and validate_psk(request_psk, client_id):
                user.username = client_id
                user.account = account
                user.admin = True
                user.system = True
            else:
                logger.error("Could not obtain identity on request.")
                return HttpResponseUnauthorizedRequest()
        except binascii.Error as error:
            logger.error("Could not decode header: %s.", error)
            raise error
        if user.username and user.account:
            request.user = user

            super().process_request(request)
            # We are now in the database context of the tenant
            assert request.tenant

    def process_response(self, request, response):  # pylint: disable=no-self-use
        """Process response for identity middleware.

        Args:
            request (object): The request object
            response (object): The response object
        """
        query_string = ""
        is_admin = False
        is_system = False
        account = None
        username = None
        req_id = getattr(request, "req_id", None)
        if request.META.get("QUERY_STRING"):
            query_string = "?{}".format(request.META["QUERY_STRING"])

        if hasattr(request, "user") and request.user:
            username = request.user.username
            if username:
                # rbac.api.models.User has these fields
                is_admin = request.user.admin
                account = request.user.account
                is_system = request.user.system
            else:
                # django.contrib.auth.models.AnonymousUser does not
                is_admin = is_system = False
                account = None

        log_object = {
            "method": request.method,
            "path": request.path + query_string,
            "status": response.status_code,
            "request_id": req_id,
            "account": account,
            "username": username,
            "is_admin": is_admin,
            "is_system": is_system,
        }

        logger.info(log_object)
        return response


class DisableCSRF(MiddlewareMixin):  # pylint: disable=too-few-public-methods
    """Middleware to disable CSRF for 3scale usecase."""

    def process_request(self, request):  # pylint: disable=no-self-use
        """Process request for csrf checks.

        Args:
            request (object): The request object

        """
        setattr(request, "_dont_enforce_csrf_checks", True)
