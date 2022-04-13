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

from django.conf import settings
from django.http import Http404, HttpResponse
from django.urls import resolve
from django.utils.deprecation import MiddlewareMixin
from management.cache import TenantCache
from management.models import Principal
from management.utils import APPLICATION_KEY, access_for_principal, validate_psk
from prometheus_client import Counter

from api.common import (
    RH_IDENTITY_HEADER,
    RH_INSIGHTS_REQUEST_ID,
    RH_RBAC_ACCOUNT,
    RH_RBAC_CLIENT_ID,
    RH_RBAC_ORG_ID,
    RH_RBAC_PSK,
)
from api.models import Tenant, User
from api.serializers import create_tenant_name, extract_header


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
req_sys_counter = Counter(
    "rbac_req_type_total",
    "Tracks a count of requests to RBAC tracking those made on behalf of the system or a princpal.",
    ["behalf", "method", "view", "status"],
)
TENANTS = TenantCache()


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


class IdentityHeaderMiddleware(MiddlewareMixin):
    """A subclass of RemoteUserMiddleware.

    Processes the provided identity found on the request.
    """

    header = RH_IDENTITY_HEADER

    def get_tenant(self, model, hostname, request):
        """Override the tenant selection logic."""
        if settings.AUTHENTICATE_WITH_ORG_ID:
            tenant_name = create_tenant_name(request.user.account)
            tenant = TENANTS.get_tenant(request.user.org_id)
            if tenant is None:
                if request.user.system:
                    try:
                        tenant = Tenant.objects.get(org_id=request.user.org_id)
                    except Tenant.DoesNotExist:
                        raise Http404()
                else:
                    tenant, created = Tenant.objects.get_or_create(
                        tenant_name=tenant_name,
                        defaults={"ready": True, "account_id": request.user.account, "org_id": request.user.org_id},
                    )
                TENANTS.save_tenant(tenant)
        else:
            tenant_name = create_tenant_name(request.user.account)
            tenant = TENANTS.get_tenant(tenant_name)
            if tenant is None:
                if request.user.system:
                    try:
                        tenant = Tenant.objects.get(tenant_name=tenant_name)
                    except Tenant.DoesNotExist:
                        raise Http404()
                else:
                    tenant, created = Tenant.objects.get_or_create(
                        tenant_name=tenant_name,
                        defaults={"ready": True, "account_id": request.user.account, "org_id": request.user.org_id},
                    )
                TENANTS.save_tenant(tenant)
        return tenant

    @staticmethod  # noqa: C901
    def _get_access_for_user(username, tenant):  # pylint: disable=too-many-locals,too-many-branches
        """Obtain access data for given username.

        Stubbed out to begin removal of RBAC on RBAC, with minimal disruption
        """
        principal = None
        access_list = None

        access = {
            "group": {"read": [], "write": []},
            "role": {"read": [], "write": []},
            "policy": {"read": [], "write": []},
            "principal": {"read": [], "write": []},
            "permission": {"read": [], "write": []},
        }

        try:  # pylint: disable=R1702
            principal = Principal.objects.get(username__iexact=username, tenant=tenant)
            kwargs = {APPLICATION_KEY: "rbac"}
            access_list = access_for_principal(principal, tenant, **kwargs)
            for access_item in access_list:  # pylint: disable=too-many-nested-blocks
                resource_type = access_item.permission.resource_type
                operation = access_item.permission.verb
                res_list = []
                if operation == "*":
                    operation = "write"
                res_list = ["*"]
                if resource_type == "*":
                    for resource in ("group", "role", "policy", "principal", "permission"):
                        if (
                            resource in access.keys()
                            and operation in access.get(resource, {}).keys()  # noqa: W504
                            and isinstance(access.get(resource, {}).get(operation), list)  # noqa: W504
                        ):  # noqa: E127
                            access[resource][operation] += res_list
                            if operation == "write":
                                access[resource]["read"] += res_list
                elif (
                    resource_type in access.keys()
                    and operation in access.get(resource_type, {}).keys()  # noqa: W504
                    and isinstance(access.get(resource_type, {}).get(operation), list)  # noqa: W504
                ):
                    access[resource_type][operation] += res_list
                    if operation == "write":
                        access[resource_type]["read"] += res_list
                for res_type, res_ops_obj in access.items():
                    for op_type, op_list in res_ops_obj.items():
                        if "*" in op_list:
                            access[res_type][op_type] = ["*"]
        except Principal.DoesNotExist:
            return access

        return access

    def process_request(self, request):  # pylint: disable=R1710
        """Process request for identity middleware.

        Args:
            request (object): The request object

        """
        # Get request ID
        request.req_id = request.META.get(RH_INSIGHTS_REQUEST_ID)

        if any([request.path.startswith(prefix) for prefix in settings.INTERNAL_API_PATH_PREFIXES]):
            # This request is for a private API endpoint
            return

        if is_no_auth(request):
            return
        user = User()
        try:
            _, json_rh_auth = extract_header(request, self.header)
            user.account = json_rh_auth.get("identity", {})["account_number"]
            user.org_id = json_rh_auth.get("identity", {}).get("org_id")
            user_info = json_rh_auth.get("identity", {}).get("user", {})
            user.username = user_info["username"]
            user.admin = user_info.get("is_org_admin")
            user.internal = user_info.get("is_internal")
            user.user_id = user_info.get("user_id")
            user.system = False
            if settings.AUTHENTICATE_WITH_ORG_ID:
                if not user.admin and not (request.path.endswith("/access/") and request.method == "GET"):
                    try:
                        tenant = Tenant.objects.filter(org_id=user.org_id).get()
                    except Tenant.DoesNotExist:
                        request.user = user
                        tenant = self.get_tenant(model=None, hostname=None, request=request)

                    user.access = IdentityHeaderMiddleware._get_access_for_user(user.username, tenant)
            else:
                if not user.admin and not (request.path.endswith("/access/") and request.method == "GET"):
                    try:
                        tenant_name = create_tenant_name(user.account)
                        tenant = Tenant.objects.filter(tenant_name=tenant_name).get()
                    except Tenant.DoesNotExist:
                        request.user = user
                        tenant = self.get_tenant(model=None, hostname=None, request=request)

                    user.access = IdentityHeaderMiddleware._get_access_for_user(user.username, tenant)
            # Cross account request check
            internal = json_rh_auth.get("identity", {}).get("internal", {})
            if internal != {}:
                cross_account = internal.get("cross_access", False)
                if cross_account:
                    if not (user.internal and user_info.get("email").endswith("@redhat.com")):
                        logger.error("Cross accout request permission denied. Requester is not internal user.")
                        return HttpResponseUnauthorizedRequest()
                    user.username = f"{user.account}-{user.user_id}"
        except (KeyError, JSONDecodeError):
            request_psk = request.META.get(RH_RBAC_PSK)
            account = request.META.get(RH_RBAC_ACCOUNT)
            org_id = request.META.get(RH_RBAC_ORG_ID)
            client_id = request.META.get(RH_RBAC_CLIENT_ID)
            has_system_auth_headers = request_psk and account and client_id

            if has_system_auth_headers and validate_psk(request_psk, client_id):
                user.username = client_id
                user.account = account
                user.org_id = org_id
                user.admin = True
                user.system = True
            else:
                logger.error("Could not obtain identity on request.")
                return HttpResponseUnauthorizedRequest()
        except binascii.Error as error:
            logger.error("Could not decode header: %s.", error)
            raise error
        if user.username and (user.account or user.org_id):
            request.user = user
            request.tenant = self.get_tenant(model=None, hostname=None, request=request)

    def process_response(self, request, response):  # pylint: disable=no-self-use
        """Process response for identity middleware.

        Args:
            request (object): The request object
            response (object): The response object
        """
        if any([request.path.startswith(prefix) for prefix in settings.INTERNAL_API_PATH_PREFIXES]):
            # This request is for a private API endpoint
            return response

        behalf = "principal"
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

        if is_system:
            behalf = "system"

        req_sys_counter.labels(
            behalf=behalf,
            method=request.method,
            view=resolve(request.path).url_name,
            status=response.get("status_code"),
        ).inc()

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
