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
import json
import logging
from json.decoder import JSONDecodeError

from django.conf import settings
from django.db import IntegrityError
from django.http import Http404, HttpResponse
from django.urls import resolve
from django.utils.deprecation import MiddlewareMixin
from management.cache import TenantCache
from management.models import Principal
from management.utils import APPLICATION_KEY, access_for_principal, validate_psk
from prometheus_client import Counter
from utils import log_request

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


def catch_integrity_error(func):
    """Catch IntegrityErrors that are raised during process_request."""

    def inner(self, request):
        try:
            return func(self, request)
        except IntegrityError as e:
            payload = {
                "code": 400,
                "message": f"IntegrityError while processing request for org_id: {request.user.org_id}",
            }
            logger.error(f"{payload['message']}\n{e.__str__()}")
            return HttpResponse(json.dumps(payload), content_type="application/json", status=400)

    return inner


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
                        org_id=request.user.org_id,
                        defaults={"ready": True, "account_id": request.user.account, "tenant_name": tenant_name},
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

    @catch_integrity_error
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
            user.account = json_rh_auth.get("identity", {}).get("account_number")
            user.org_id = json_rh_auth.get("identity", {}).get("org_id") or json_rh_auth.get("identity").get(
                "internal"
            ).get("org_id")
            user_info = json_rh_auth.get("identity", {}).get("user")
            user.username = user_info["username"]
            user.admin = user_info.get("is_org_admin")
            user.internal = user_info.get("is_internal")
            user.user_id = user_info.get("user_id")
            user.system = False

            if not user.org_id:
                payload = {
                    "code": 400,
                    "message": "An org_id must be provided in the identity header.",
                }
                return HttpResponse(json.dumps(payload), content_type="application/json", status=400)

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
        except (KeyError, TypeError, JSONDecodeError):
            request_psk = request.META.get(RH_RBAC_PSK)
            account = request.META.get(RH_RBAC_ACCOUNT)
            org_id = request.META.get(RH_RBAC_ORG_ID)
            client_id = request.META.get(RH_RBAC_CLIENT_ID)
            if settings.AUTHENTICATE_WITH_ORG_ID:
                has_system_auth_headers = request_psk and org_id and client_id
            else:
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
        is_internal = False
        if any([request.path.startswith(prefix) for prefix in settings.INTERNAL_API_PATH_PREFIXES]):
            # This request is for a private API endpoint
            is_internal = True
            log_request(request, response, is_internal)
            return response

        behalf = "principal"
        is_system = False

        if is_system:
            behalf = "system"

        req_sys_counter.labels(
            behalf=behalf,
            method=request.method,
            view=resolve(request.path).url_name,
            status=response.get("status_code"),
        ).inc()

        log_request(request, response, is_internal)
        return response


class DisableCSRF(MiddlewareMixin):  # pylint: disable=too-few-public-methods
    """Middleware to disable CSRF for 3scale usecase."""

    def process_request(self, request):  # pylint: disable=no-self-use
        """Process request for csrf checks.

        Args:
            request (object): The request object

        """
        setattr(request, "_dont_enforce_csrf_checks", True)
