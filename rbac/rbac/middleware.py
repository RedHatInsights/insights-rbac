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

from django.db import transaction
from django.db.utils import IntegrityError
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin
from rest_framework.exceptions import ValidationError
from tenant_schemas.middleware import BaseTenantMiddleware
from tenant_schemas.utils import tenant_context

from api.common import (RH_IDENTITY_HEADER,
                        RH_INSIGHTS_REQUEST_ID,
                        RH_RBAC_ACCOUNT,
                        RH_RBAC_CLIENT_ID,
                        RH_RBAC_PSK)
from api.models import Tenant, User
from api.serializers import UserSerializer, create_schema_name, extract_header

from management.group.definer import seed_group  # noqa: I100, I201
from management.models import Principal  # noqa: I100, I201
from management.role.definer import seed_roles
from management.utils import validate_psk


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def is_no_auth(request):
    """Check condition for needing to authenticate the user."""
    no_auth_list = ['status', 'apidoc', 'metrics', 'openapi.json']
    no_auth = any(no_auth_path in request.path for no_auth_path in no_auth_list)
    return no_auth


class HttpResponseUnauthorizedRequest(HttpResponse):
    """A subclass of HttpResponse to return a 401.

    Used if identity header is not sent.
    """

    status_code = 401


class RolesTenantMiddleware(BaseTenantMiddleware):
    """A subclass of the Django-tenant-schemas tenant middleware.

    Determines which schema to use based on the customer's schema
    found from the user tied to a request.
    """

    def process_request(self, request):  # pylint: disable=R1710
        """Check before super."""
        if not is_no_auth(request):
            if hasattr(request, 'user') and hasattr(request.user, 'system') and request.user.system:
                super().process_request(request)
            elif hasattr(request, 'user') and hasattr(request.user, 'username'):
                username = request.user.username
                try:
                    User.objects.get(username=username)
                except User.DoesNotExist:
                    return HttpResponseUnauthorizedRequest()
            else:
                return HttpResponseUnauthorizedRequest()
        super().process_request(request)

    def get_tenant(self, model, hostname, request):
        """Override the tenant selection logic."""
        if request.user.system:
            tenant = model.objects.get(schema_name=create_schema_name(request.user.account))
            return tenant
        schema_name = 'public'
        if not is_no_auth(request):
            user = User.objects.get(username=request.user.username)
            tenant = user.tenant
            schema_name = tenant.schema_name
        try:
            tenant = model.objects.get(schema_name=schema_name)
        except model.DoesNotExist:
            tenant = model(schema_name=schema_name)
            tenant.save()
        return tenant


class IdentityHeaderMiddleware(MiddlewareMixin):  # pylint: disable=R0903
    """A subclass of RemoteUserMiddleware.

    Processes the provided identity found on the request.
    """

    header = RH_IDENTITY_HEADER

    @staticmethod
    def _create_tenant(account):
        """Create a tenant.

        Args:
            account (str): The account identifier

        Returns:
            (Tenant) The created tenant

        """
        schema_name = create_schema_name(account)
        try:
            with transaction.atomic():
                tenant = Tenant(schema_name=schema_name)
                tenant.save()
                logger.info('Created new tenant from account_id %s.', account)
                seed_roles(tenant=tenant, update=False)
                seed_group(tenant=tenant)
        except IntegrityError:
            tenant = Tenant.objects.filter(schema_name=schema_name).get()

        return tenant

    @staticmethod
    def _create_user(username, tenant, request):
        """Create a user for a tenant.

        Args:
            username (str): The username
            tenant (Tenant): The tenant the user is associated with
            request (object): The incoming request

        Returns:
            (User) The created user

        """
        new_user = None
        try:
            with transaction.atomic():
                user_data = {'username': username}
                context = {'request': request}
                serializer = UserSerializer(data=user_data, context=context)
                if serializer.is_valid(raise_exception=True):
                    new_user = serializer.save()

                logger.info('Created new user %s for tenant( %s).',
                            username, tenant.schema_name)
        except (IntegrityError, ValidationError):
            new_user = User.objects.get(username=username)
        return new_user

    @staticmethod  # noqa: C901
    def _get_access_for_user():  # pylint: disable=too-many-locals,too-many-branches
        """Obtain access data for given username.

        Stubbed out to begin removal of RBAC on RBAC, with minimal disruption
        """
        access = {
            'group': {
                'read': [],
                'write': []
            },
            'role': {
                'read': [],
                'write': []
            },
            'policy': {
                'read': [],
                'write': []
            }
        }

        return access

    @staticmethod
    def _system_auth(request):
        request_psk = request.META.get(RH_RBAC_PSK)
        request_account = request.META.get(RH_RBAC_ACCOUNT)
        request_client_id = request.META.get(RH_RBAC_CLIENT_ID)
        has_system_auth_headers = request_psk and request_account and request_client_id

        if has_system_auth_headers and validate_psk(request_psk, request_client_id):
            user = IdentityHeaderMiddleware._system_user()
            user.username = request_client_id
            req_id = request.META.get(RH_INSIGHTS_REQUEST_ID)
            user.account = request_account
            user.admin = True
            user.system = True
            user.req_id = req_id
            request.user = user

            return True

        return False

    @staticmethod
    def _system_user():
        """Return a non-principal based user."""
        return User('', '')

    def process_request(self, request):  # noqa: C901
        """Process request for identity middleware.

        Args:
            request (object): The request object

        """
        if is_no_auth(request):
            request.user = IdentityHeaderMiddleware._system_user()
            return
        try:
            rh_auth_header, json_rh_auth = extract_header(request, self.header)
            username = json_rh_auth.get('identity', {}).get('user', {}).get('username')
            account = json_rh_auth.get('identity', {}).get('account_number')
            is_admin = json_rh_auth.get('identity', {}).get('user', {}).get('is_org_admin')
        except (KeyError, JSONDecodeError):
            if IdentityHeaderMiddleware._system_auth(request):
                return

            logger.error('Could not obtain identity on request.')
            HttpResponseUnauthorizedRequest()
            return
        except binascii.Error as error:
            logger.error('Could not decode header: %s.', error)
            raise error
        if (username and account):
            # Get request ID
            req_id = request.META.get(RH_INSIGHTS_REQUEST_ID)
            # Check for customer creation & user creation
            try:
                schema_name = create_schema_name(account)
                tenant = Tenant.objects.filter(schema_name=schema_name).get()
            except Tenant.DoesNotExist:
                tenant = IdentityHeaderMiddleware._create_tenant(account)

            try:
                user = User.objects.get(username__iexact=username)
            except User.DoesNotExist:
                user = IdentityHeaderMiddleware._create_user(username,
                                                             tenant,
                                                             request)

            with tenant_context(tenant):
                try:
                    Principal.objects.get(username__iexact=username)
                except Principal.DoesNotExist:
                    Principal.objects.create(username=username)
                    logger.info('Created new principal %s for account %s.', username, account)

            user.identity_header = {
                'encoded': rh_auth_header,
                'decoded': json_rh_auth
            }
            user.admin = is_admin
            user.account = account
            user.req_id = req_id
            if not is_admin:
                user.access = IdentityHeaderMiddleware._get_access_for_user()
            request.user = user

    def process_response(self, request, response):  # pylint: disable=no-self-use
        """Process response for identity middleware.

        Args:
            request (object): The request object
            response (object): The response object
        """
        context = ''
        query_string = ''
        is_admin = False
        account = None
        username = None
        req_id = None
        if request.META.get('QUERY_STRING'):
            query_string = '?{}'.format(request.META['QUERY_STRING'])

        if hasattr(request, 'user') and request.user:
            is_admin = f'Admin: {request.user.admin}'
            account = request.user.account
            username = request.user.username
            is_system = f'System: {request.user.system}'
            req_id = request.user.req_id
        if account:
            context = f' -- {req_id} {account} {username} {is_admin} {is_system}'
        logger.info(f'{request.method} {request.path}{query_string}'  # pylint: disable=W1203
                    f' {response.status_code}{context}')
        return response


class DisableCSRF(MiddlewareMixin):  # pylint: disable=too-few-public-methods
    """Middleware to disable CSRF for 3scale usecase."""

    def process_request(self, request):  # pylint: disable=no-self-use
        """Process request for csrf checks.

        Args:
            request (object): The request object

        """
        setattr(request, '_dont_enforce_csrf_checks', True)
