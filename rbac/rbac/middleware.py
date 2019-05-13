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
import logging
from json.decoder import JSONDecodeError

from django.db import transaction
from django.db.utils import IntegrityError
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin
from rest_framework.exceptions import ValidationError
from tenant_schemas.middleware import BaseTenantMiddleware
from tenant_schemas.utils import tenant_context

from api.common import RH_IDENTITY_HEADER, RH_INSIGHTS_REQUEST_ID
from api.models import Tenant, User
from api.serializers import UserSerializer, create_schema_name, extract_header
from management.access.utils import access_for_principal  # noqa: I100, I201
from management.models import Principal  # noqa: I100, I201
from management.role.definer import seed_roles

from rbac.filters import local

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def is_no_auth(request):
    """Check condition for needing to authenticate the user."""
    no_auth_list = ['status', 'apidoc', 'metrics']
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
            if hasattr(request, 'user') and hasattr(request.user, 'username'):
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
    def _get_access_for_user(username, tenant):  # pylint: disable=too-many-locals,too-many-branches
        """Obtain access data for given username."""
        principal = None
        access_list = None
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
        with tenant_context(tenant):
            try:  # pylint: disable=R1702
                principal = Principal.objects.get(username__iexact=username)
                access_list = access_for_principal(principal, 'rbac')
                for access_item in access_list:  # pylint: disable=too-many-nested-blocks
                    perm_list = access_item.permission.split(':')
                    perm_len = len(perm_list)
                    if perm_len != 3:
                        logger.warning('Skipping invalid permission %s', access_item.permission)
                    else:
                        resource_type = perm_list[1]
                        operation = perm_list[2]
                        res_list = []
                        res_defs = access_item.resourceDefinitions
                        if operation == '*':
                            operation = 'write'
                        for res_def in res_defs.all():
                            attr_filter = res_def.attributeFilter
                            if attr_filter.get('operation') == 'equal' and attr_filter.get('value'):
                                res_list.append(attr_filter.get('value'))
                            if attr_filter.get('operation') == 'in' and attr_filter.get('value'):
                                res_list += attr_filter.get('value').split(',')
                        if not res_defs or not res_defs.values():
                            res_list = ['*']
                        if resource_type == '*':
                            for resource in ('group', 'role', 'policy'):
                                if (resource in access.keys() and  # noqa: W504
                                        operation in access.get(resource,
                                                                {}).keys() and  # noqa: W504
                                        isinstance(access.get(resource,
                                                              {}).get(operation), list)):
                                    access[resource][operation] += res_list
                                    if operation == 'write':
                                        access[resource]['read'] += res_list
                        elif (resource_type in access.keys() and  # noqa: W504
                              operation in access.get(resource_type, {}).keys() and  # noqa: W504
                              isinstance(access.get(resource_type, {}).get(operation), list)):
                            access[resource_type][operation] += res_list
                            if operation == 'write':
                                access[resource_type]['read'] += res_list
                    for res_type, res_ops_obj in access.items():
                        for op_type, op_list in res_ops_obj.items():
                            if '*' in op_list:
                                access[res_type][op_type] = ['*']
            except Principal.DoesNotExist:
                return access
        return access

    def process_request(self, request):  # noqa: C901
        """Process request for identity middleware.

        Args:
            request (object): The request object

        """
        if is_no_auth(request):
            request.user = User('', '')
            return
        try:
            rh_auth_header, json_rh_auth = extract_header(request, self.header)
            username = json_rh_auth.get('identity', {}).get('user', {}).get('username')
            account = json_rh_auth.get('identity', {}).get('account_number')
            is_admin = json_rh_auth.get('identity', {}).get('user', {}).get('is_org_admin')
        except (KeyError, JSONDecodeError):
            logger.warning('Could not obtain identity on request.')
            return
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
            if not is_admin:
                user.access = IdentityHeaderMiddleware._get_access_for_user(username, tenant)
            request.user = user
            setattr(local, 'account', account)
            setattr(local, 'username', username)
            setattr(local, 'is_admin', is_admin)
            setattr(local, 'req_id', req_id)


class DisableCSRF(MiddlewareMixin):  # pylint: disable=too-few-public-methods
    """Middleware to disable CSRF for 3scale usecase."""

    def process_request(self, request):  # pylint: disable=no-self-use
        """Process request for csrf checks.

        Args:
            request (object): The request object

        """
        setattr(request, '_dont_enforce_csrf_checks', True)
