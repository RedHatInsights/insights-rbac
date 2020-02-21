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

"""Proxy for principal management."""
import logging
import os

import requests
from django.conf import settings
from rest_framework import status

from rbac.env import ENVIRONMENT


LOGGER = logging.getLogger(__name__)
PROTOCOL = 'protocol'
HOST = 'host'
PORT = 'port'
PATH = 'path'
SSL_VERIFY = 'ssl_verify'
SOURCE_CERT = 'source_cert'
USER_ENV = 'env'
CLIENT_ID = 'clientid'
API_TOKEN = 'apitoken'
USER_ENV_HEADER = 'x-rh-insights-env'
CLIENT_ID_HEADER = 'x-rh-clientid'
API_TOKEN_HEADER = 'x-rh-apitoken'


class PrincipalProxy:  # pylint: disable=too-few-public-methods
    """A class to handle interactions with the Principal proxy service."""

    def __init__(self):
        """Establish proxy connection information."""
        proxy_conn_info = self._get_proxy_service()
        self.protocol = proxy_conn_info.get(PROTOCOL)
        self.host = proxy_conn_info.get(HOST)
        self.port = proxy_conn_info.get(PORT)
        self.path = proxy_conn_info.get(PATH)
        self.ssl_verify = proxy_conn_info.get(SSL_VERIFY)
        self.source_cert = proxy_conn_info.get(SOURCE_CERT)
        self.user_env = proxy_conn_info.get(USER_ENV)
        self.client_id = proxy_conn_info.get(CLIENT_ID)
        self.api_token = proxy_conn_info.get(API_TOKEN)
        self.client_cert = os.path.join(settings.BASE_DIR, 'management', 'principal', 'certs', 'client.pem')

    @staticmethod
    def _create_params(limit=None, offset=None):
        """Create query parameters."""
        params = {}
        if limit:
            params['limit'] = limit
        if offset:
            params['offset'] = offset
        return params

    def _process_data(self, data, account, account_filter):
        """Process data for uniform output."""
        processed_data = []
        for item in data:
            if account_filter:
                if account == item.get('account_number'):
                    processed_data.append(self._call_item(item))
            else:
                processed_data.append(self._call_item(item))

        return processed_data

    @staticmethod
    def _call_item(item):
        processed_item = {
            'username': item.get('username'),
            'email': item.get('email'),
            'first_name': item.get('first_name'),
            'last_name': item.get('last_name')
        }
        return processed_item

    def _get_proxy_service(self):  # pylint: disable=no-self-use
        """Get proxy service host and port info from environment."""
        proxy_conn_info = {
            PROTOCOL: ENVIRONMENT.get_value('PRINCIPAL_PROXY_SERVICE_PROTOCOL', default='https'),
            HOST: ENVIRONMENT.get_value('PRINCIPAL_PROXY_SERVICE_HOST', default='localhost'),
            PORT: ENVIRONMENT.get_value('PRINCIPAL_PROXY_SERVICE_PORT', default='443'),
            PATH: ENVIRONMENT.get_value('PRINCIPAL_PROXY_SERVICE_PATH',
                                        default='/r/insights-services'),
            SOURCE_CERT: ENVIRONMENT.bool('PRINCIPAL_PROXY_SERVICE_SOURCE_CERT', default=False),
            SSL_VERIFY: ENVIRONMENT.bool('PRINCIPAL_PROXY_SERVICE_SSL_VERIFY', default=True),
            USER_ENV: ENVIRONMENT.get_value('PRINCIPAL_PROXY_USER_ENV', default='env'),
            CLIENT_ID: ENVIRONMENT.get_value('PRINCIPAL_PROXY_CLIENT_ID', default='client_id'),
            API_TOKEN: ENVIRONMENT.get_value('PRINCIPAL_PROXY_API_TOKEN', default='token')
        }
        return proxy_conn_info

    def _request_principals(self, url, account=None, account_filter=False, method=requests.get, params=None, data=None):
        """Send request to proxy service."""
        headers = {
            USER_ENV_HEADER: self.user_env,
            CLIENT_ID_HEADER: self.client_id,
            API_TOKEN_HEADER: self.api_token
        }
        unexpected_error = {
            'detail': 'Unexpected error.',
            'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
            'source': 'principals'
        }
        try:
            kwargs = {
                'headers': headers,
                'params': params,
                'json': data,
                'verify': self.ssl_verify
            }
            if self.source_cert:
                kwargs['verify'] = self.client_cert
            response = method(url, **kwargs)
        except requests.exceptions.ConnectionError as conn:
            LOGGER.error('Unable to connect for URL %s with error: %s', url, conn)
            resp = {
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'errors': [unexpected_error]
            }
            return resp

        error = None
        resp = {
            'status_code': response.status_code
        }
        if response.status_code == status.HTTP_200_OK:
            """ Testing if account numbers match """
            try:
                data = response.json()
                if isinstance(data, dict):
                    userList = self._process_data(data.get('users'), account, account_filter)
                else:
                    userList = self._process_data(data, account, account_filter)
                resp['data'] = userList
            except ValueError:
                resp['status_code'] = status.HTTP_500_INTERNAL_SERVER_ERROR
                error = unexpected_error
        elif response.status_code == status.HTTP_404_NOT_FOUND:
            error = {
                'detail': 'Not Found.',
                'status': response.status_code,
                'source': 'principals'
            }
        else:
            LOGGER.error('Error calling URL %s -- status=%d', url, response.status_code)
            error = unexpected_error
            error['status'] = response.status_code
        if error:
            resp['errors'] = [error]
        return resp

    def request_principals(self, account, limit=None, offset=None):
        """Request principals for an account."""
        account_principals_path = '/v2/accounts/{}/users'.format(account)

        params = self._create_params(limit=limit, offset=offset)
        url = '{}://{}:{}{}{}'.format(self.protocol,
                                      self.host,
                                      self.port,
                                      self.path,
                                      account_principals_path)

        # For v2 account users endpoints are already filtered by account
        return self._request_principals(url, params=params, account_filter=False)

    def request_filtered_principals(self, principals, account=None, limit=None, offset=None):
        """Request specific principals for an account."""
        if account is None:
            account_filter = False
        else:
            account_filter = True
        if not principals:
            return {'status_code': status.HTTP_200_OK, 'data': []}
        filtered_principals_path = '/v1/users'
        params = self._create_params(limit=limit, offset=offset)
        payload = {
            'users': principals,
            'include_permissions': False
        }
        url = '{}://{}:{}{}{}'.format(self.protocol,
                                      self.host,
                                      self.port,
                                      self.path,
                                      filtered_principals_path)
        return self._request_principals(url,
                                        account=account,
                                        account_filter=account_filter,
                                        method=requests.post,
                                        params=params,
                                        data=payload)
