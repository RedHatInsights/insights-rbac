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
"""Classes to handle JWT token generation and management."""
import http.client
import json
import logging

from django.conf import settings

from rbac.env import ENVIRONMENT

client_id = ENVIRONMENT.get_value("RELATION_API_CLIENT_ID", default="")
client_secret = ENVIRONMENT.get_value("RELATION_API_CLIENT_SECRET", default="")

logger = logging.getLogger(__name__)


class JWTProvider:
    """Class to handle creation of JWT token."""

    # Instance variable for the class.
    _instance = None

    def __new__(cls, *args, **kwargs):
        """Create a single instance of the class."""
        if cls._instance is None:
            cls._instance = super().__new__(cls, *args, **kwargs)

        return cls._instance

    def __init__(self):
        """Establish SSO connection information."""
        self.conn = None

    def get_conn(self):
        """Get connection to sso stage."""
        if settings.REDHAT_STAGE_SSO is not None:
            self.conn = http.client.HTTPSConnection(settings.REDHAT_STAGE_SSO)
        return self.conn

    def get_jwt_token(self, client_id, client_secret):
        """Retrieve jwt token from Redhat SSO."""
        conn = self.get_conn()

        # Test the connection
        if conn is None:
            return None

        if client_id is None or client_secret is None:
            raise Exception("Missing client_id or client_secret in environment file.")

        payload = (
            f"grant_type={settings.TOKEN_GRANT_TYPE}&"
            f"client_id={client_id}&"
            f"client_secret={client_secret}&"
            f"scope={settings.SCOPE}"
        )

        headers = {"content-type": "application/x-www-form-urlencoded"}

        conn.request("POST", settings.OPENID_URL, payload, headers)

        res = conn.getresponse()
        data = res.read()
        json_data = json.loads(data)

        token = json_data["access_token"]
        return token


class JWTManager:
    """Class to handle management of JWT tokens."""

    def __init__(self, jwt_provider, jwt_cache):
        """Establish connection to JWT cache and provider."""
        self.JWT_Cache = jwt_cache
        self.JWT_Provider = jwt_provider

    def get_jwt_from_redis(self):
        """Retrieve jwt token from redis or generate from Redhat SSO if not exists in redis."""
        try:
            # Try retrieve token from redis
            token = self.JWT_Cache.get_jwt_response()

            # If token not is redis
            if not token:
                token = self.JWT_Provider.get_jwt_token(client_id, client_secret)
                # Token obtained store it in redis
                if token:
                    self.JWT_Cache.set_jwt_response(token)
                    logger.info("Token stored in redis.")
                else:
                    logger.error("Failed to store jwt token in redis.")
            else:
                # Token exists return it
                logger.info("Token retrieved from redis.")
            return token

        except Exception as e:
            logger.error(f"error occurred when trying to retrieve JWT token. {e}")
            return None
