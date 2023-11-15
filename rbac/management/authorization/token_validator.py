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

"""A token instrospector class which validates that the given token is valid."""
import logging
import re

import requests
from django.conf import settings
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry, Token
from management.cache import JWKSCache
from rest_framework import status
from rest_framework.request import Request

from .invalid_token import InvalidTokenError
from .missing_authorization import MissingAuthorizationError
from .unable_meet_prerequisites import UnableMeetPrerequisitesError

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

# The audience claim we are expecting to find in the token.
AUDIENCE_CLAIM = "cloud-services"
# The service accounts claim we are expecting to find in the token.
SERVICE_ACCOUNTS_CLAIM = "api.iam.service_accounts"


class ITSSOTokenValidator:
    """JWT token  validator."""

    def __init__(self):
        """Get the OIDC configuration URL."""
        # TODO replace it with:
        it_host = settings.IT_SERVICE_HOST
        it_port = settings.IT_SERVICE_PORT
        self.it_request_timeout_seconds = settings.IT_SERVICE_TIMEOUT_SECONDS
        it_scheme = settings.IT_SERVICE_PROTOCOL_SCHEME

        # it_host = "https://sso.stage.redhat.com"

        # The host contains the URL including the port...
        self.host = f"{it_scheme}://{it_host}:{it_port}/auth/realms/redhat-external"
        # ... but the issuer does not. We need to make this distinction so that when validating the token, the issuer
        # correctly matches.
        self.issuer = f"{it_scheme}://{it_host}/auth/realms/redhat-external"
        self.oidc_configuration_url = f"{self.host}/.well-known/openid-configuration"

    def _get_json_web_keyset(self) -> KeySet:
        jwks_cache = JWKSCache()
        try:
            jwks_certificates_response = jwks_cache.get_jwks_response()
        except Exception as e:
            logger.debug(
                "Fetching the JSON Web Key Set from Redis raised an exception, attempting to fetch the keys from the"
                " OIDC configuration instead. Raised error: ",
                e,
            )

        if jwks_certificates_response:
            logger.debug("JWKS response loaded from cache. Skipped fetching the OIDC configuration.")
        else:
            # Attempt getting IT's OIDC configuration.
            oidc_response = requests.get(url=self.oidc_configuration_url)
            if not status.is_success(oidc_response.status_code):
                logger.error(
                    f"Unable to get the OIDC configuration payload when attempting to validate a JWT token. Response"
                    f" code: {oidc_response.status_code}. Response body: {oidc_response.content}"
                )
                raise UnableMeetPrerequisitesError()

            logger.debug('OIDC configuration fetched from "%s"', self.oidc_configuration_url)

            # Attempt getting their public certificates' URL.
            jwks_uri = oidc_response.json()["jwks_uri"]
            if not jwks_uri:
                logger.error(
                    f"Unable to extract the JWKs' URI when attempting to validate a JWT token. Actual payload:"
                    f"{oidc_response.content}"
                )
                raise UnableMeetPrerequisitesError()

            logger.debug('JWKS URI extracted: "%s"', jwks_uri)

            # Attempt getting their public certificates.
            jwks_certificates_response = requests.get(url=jwks_uri)
            if not status.is_success(jwks_certificates_response.status_code):
                logger.error(
                    f"Unable to obtain the JWK certificates when attempting to validate a JWT token. Response code:"
                    f"{jwks_certificates_response.status_code}. Response body: {jwks_certificates_response.content}"
                )
                raise UnableMeetPrerequisitesError()

            logger.debug('JWKS fetched from "%s"', jwks_uri)

            jwks_cache.set_jwks_response(jwks_certificates_response.json())

            logger.debug("JWKS response stored in cache")

            jwks_certificates_response = jwks_certificates_response.json()

        # Import the certificates.
        try:
            return KeySet.import_key_set(jwks_certificates_response)
        except Exception as e:
            logger.error("Unable to import IT's public keys to validate the token: {token:%s}".format(token=str(e)))
            raise UnableMeetPrerequisitesError()

    def validate_token(self, request: Request) -> str:
        """Validate the JWT token issued by Red Hat's SSO.

        Performs validations on the issuer, audience and scope of the token. Raises exceptions if the token is not
        valid. Finally, it returns the received Bearer token in order to be able to forward it as is to IT.
        """
        if settings.IT_BYPASS_TOKEN_VALIDATION:
            return "mocked-invalid-bearer-token-because-token-validation-is-disabled"

        bearer_token: str = request.headers.get("Authorization")
        if not bearer_token:
            logger.debug(
                f"Issuing unauthorized response either because the Authorization header is missing, or it's blank."
                f" Request: {request}"
            )
            raise MissingAuthorizationError()

        # Strip the "Bearer" part of the token if it comes with it.
        if bearer_token.startswith("Bearer"):
            bearer_token = re.sub("Bearer\\s+", "", bearer_token)

        # Import the certificates.
        key_set = self._get_json_web_keyset()

        # Decode the token.
        try:
            token: Token = jwt.decode(value=bearer_token, key=key_set)
        except Exception:
            raise InvalidTokenError("Unable to decode token")

        # Make sure that the token issuer matches the IT issuer, that the audience is set to the "cloud-services"
        # client, and that the scope contains the "service accounts" claim.
        claim_requests = JWTClaimsRegistry(
            iss={"essential": True, "value": self.issuer},
            aud={"essential": True, "value": AUDIENCE_CLAIM},
        )

        # Make sure that the token is valid.
        try:
            # Manually check for the service accounts claim in the scope claim. We do this because "joserfc" doesn't
            # have a way to specify that we want to focus of one of the multiple scope claims that the token may
            # have.
            scope_claim = token.claims.get("scope")
            if not scope_claim:
                raise ValueError("the provided token does not have the required scope claim")
            elif SERVICE_ACCOUNTS_CLAIM not in scope_claim:
                raise ValueError(f"the provided token does not have the required {SERVICE_ACCOUNTS_CLAIM}")

            # Validate the rest of the claims, including the token expiration which will be validated with the function
            # below.
            claim_requests.validate(token.claims)
        except Exception as e:
            logger.debug('Token "%s" rejected for having invalid claims: %s', token, str(e))
            raise InvalidTokenError("The token's claims are invalid")

        return bearer_token
