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

"""A token introspector class which validates that the given token is valid."""
import logging
import re
from typing import Tuple

import requests
from django.conf import settings
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry, Token
from api.models import User
from management.cache import JWKSCache
from requests import Response
from rest_framework import status
from rest_framework.request import Request

from .invalid_token import InvalidTokenError
from .missing_authorization import MissingAuthorizationError
from .scope_claims import ScopeClaims
from .unable_meet_prerequisites import UnableMeetPrerequisitesError

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class ITSSOTokenValidator:
    """JWT token  validator."""

    # Instance variable for the class.
    _instance = None

    def __new__(cls, *args, **kwargs):
        """Create a single instance of the class."""
        if cls._instance is None:
            cls._instance = super().__new__(cls, *args, **kwargs)

        return cls._instance

    def __init__(self):
        """Get the OIDC configuration URL."""
        it_host = settings.IT_SERVICE_HOST
        it_port = settings.IT_SERVICE_PORT
        self.it_request_timeout_seconds = settings.IT_SERVICE_TIMEOUT_SECONDS
        it_scheme = settings.IT_SERVICE_PROTOCOL_SCHEME

        # The host contains the URL including the port...
        self.host = f"{it_scheme}://{it_host}:{it_port}/auth/realms/redhat-external"
        # ... but the issuer does not. We need to make this distinction so that when validating the token, the issuer
        # correctly matches.
        self.issuer = f"{it_scheme}://{it_host}/auth/realms/redhat-external"
        self.oidc_configuration_url = f"{self.host}/.well-known/openid-configuration"

        # Initialize the cache dependency.
        self.jwks_cache = JWKSCache()

    def _get_json_web_keyset(self) -> KeySet:
        try:
            jwks_certificates = self.jwks_cache.get_jwks_response()
        except Exception as e:
            jwks_certificates = None
            logger.debug(
                "Fetching the JSON Web Key Set from Redis raised an exception, attempting to fetch the keys from the"
                f" OIDC configuration instead. Raised error: {e}"
            )

        if jwks_certificates:
            logger.debug("JWKS response loaded from cache. Skipped fetching the OIDC configuration.")
        else:
            # Attempt getting IT's OIDC configuration.
            try:
                oidc_response: Response = requests.get(url=self.oidc_configuration_url)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as ce:
                logger.error("Unable to fetch the OIDC configuration to validate the token: %s", ce)

                raise UnableMeetPrerequisitesError("unable to fetch the OIDC configuration to validate the token")

            if not status.is_success(oidc_response.status_code):
                logger.error(
                    f"Unable to get the OIDC configuration payload when attempting to validate a JWT token due to an"
                    f" unexpected status code: {oidc_response.status_code}. Response body:"
                    f" {oidc_response.content.decode()}"
                )
                raise UnableMeetPrerequisitesError(
                    "unexpected status code received from IT when attempting to fetch the OIDC configuration"
                )

            logger.debug('OIDC configuration fetched from "%s"', self.oidc_configuration_url)

            # Attempt getting their public certificates' URL.
            try:
                jwks_uri = oidc_response.json()["jwks_uri"]
            except KeyError:
                logger.error(
                    f"Unable to extract the JWKs' URI when attempting to validate a JWT token. Actual payload:"
                    f" {oidc_response.content.decode()}"
                )
                raise UnableMeetPrerequisitesError('the "jwks_uri" key was not present in the response payload')

            if not jwks_uri:
                logger.error(
                    f"Unable to extract the JWKs' URI when attempting to validate a JWT token. Actual payload:"
                    f" {oidc_response.content.decode()}"
                )
                raise UnableMeetPrerequisitesError('the "jwks_uri" key has an empty value')

            logger.debug('JWKS URI extracted: "%s"', jwks_uri)

            # Attempt getting their public certificates.
            try:
                jwks_certificates_response: Response = requests.get(url=jwks_uri)
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as ce:
                logger.error("unable to fetch the JWKS certificates to validate the token: %s", ce)

                raise UnableMeetPrerequisitesError("unable to fetch the JWKS certificates to validate the token")

            if not status.is_success(jwks_certificates_response.status_code):
                logger.error(
                    "Unable to obtain the JWK certificates when attempting to validate a JWT token. Response code:"
                    f"{jwks_certificates_response.status_code}. Response body:"
                    f" {jwks_certificates_response.content.decode()}"
                )
                raise UnableMeetPrerequisitesError(
                    "unexpected status code received from IT when attempting to fetch the JWKS certificates"
                )

            logger.debug('JWKS fetched from "%s"', jwks_uri)

            # Cache the JWKS contents.
            self.jwks_cache.set_jwks_response(jwks_certificates_response.json())

            logger.debug("JWKS response stored in cache")

            jwks_certificates = jwks_certificates_response.json()

        # Import the certificates.
        try:
            return KeySet.import_key_set(jwks_certificates)
        except Exception as e:
            logger.error(f"Unable to import IT's public keys to validate the token: {e}")
            raise UnableMeetPrerequisitesError("unable to import IT's public keys to validate the token")

    def _validate_token(self, request: Request, additional_scopes_to_validate: set[ScopeClaims]) -> Tuple[str, Token]:
        """Validate the JWT token issued by Red Hat's SSO.

        Performs validations on the issuer, audience and scope of the token. Raises exceptions if the token is not
        valid. Finally, it returns the received Bearer token in order to be able to forward it as is to IT.
        """
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
        key_set: KeySet = self._get_json_web_keyset()

        # Decode the token.
        try:
            token: Token = jwt.decode(value=bearer_token, key=key_set)
        except Exception as e:
            logging.warning("[request_id: %s] Unable to decode token: %s", getattr(request, "req_id", None), str(e))
            raise InvalidTokenError("Unable to decode token")

        # Make sure that the token issuer matches the IT issuer and that the scope contains the "service accounts"
        # claim.
        claim_requests = JWTClaimsRegistry(iss={"essential": True, "value": self.issuer})

        # Make sure that the token is valid.
        try:
            # Manually check for the additional scope claims in the incoming scope claim. We do this because "joserfc"
            # doesn't have a way to specify that we want to focus on some specific claims from the many that the token
            # may have.
            if len(additional_scopes_to_validate) > 0:
                # Make sure that the "scope" claim of the token is not empty.
                scope_claim = token.claims.get("scope")
                if not scope_claim:
                    raise ValueError("the provided does not have any contents in the scope claim")

                # Validate that the additional scopes are present in the token.
                for scope_to_validate in additional_scopes_to_validate:
                    if scope_to_validate not in scope_claim:
                        raise ValueError(
                            f"the provided token does not have the required '{scope_to_validate}' claim in the scope"
                        )

            # Validate the rest of the claims, including the token expiration which will be validated with the function
            # below.
            claim_requests.validate(token.claims)
        except Exception as e:
            logging.warning(
                "[request_id: %s] Token rejected for having invalid claims: %s",
                getattr(request, "req_id", "no-request-id-present"),
                str(e),
            )
            raise InvalidTokenError("The token's claims are invalid")

        return bearer_token, token

    def validate_token(self, request: Request, additional_scopes_to_validate: set[ScopeClaims]) -> str
        """Validate the JWT token issued by Red Hat's SSO.

        Performs validations on the issuer, audience and scope of the token. Raises exceptions if the token is not
        valid. Finally, it returns the received Bearer token in order to be able to forward it as is to IT.
        """
        if settings.IT_BYPASS_TOKEN_VALIDATION:
            return "mocked-invalid-bearer-token-because-token-validation-is-disabled"

        bearer_token, _ = self._validate_token(request, additional_scopes_to_validate)
        return bearer_token

    def get_user_from_bearer_token(self, request: Request) -> User:
        """Validate the JWT token and parse into a User object.
        
        Performs validations on the issuer, audience and scope of the token. Raises exceptions if the token is not
        valid. Finally, it returns the User object corresponding to the token.
        """
        if settings.IT_BYPASS_TOKEN_VALIDATION:
            user = User()
            user.user_id = "mocked-user-id-because-token-validation-is-disabled"
            user.username = "mocked-username-because-token-validation-is-disabled"
            user.org_id = "mocked-org-id-because-token-validation-is-disabled"
            user.account = "mocked-account-number-because-token-validation-is-disabled"
            user.bearer_token = "mocked-invalid-bearer-token-because-token-validation-is-disabled"
            user.admin = False
            return user

        bearer_token, jwt = self._validate_token(request, set())
        
        # Assumes a particular token shape
        # TODO: support multiple based on scope similar to gateway code
        user = User()
        user.user_id = jwt.claims.get("sub")
        user.username = jwt.claims.get("preferred_username")
        user.org_id = jwt.claims.get("organization", {}).get("id", None)
        user.account = jwt.claims.get("organization", {}).get("account_number", None)
        user.admin = "org:admin:all" in jwt.claims.get("roles", [])
        user.bearer_token = bearer_token
        user.client_id = jwt.claims.get("client_id", "")
        # TODO user.is_service_account ?

        return user

