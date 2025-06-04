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

"""Sources for fetching JSON Web KeySets for validating JWT signatures."""

import logging
from typing import Protocol

import requests
from management.authorization.unable_meet_prerequisites import UnableMeetPrerequisitesError
from management.cache import JWKSCache
from requests import Response
from rest_framework import status

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class JWKSSource(Protocol):
    """Protocol for a source that provides JSON Web Key Sets (JWKS)."""

    def fetch_jwks(self) -> dict:
        """Fetch the JSON Web Key Set (JWKS) from the source."""
        ...


class OIDCConfigurationJWKSSource(JWKSSource):
    """Fetch JWKS from the well-known URL."""

    def __init__(self, url: str):
        """
        Initialize OIDCConfigurationJWKSSource with the given OIDC configuration URL.

        See: https://openid.net/specs/openid-connect-discovery-1_0.html
        """
        self.oidc_configuration_url = url

    def fetch_jwks(self) -> dict:
        """Fetch the JWKS from the well-known URL."""
        # Attempt getting the OIDC configuration.
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

        return jwks_certificates_response.json()


class JWKSCacheSource(JWKSSource):
    """Delegates to a JWKSSource and then caches the result using a JWKSCache."""

    def __init__(self, jwks_source: JWKSSource, cache: JWKSCache = JWKSCache()):
        """
        Initialize JWKSCacheSource with a JWKSSource and a JWKSCache.

        The source is used for actually fetching the JWKS when there is a cache miss.
        Otherwise, the cache is used.
        """
        self.jwks_source = jwks_source
        self.jwks_cache = cache

    def fetch_jwks(self) -> dict:
        """Retrieve the cached JWKS, or fetch the JWKS from the source and cache it."""
        try:
            jwks_certificates = self.jwks_cache.get_jwks_response()
        except Exception as e:
            jwks_certificates = None
            logger.debug(
                "Fetching the JSON Web Key Set from Redis raised an exception, attempting to fetch the keys from the"
                f" OIDC configuration instead. Raised error: {e}"
            )

        if jwks_certificates:
            logger.debug("JWKS response loaded from cache. Skipped fetching the source configuration.")
        else:
            jwks_certificates = self.jwks_source.fetch_jwks()

        return jwks_certificates
