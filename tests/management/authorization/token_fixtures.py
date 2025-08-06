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
"""In-memory JWKSSource and related fixtures for testing token validation."""

from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import Key
from management.authorization.jwks_source import JWKSSource


class InMemoryIssuer(JWKSSource):
    """In-memory JWKSSource for testing purposes."""

    iss = "http://localhost"

    def __init__(self, key: Key):
        """
        Initialize the in-memory JWKSSource with provided key.

        :param key: The key to be used in the JWKS.
        """
        self.key = key

    @staticmethod
    def generate() -> "InMemoryIssuer":
        """Generate keys for an InMemoryJWKSSource."""
        key = ECKey.generate_key(auto_kid=True)
        return InMemoryIssuer(key)

    def fetch_jwks(self) -> dict:
        """Return the JWKS."""
        return {"keys": [self.key.as_dict()]}

    def issue_jwt(self, header: dict, claims: dict, include_defaults: bool = True) -> str:
        """
        Issue a JWT with the given header and claims.

        :param header: The JWT header.
        :param claims: The JWT claims.
        :param include_defaults: Whether to include default values in the header and claims.
                                 This can be useful for testing purposes.
        :return: The signed JWT as a string.
        """
        if include_defaults:
            header.setdefault("alg", "ES256")
            header.setdefault("typ", "JWT")
            claims.setdefault("iss", self.iss)
        return jwt.encode(
            header=header,
            claims=claims,
            key=self.key,
        )
