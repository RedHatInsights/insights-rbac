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
