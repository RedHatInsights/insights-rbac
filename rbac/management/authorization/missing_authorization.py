"""Exception for stating that the Authorization header is missing or blank."""


class MissingAuthorizationError(Exception):
    """Error for signaling that the authorization is missing or its contents are blank."""

    pass
