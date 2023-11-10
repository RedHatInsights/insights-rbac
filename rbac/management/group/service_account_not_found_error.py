"""A custom exception for when the specified service accounts by the user were not found."""


class ServiceAccountNotFoundError(Exception):
    """Raised when the specified service accounts were not found on IT."""

    pass
