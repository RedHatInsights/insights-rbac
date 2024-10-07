"""A custom exception for when the specified service accounts by the user were not found."""


class ServiceAccountNotFoundError(Exception):
    """Raised when the specified service accounts were not found on IT."""

    def __init__(self, message, invalid: set[str]):
        """Create a new instance of the ServiceAccountNotFoundError class."""
        super().__init__(message)
        self.message = message
        self.invalid = invalid
