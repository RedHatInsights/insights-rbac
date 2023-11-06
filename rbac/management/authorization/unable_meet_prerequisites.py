"""Exception for when the prerequisites could not be met in order to validate the given JWT token."""


class UnableMeetPrerequisitesError(Exception):
    """Exception to signal that the prerequisites to validate the token were not met."""

    pass
