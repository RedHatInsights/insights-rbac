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

"""Utilities for getting principal ID for Kessel v2 access checks."""

import logging

from management.authorization.invalid_token import InvalidTokenError
from management.authorization.missing_authorization import MissingAuthorizationError
from management.authorization.token_validator import ITSSOTokenValidator
from management.principal.model import Principal
from management.principal.proxy import get_kessel_principal_id

logger = logging.getLogger(__name__)

# Module-level token validator instance to avoid re-initialization on each request
_token_validator = ITSSOTokenValidator()


def get_kessel_principal_id_for_v2_access(request) -> str | None:
    """
    Get the principal ID for Kessel v2 access checks with service account support.

    This function is specifically for v2 access checks (workspace access, role binding access)
    and handles service account authentication via ITSSOTokenValidator.

    Tries to get principal_id from (in order of precedence):
    1. Standard lookup via get_kessel_principal_id (principal DB, request.user, IT service)
    2. Bearer token via ITSSOTokenValidator (for service accounts)

    Args:
        request: The HTTP request object

    Returns:
        str: The principal ID formatted for Kessel API (e.g., "localhost/user_id"),
             or None if principal_id could not be determined
    """
    # 1. Try standard lookup
    principal_id = get_kessel_principal_id(request)
    if principal_id:
        return principal_id

    # 2. For service accounts, try to get user_id from bearer token
    is_service_account = getattr(request.user, "is_service_account", False)
    if is_service_account:
        user_id = _get_user_id_from_bearer_token(request)
        if user_id:
            return Principal.user_id_to_principal_resource_id(user_id)

    return None


def _get_user_id_from_bearer_token(request) -> str | None:
    """
    Extract user_id from bearer token using ITSSOTokenValidator.

    This is used for service account authentication where user_id
    is not available in the x-rh-identity header but can be extracted
    from the JWT bearer token.

    Args:
        request: The HTTP request object

    Returns:
        str: The user_id from the JWT "sub" claim, or None if extraction fails
    """
    try:
        user = _token_validator.get_user_from_bearer_token(request)
        if user and user.user_id:
            logger.debug("Retrieved user_id from bearer token via ITSSOTokenValidator: %s", user.user_id)
            return user.user_id
    except (InvalidTokenError, MissingAuthorizationError) as e:
        logger.debug("Failed to extract user_id from bearer token: %s", e)
    except Exception as e:
        logger.warning(
            "Unexpected error extracting user_id from bearer token: %s: %s",
            type(e).__name__,
            e,
            exc_info=True,
        )

    return None
