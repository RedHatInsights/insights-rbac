#
# Copyright 2026 Red Hat, Inc.
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
"""Service for Role management."""

import logging

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from management.atomic_transactions import atomic
from management.exceptions import (
    AlreadyExistsError,
    DatabaseError,
    InvalidFieldError,
    MissingRequiredFieldError,
)
from management.permission.model import PermissionValue
from management.permission.service import PermissionService
from management.role.v2_model import CustomRoleV2

from api.models import Tenant

logger = logging.getLogger(__name__)

OPERATION_CREATE_ROLE = "Create Role"


class RoleV2Service:
    """
    Application service for Role operations.

    Raises domain-specific exceptions that should be caught and converted
    to HTTP-level errors by the exception handler.
    """

    def __init__(self):
        """Initialize the service with its dependencies."""
        self.permission_service = PermissionService()

    @atomic
    def create(
        self,
        name: str,
        description: str,
        permission_data: list[dict],
        tenant: Tenant,
    ) -> CustomRoleV2:
        """Create a new custom role with the given attributes."""
        # TODO: Move this validation to RoleV2 model once a migration is created
        # to change description from TextField(null=True, blank=True) to
        # TextField(null=False, blank=False). Currently enforced here because
        # the API requires description but the model doesn't yet.
        if not description or not description.strip():
            raise MissingRequiredFieldError("description", OPERATION_CREATE_ROLE)

        if not permission_data:
            raise MissingRequiredFieldError("permissions", OPERATION_CREATE_ROLE)

        try:
            permissions = self.permission_service.resolve(permission_data)
            requested = {PermissionValue.from_v2_dict(p).v1_string() for p in permission_data}
        except (InvalidFieldError, MissingRequiredFieldError) as e:
            # Convert permission-level exceptions to role context with "permissions" as the field
            field = getattr(e, "field", None)
            message = str(e) if field == "permissions" else f"Permission field error: {e}"
            rejected_value = getattr(e, "rejected_value", None)
            raise InvalidFieldError(
                "permissions", message, OPERATION_CREATE_ROLE, rejected_value=rejected_value
            ) from e

        found = {p.permission for p in permissions}
        not_found = requested - found
        if not_found:
            missing_list = ", ".join(sorted(not_found))
            raise InvalidFieldError(
                "permissions",
                f"The following permissions do not exist: {missing_list}",
                OPERATION_CREATE_ROLE,
            )

        try:
            role = CustomRoleV2(
                name=name,
                description=description,
                tenant=tenant,
            )
            role.save()
            role.permissions.set(permissions)

            logger.info(
                "Created custom role '%s' (uuid=%s) with %d permissions for tenant %s",
                role.name,
                role.uuid,
                len(permissions),
                tenant.org_id,
            )

            return role

        except ValidationError as e:
            error_msg = str(e)
            if "name" in error_msg.lower() and "already exists" in error_msg.lower():
                raise AlreadyExistsError("role", name, OPERATION_CREATE_ROLE)
            raise
        except IntegrityError as e:
            error_msg = str(e)
            if "unique role v2 name per tenant" in error_msg.lower() or "unique" in error_msg.lower():
                raise AlreadyExistsError("role", name, OPERATION_CREATE_ROLE)
            logger.exception("Database error creating role '%s'", name)
            raise DatabaseError(OPERATION_CREATE_ROLE)
