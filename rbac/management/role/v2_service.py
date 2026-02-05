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
"""Service for RoleV2 management."""

import logging

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from management.atomic_transactions import atomic
from management.exceptions import RequiredFieldError
from management.permission.exceptions import InvalidPermissionDataError
from management.permission.model import PermissionValue
from management.permission.service import PermissionService
from management.role.v2_exceptions import (
    InvalidRolePermissionsError,
    PermissionsNotFoundError,
    RoleAlreadyExistsError,
    RoleDatabaseError,
)
from management.role.v2_model import CustomRoleV2

from api.models import Tenant

logger = logging.getLogger(__name__)


class RoleV2Service:
    """
    Application service for RoleV2 operations.

    Raises domain-specific exceptions that should be caught and converted
    to HTTP-level errors by the serializer layer.
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
            raise RequiredFieldError("description")

        if not permission_data:
            raise RequiredFieldError("permissions")

        try:
            permissions = self.permission_service.resolve(permission_data)
            requested = {PermissionValue.from_v2_dict(p).v1_string() for p in permission_data}
        except (InvalidPermissionDataError, RequiredFieldError) as e:
            raise InvalidRolePermissionsError(str(e))

        found = {p.permission for p in permissions}
        not_found = requested - found
        if not_found:
            raise PermissionsNotFoundError(list(not_found))

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
                raise RoleAlreadyExistsError(name)
            raise
        except IntegrityError as e:
            error_msg = str(e)
            if "unique role v2 name per tenant" in error_msg.lower() or "unique" in error_msg.lower():
                raise RoleAlreadyExistsError(name)
            logger.exception("Database error creating role '%s'", name)
            raise RoleDatabaseError()
