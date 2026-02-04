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
"""Service for RoleV2 management following DDD principles."""

import logging
from typing import Iterable

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from management.atomic_transactions import atomic
from management.permission.model import Permission
from management.permission.service import PermissionService
from management.role.v2_exceptions import (
    EmptyDescriptionError,
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

    def resolve_permissions(self, permission_data: list[dict]) -> list[Permission]:
        """Delegate to PermissionService."""
        return self.permission_service.resolve(permission_data)

    @atomic
    def create(
        self,
        name: str,
        description: str,
        permissions: Iterable[Permission],
        tenant: Tenant,
    ) -> CustomRoleV2:
        """Create a new custom role with the given attributes."""
        # TODO: Move this validation to RoleV2 model once a migration is created
        # to change description from TextField(null=True, blank=True) to
        # TextField(null=False, blank=False). Currently enforced here because
        # the API requires description but the model doesn't yet.
        if not description or not description.strip():
            raise EmptyDescriptionError()

        permissions = list(permissions)

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
