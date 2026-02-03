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
"""Service for RoleV2 management following DDD principles."""

import logging
from typing import Iterable

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from management.permission.model import Permission
from management.role.v2_exceptions import (
    EmptyDescriptionError,
    EmptyPermissionsError,
    PermissionsNotFoundError,
    RoleAlreadyExistsError,
    RoleDatabaseError,
)
from management.role.v2_model import CustomRoleV2

from api.models import Tenant

logger = logging.getLogger(__name__)


class RoleV2Service:
    """
    Domain service for RoleV2 operations.

    This service encapsulates business logic for role management.

    Raises domain-specific exceptions that should be caught and converted
    to HTTP-level errors by the serializer layer.
    """

    def create(
        self,
        name: str,
        description: str,
        permissions: Iterable[Permission],
        tenant: Tenant,
    ) -> CustomRoleV2:
        """
        Create a new custom role with the given permissions.

        Args:
            name: Human-readable name for the role
            description: Description of the role's purpose
            permissions: Iterable of Permission objects to assign
            tenant: The tenant this role belongs to

        Returns:
            The created CustomRoleV2 instance

        Raises:
            RoleAlreadyExistsError: If a role with the same name exists for this tenant
            RoleDatabaseError: If an unexpected database error occurs
        """
        # TODO: Move this validation to RoleV2 model once a migration is created
        # to change description from TextField(null=True, blank=True) to
        # TextField(null=False, blank=False). Currently enforced here because
        # the API requires description but the model doesn't yet.
        if not description or not description.strip():
            raise EmptyDescriptionError()

        try:
            # Create the role using domain model constructor
            # CustomRoleV2 encapsulates construction rules (type validation) in its __init__
            role = CustomRoleV2(
                name=name,
                description=description,
                tenant=tenant,
            )
            # save() triggers full_clean() which validates model constraints
            role.save()

            # Set permissions through M2M relationship
            role.permissions.set(permissions)

            logger.info(
                "Created custom role '%s' (uuid=%s) with %d permissions for tenant %s",
                role.name,
                role.uuid,
                len(list(permissions)),
                tenant.org_id,
            )

            return role

        except ValidationError as e:
            # full_clean() raises ValidationError for unique constraint violations
            error_msg = str(e)
            if "name" in error_msg.lower() and "already exists" in error_msg.lower():
                raise RoleAlreadyExistsError(name)
            raise
        except IntegrityError as e:
            # DB-level constraint violations
            error_msg = str(e)
            if "unique role v2 name per tenant" in error_msg.lower() or "unique" in error_msg.lower():
                raise RoleAlreadyExistsError(name)
            logger.exception("Database error creating role '%s'", name)
            raise RoleDatabaseError()

    def resolve_permissions(
        self,
        permission_data: list[dict],
    ) -> list[Permission]:
        """
        Resolve permission dictionaries to Permission model instances.

        Args:
            permission_data: List of dicts with 'application', 'resource_type', 'operation' keys

        Returns:
            List of Permission instances

        Raises:
            EmptyPermissionsError: If no permissions are provided
            PermissionsNotFoundError: If any permission cannot be found
        """
        if not permission_data:
            raise EmptyPermissionsError()

        permissions = []
        not_found = []

        for perm_dict in permission_data:
            application = perm_dict.get("application")
            resource_type = perm_dict.get("resource_type")
            # Accept both 'operation' (API/test) and 'verb' (serializer validated_data)
            operation = perm_dict.get("operation") or perm_dict.get("verb")

            # Build the V1 permission string format: app:resource:verb
            permission_string = f"{application}:{resource_type}:{operation}"

            try:
                permission = Permission.objects.get(permission=permission_string)
                permissions.append(permission)
            except Permission.DoesNotExist:
                not_found.append(permission_string)

        if not_found:
            raise PermissionsNotFoundError(not_found)

        return permissions
