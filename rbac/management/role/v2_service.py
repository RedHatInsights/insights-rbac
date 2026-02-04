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
from uuid import UUID

from management.role.v2_exceptions import RoleNotFoundError
from management.role.v2_model import RoleV2

from api.models import Tenant

logger = logging.getLogger(__name__)


class RoleV2Service:
    """
    Domain service for RoleV2 operations.

    This service encapsulates business logic for role management.

    Raises domain-specific exceptions that should be caught and converted
    to HTTP-level errors by the view layer.
    """

    def __init__(self, tenant: Tenant | None = None):
        """
        Initialize the service with an optional tenant.

        Args:
            tenant: The tenant context for operations. Required for get_role.
        """
        self.tenant = tenant

    def get_role(self, uuid: UUID) -> RoleV2:
        """
        Get a single role by UUID.

        Args:
            uuid: The UUID of the role to retrieve

        Returns:
            RoleV2 instance

        Raises:
            RoleNotFoundError: If role not found for this tenant
            ValueError: If tenant is not set
        """
        if not self.tenant:
            raise ValueError("Tenant must be set to retrieve a role")

        try:
            role = RoleV2.objects.filter(tenant=self.tenant, uuid=uuid).prefetch_related("permissions").get()
            logger.debug(f"Retrieved role {uuid} for tenant {self.tenant.org_id}")
            return role
        except RoleV2.DoesNotExist:
            logger.warning(f"Role {uuid} not found for tenant {self.tenant.org_id}")
            raise RoleNotFoundError(uuid)
