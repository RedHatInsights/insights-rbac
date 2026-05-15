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

"""Role V2 access permissions using Kessel Inventory API."""

import logging

from management.permissions.workspace_inventory_access import (
    WorkspaceInventoryAccessChecker,
)
from management.principal.proxy import get_kessel_principal_id
from rest_framework import permissions

logger = logging.getLogger(__name__)


class RoleV2KesselAccessPermission(permissions.BasePermission):
    """
    Permission class for Role V2 API access using Kessel Inventory API.

    Checks if the principal has rbac_roles_read or rbac_roles_write permission
    on the org resource via the Inventory API's CheckForUpdate gRPC call.

    Read actions (list, retrieve) require rbac_roles_read.
    Write actions (create, update, bulk_destroy) require rbac_roles_write.
    """

    RESOURCE_TYPE = "tenant"
    ROLES_READ_RELATION = "rbac_roles_read"
    ROLES_WRITE_RELATION = "rbac_roles_write"
    WRITE_ACTIONS = {"create", "update", "bulk_destroy"}

    def _get_principal_info(self, request):
        """Safely extract principal information from request for logging."""
        user = getattr(request, "user", None)
        if user is None:
            return {"username": None, "org_id": None, "user_id": None}
        return {
            "username": getattr(user, "username", None),
            "org_id": getattr(user, "org_id", None),
            "user_id": getattr(user, "user_id", None),
        }

    def _get_endpoint(self, request):
        """Safely extract endpoint path from request for logging."""
        return getattr(request, "path", None)

    def _get_relation(self, view) -> str:
        """Get the relation to check based on the view action."""
        action = getattr(view, "action", None)
        if action in self.WRITE_ACTIONS:
            return self.ROLES_WRITE_RELATION
        return self.ROLES_READ_RELATION

    def has_permission(self, request, view):
        """
        Check if the user has permission to access Role V2 APIs.

        Args:
            request: The HTTP request object
            view: The view being accessed

        Returns:
            bool: True if the user has permission, False otherwise
        """
        tenant = getattr(request, "tenant", None)
        if tenant is None:
            # Log authorization failure - SEC-MON-REQ-1 compliance (#8 authorization_failure)
            logger.warning(
                "Authorization denied: No tenant on request",
                extra={
                    "event": "authorization_failure",
                    "principal": self._get_principal_info(request),
                    "resource_type": "role_v2",
                    "outcome": "failure",
                    "reason": "No tenant on request",
                    "endpoint": self._get_endpoint(request),
                },
            )
            return False

        org_resource_id = tenant.tenant_resource_id()
        if not org_resource_id:
            # Log authorization failure - SEC-MON-REQ-1 compliance (#8 authorization_failure)
            logger.warning(
                "Authorization denied: Tenant has no resource ID",
                extra={
                    "event": "authorization_failure",
                    "principal": self._get_principal_info(request),
                    "resource_type": "role_v2",
                    "outcome": "failure",
                    "reason": "Tenant has no resource ID",
                    "endpoint": self._get_endpoint(request),
                },
            )
            return False

        principal_id = get_kessel_principal_id(request)
        if not principal_id:
            # Log authorization failure - SEC-MON-REQ-1 compliance (#8 authorization_failure)
            logger.warning(
                "Authorization denied: Could not determine principal ID",
                extra={
                    "event": "authorization_failure",
                    "principal": self._get_principal_info(request),
                    "resource_type": "role_v2",
                    "outcome": "failure",
                    "reason": "Could not determine Kessel principal ID",
                    "endpoint": self._get_endpoint(request),
                },
            )
            return False

        relation = self._get_relation(view)
        checker = WorkspaceInventoryAccessChecker()
        has_access = checker.check_resource_access(
            resource_type=self.RESOURCE_TYPE,
            resource_id=org_resource_id,
            principal_id=principal_id,
            relation=relation,
        )

        if not has_access:
            # Log authorization failure - SEC-MON-REQ-1 compliance (#8 authorization_failure)
            principal_info = self._get_principal_info(request)
            principal_info["kessel_principal_id"] = principal_id
            logger.warning(
                "Authorization denied by Kessel permission check for Role V2 API",
                extra={
                    "event": "authorization_failure",
                    "principal": principal_info,
                    "resource_type": "role_v2",
                    "resource_id": org_resource_id,
                    "required_permission": relation,
                    "outcome": "failure",
                    "reason": "Kessel Inventory permission check denied",
                    "endpoint": self._get_endpoint(request),
                },
            )

        return has_access
