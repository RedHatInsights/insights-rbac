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
"""Permission classes for gating V1/V2 write operations by the v2_edit_api feature flag.

These permission classes serve as a fast, non-locking first line of defense.
The authoritative check with row-level locking happens inside the transaction
(see management.tenant_mapping.v2_activation).
"""

import logging

from feature_flags import FEATURE_FLAGS
from management.tenant_mapping.v2_activation import is_v2_write_activated
from rest_framework import permissions

from api.models import Tenant

logger = logging.getLogger(__name__)


def _is_v2_edit_enabled_for_request(request) -> bool:
    """Check if V2 edit API is enabled via feature flag OR DB activation state."""
    if FEATURE_FLAGS.is_v2_edit_api_enabled(request.user.org_id):
        return True

    try:
        tenant = Tenant.objects.get(org_id=request.user.org_id)
        return is_v2_write_activated(tenant)
    except Tenant.DoesNotExist:
        return False


class V1WriteBlockedWhenWorkspacesEnabled(permissions.BasePermission):
    """Deny V1 write operations when workspaces (v2 edit API) is enabled for the org.

    Checks both the feature flag and the database activation state. If either
    indicates V2 is active, V1 writes are blocked.

    Add to V1 viewsets (RoleViewSet, GroupViewSet) to block write requests
    for orgs that have been migrated to workspaces.
    """

    message = "V1 write operations are not allowed for orgs using workspaces."

    def has_permission(self, request, view):
        """Allow reads always; deny writes when v2 edit API is enabled for this org."""
        if request.method in permissions.SAFE_METHODS:
            return True
        return not _is_v2_edit_enabled_for_request(request)


class V2WriteRequiresWorkspacesEnabled(permissions.BasePermission):
    """Deny V2 write operations when workspaces (v2 edit API) is NOT enabled for the org.

    Checks the feature flag only (not DB state), since V2 writes are what
    *create* the DB activation state.

    Add to V2 viewsets (RoleV2ViewSet, RoleBindingViewSet) to block write requests
    for orgs that have not been migrated to workspaces.
    """

    message = "V2 write operations require the workspaces feature to be enabled for this org."

    def has_permission(self, request, view):
        """Allow reads always; deny writes when v2 edit API is disabled for this org."""
        if request.method in permissions.SAFE_METHODS:
            return True
        return FEATURE_FLAGS.is_v2_edit_api_enabled(request.user.org_id)
