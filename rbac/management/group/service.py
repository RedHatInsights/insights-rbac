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
"""Service layer for group principal synchronization."""

import logging
from typing import List

from django.db import transaction

from management.principal.proxy import external_principal_to_user
from management.inventory_replicator.outbox_replicator import OutboxReplicator
from management.tenant_service import get_tenant_bootstrap_service

logger = logging.getLogger(__name__)


def backfill_remote_principal(bootstrap_service, user, org_id=None):
    """Backfill a single user's TenantMapping membership via update_user.

    Wraps update_user() in a savepoint so that a database error does not mark
    the caller's outer transaction for rollback.  Exceptions are caught and
    logged so callers can continue processing other principals.

    Args:
        bootstrap_service: TenantBootstrapService instance.
        user: User object to sync.
        org_id: Fallback org_id for log context when user.org_id is unavailable.
    """
    try:
        with transaction.atomic():
            bootstrap_service.update_user(user, upsert=True)
    except Exception:
        logger.warning(
            "Failed to backfill remote principal %s in org %s",
            user.username,
            org_id or getattr(user, "org_id", "unknown"),
            exc_info=True,
        )


def backfill_remote_principals(principals_needing_sync: List[dict], org_id: str) -> None:
    """Backfill remote principals from BOP response items.

    Converts BOP response items to User objects and calls update_user() for each
    active principal that has a user_id. Failures are logged per-principal so that
    one bad record does not prevent the remaining principals from being synced.

    Args:
        principals_needing_sync: BOP response items for principals that were
            newly created or had user_id populated for the first time.
        org_id: The organization ID to use as fallback for principals missing org_id.
    """
    if not principals_needing_sync:
        return

    bootstrap_service = get_tenant_bootstrap_service(OutboxReplicator())
    for bop_item in principals_needing_sync:
        user_obj = external_principal_to_user(bop_item)
        if not user_obj.org_id:
            user_obj.org_id = org_id
        if user_obj.user_id and user_obj.is_active:
            backfill_remote_principal(bootstrap_service, user_obj, org_id)
