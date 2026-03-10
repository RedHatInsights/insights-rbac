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
"""V2 write activation state for tenants.

Provides functions to lock and check whether a tenant has been activated for V2
writes. Once activated, a tenant must never write via V1 again, regardless of
feature flag state.

Uses SELECT FOR SHARE where possible to allow concurrent reads within a tenant,
escalating to SELECT FOR UPDATE only when updating. Django does not support
FOR SHARE in the ORM, so raw SQL is used.

Usage:
    # In V2 write paths (inside SERIALIZABLE transaction):
    ensure_v2_write_activated(tenant)

    # In V1 write paths (inside transaction):
    assert_v1_write_allowed(tenant)
"""

import logging

from django.db import connection
from django.utils import timezone
from management.tenant_mapping.model import TenantMapping

logger = logging.getLogger(__name__)

_TABLE = TenantMapping._meta.db_table


def _lock_for_share(tenant):
    """Lock the TenantMapping row with SELECT FOR SHARE. Returns (id, v2_write_activated_at) or None."""
    with connection.cursor() as cursor:
        cursor.execute(
            f'SELECT id, v2_write_activated_at FROM "{_TABLE}" WHERE tenant_id = %s FOR SHARE',
            [tenant.id],
        )
        return cursor.fetchone()


def _lock_for_update(tenant):
    """Lock the TenantMapping row with SELECT FOR UPDATE. Returns (id, v2_write_activated_at) or None."""
    with connection.cursor() as cursor:
        cursor.execute(
            f'SELECT id, v2_write_activated_at FROM "{_TABLE}" WHERE tenant_id = %s FOR UPDATE',
            [tenant.id],
        )
        return cursor.fetchone()


class V1WriteBlockedError(Exception):
    """Raised when a V1 write is attempted on a tenant that has been activated for V2."""

    pass


class TenantNotBootstrappedError(Exception):
    """Raised when a V2 write is attempted on a tenant that has no TenantMapping."""

    pass


def ensure_v2_write_activated(tenant):
    """Mark the tenant as V2-activated if not already. Must be called inside a transaction.

    Takes a shared lock first; if already V2, returns (allows concurrent V2 reads).
    If not V2, escalates to exclusive lock and updates. This reduces contention
    compared to always using FOR UPDATE.
    """
    row = _lock_for_share(tenant)
    if row is None:
        raise TenantNotBootstrappedError(
            f"Tenant {tenant.org_id} has no TenantMapping; V2 writes require tenant bootstrapping."
        )
    _pk, v2_activated = row
    if v2_activated is not None:
        return

    row = _lock_for_update(tenant)
    if row is None:
        raise TenantNotBootstrappedError(
            f"Tenant {tenant.org_id} has no TenantMapping; V2 writes require tenant bootstrapping."
        )
    _pk, v2_activated = row
    if v2_activated is not None:
        return

    mapping = TenantMapping.objects.get(tenant=tenant)
    mapping.v2_write_activated_at = timezone.now()
    mapping.save(update_fields=["v2_write_activated_at"])
    logger.info("Tenant %s activated for V2 writes", tenant.org_id)


def is_v2_write_activated(tenant):
    """Check if the tenant has been activated for V2 writes (without locking).

    This is a non-locking read for use in permission classes as a fast check.
    The authoritative check with locking is done inside the transaction by
    assert_v1_write_allowed.
    """
    try:
        mapping = TenantMapping.objects.get(tenant=tenant)
        return mapping.v2_write_activated_at is not None
    except TenantMapping.DoesNotExist:
        return False


def assert_v1_write_allowed(tenant):
    """Assert that V1 writes are still allowed for this tenant. Must be called inside a transaction.

    Uses SELECT FOR SHARE: a tenant cannot go V2->V1, and the shared lock prevents
    any V2 write (which needs FOR UPDATE) from converting the tenant while we hold it.
    """
    row = _lock_for_share(tenant)
    if row is None:
        return

    _pk, v2_activated = row
    if v2_activated is not None:
        raise V1WriteBlockedError(
            f"Tenant {tenant.org_id} has been activated for V2 writes "
            f"(since {v2_activated}). V1 writes are no longer permitted."
        )
