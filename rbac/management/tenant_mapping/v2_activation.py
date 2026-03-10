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

These functions use SELECT FOR UPDATE on TenantMapping to serialize concurrent
V1 and V2 write attempts for the same tenant. This prevents the TOCTOU race
between the feature flag check (outside transaction) and the actual write
(inside transaction).

Usage:
    # In V2 write paths (inside SERIALIZABLE transaction):
    ensure_v2_write_activated(tenant)

    # In V1 write paths (inside transaction):
    assert_v1_write_allowed(tenant)
"""

import logging

from django.utils import timezone
from management.tenant_mapping.model import TenantMapping

logger = logging.getLogger(__name__)


class V1WriteBlockedError(Exception):
    """Raised when a V1 write is attempted on a tenant that has been activated for V2."""

    pass


def _lock_tenant_mapping(tenant):
    """Lock the TenantMapping row for the given tenant using SELECT FOR UPDATE.

    Returns the locked TenantMapping, or None if the tenant has no mapping
    (i.e. not bootstrapped for V2).
    """
    try:
        return TenantMapping.objects.select_for_update().get(tenant=tenant)
    except TenantMapping.DoesNotExist:
        return None


def ensure_v2_write_activated(tenant):
    """Mark the tenant as V2-activated if not already. Must be called inside a transaction.

    This locks the TenantMapping row and sets v2_write_activated_at if it hasn't
    been set yet. Subsequent V1 writes will be blocked by assert_v1_write_allowed.

    If the tenant has no TenantMapping (not bootstrapped), this is a no-op.
    """
    mapping = _lock_tenant_mapping(tenant)
    if mapping is None:
        return

    if mapping.v2_write_activated_at is None:
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

    Locks the TenantMapping row and checks v2_write_activated_at. If the tenant
    has ever performed a V2 write, raises V1WriteBlockedError.

    If the tenant has no TenantMapping (not bootstrapped), V1 writes are allowed.
    """
    mapping = _lock_tenant_mapping(tenant)
    if mapping is None:
        return

    if mapping.v2_write_activated_at is not None:
        raise V1WriteBlockedError(
            f"Tenant {tenant.org_id} has been activated for V2 writes "
            f"(since {mapping.v2_write_activated_at}). V1 writes are no longer permitted."
        )
