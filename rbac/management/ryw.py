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
"""Read-your-writes (RYW) consistency support via PostgreSQL LISTEN/NOTIFY."""

import logging
import select
import time

from django.conf import settings
from django.db import connection
from prometheus_client import Counter, Histogram
from psycopg2 import sql

logger = logging.getLogger(__name__)

READ_YOUR_WRITES_CHANNEL = settings.READ_YOUR_WRITES_CHANNEL


def _generate_ryw_histogram_buckets(timeout_seconds: int) -> tuple:
    """Generate histogram buckets based on the configured timeout.

    Creates buckets at 1%, 2.5%, 5%, 10%, 25%, 50%, 75%, and 100% of the timeout.
    """
    percentages = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0]
    return tuple(round(timeout_seconds * p, 2) for p in percentages)


# Prometheus metrics for read-your-writes consistency monitoring.
# The `entity` label distinguishes RYW contexts (e.g. "workspace", "role_binding_batch").
ryw_wait_total = Counter(
    "ryw_wait_total",
    "Total number of read-your-writes consistency checks",
    ["entity", "result"],
)
ryw_wait_duration_seconds = Histogram(
    "ryw_wait_duration_seconds",
    "Duration of read-your-writes consistency checks in seconds",
    ["entity", "result"],
    buckets=_generate_ryw_histogram_buckets(settings.READ_YOUR_WRITES_TIMEOUT_SECONDS),
)


def _record_ryw_metrics(duration: float, entity: str, result: str) -> None:
    """Record RYW metrics for both counter and histogram.

    Args:
        duration: The duration of the RYW wait in seconds.
        entity: The RYW context (e.g. "workspace", "role_binding_batch").
        result: The outcome of the wait ('success' or 'timeout').
    """
    ryw_wait_duration_seconds.labels(entity=entity, result=result).observe(duration)
    ryw_wait_total.labels(entity=entity, result=result).inc()


LISTEN_SQL = sql.SQL("LISTEN {};").format(sql.Identifier(READ_YOUR_WRITES_CHANNEL))
UNLISTEN_SQL = sql.SQL("UNLISTEN {};").format(sql.Identifier(READ_YOUR_WRITES_CHANNEL))


def wait_for_ryw_notify(identifier: str, entity_description: str) -> None:
    """Wait for a NOTIFY on the RYW channel matching the given identifier.

    Intended for use as a ``transaction.on_commit`` callback.

    Args:
        identifier: The payload to match in the NOTIFY message (e.g. workspace UUID, batch UUID).
        entity_description: Human-readable description for log messages (e.g. "workspace", "role binding batch").
    """
    try:
        connection.ensure_connection()
        conn = connection.connection
        timeout_seconds = settings.READ_YOUR_WRITES_TIMEOUT_SECONDS

        # Early exit if misconfigured
        if timeout_seconds is None or timeout_seconds <= 0:
            logger.debug(
                "[RYW] Skipped waiting due to non-positive timeout for channel='%s' %s='%s'",
                READ_YOUR_WRITES_CHANNEL,
                entity_description,
                identifier,
            )
            return

        with connection.cursor() as cursor:
            cursor.execute(LISTEN_SQL)

        logger.info(
            "[RYW] Waiting for NOTIFY channel='%s' %s='%s' timeout=%ss",
            READ_YOUR_WRITES_CHANNEL,
            entity_description,
            identifier,
            timeout_seconds,
        )

        # Use monotonic clock and a strict deadline to avoid overshooting
        started = time.monotonic()
        deadline = started + float(timeout_seconds)
        identifier_str = str(identifier)

        # Clear any stale notifications from before LISTEN was issued
        try:
            conn.poll()  # bring any pending into conn.notifies
            if getattr(conn, "notifies", None):
                conn.notifies.clear()
        except Exception:
            logger.debug("Failed to clear stale notifications before LISTEN, continuing anyway")

        fd = conn.fileno()

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            readable, _, _ = select.select([fd], [], [], min(1.0, remaining))
            if not readable:
                continue

            conn.poll()
            notifies = getattr(conn, "notifies", None)
            if notifies:
                pending = list(notifies)
                notifies.clear()
                for n in pending:
                    payload = (getattr(n, "payload", "") or "").strip()
                    if n.channel == READ_YOUR_WRITES_CHANNEL and payload == identifier_str:
                        duration = time.monotonic() - started
                        logger.info(
                            "[RYW] Received NOTIFY channel='%s' %s='%s' after %.3fs",
                            n.channel,
                            entity_description,
                            payload,
                            duration,
                        )
                        _record_ryw_metrics(duration, entity_description, "success")
                        return

        duration = time.monotonic() - started
        logger.error(
            "[RYW] Timed out waiting for NOTIFY channel='%s' %s='%s' after %ss",
            READ_YOUR_WRITES_CHANNEL,
            entity_description,
            identifier,
            timeout_seconds,
        )
        _record_ryw_metrics(duration, entity_description, "timeout")
        raise TimeoutError(
            f"Read-your-writes consistency check timed out after {timeout_seconds}s "
            f"for {entity_description} {identifier}"
        )
    except Exception:
        logger.exception("Error while waiting for NOTIFY after %s", entity_description)
        raise
    finally:
        try:
            with connection.cursor() as cursor:
                cursor.execute(UNLISTEN_SQL)
        except Exception:
            # Best-effort cleanup
            pass
