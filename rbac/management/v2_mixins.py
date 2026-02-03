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
"""Mixins for v2 API ViewSets."""

import logging

import pgtransaction
from django.db import OperationalError
from psycopg2.errors import DeadlockDetected, SerializationFailure
from rest_framework import status
from rest_framework.response import Response

logger = logging.getLogger(__name__)


class AtomicOperationsMixin:
    """
    Mixin providing atomic create/update/destroy with SERIALIZABLE isolation.

    Wraps write operations in PostgreSQL SERIALIZABLE transactions with automatic
    retry (up to 3 times) for transient concurrency errors. Converts exhausted
    retries into appropriate HTTP responses:
    - SerializationFailure → 409 Conflict
    - DeadlockDetected → 500 Internal Server Error

    Usage:
        class MyViewSet(AtomicOperationsMixin, BaseV2ViewSet):
            ...
            # create(), update(), destroy() are automatically wrapped
    """

    def _handle_concurrency_error(self, e, operation_name):
        """Convert PostgreSQL concurrency errors to HTTP responses."""
        if hasattr(e, "__cause__"):
            if isinstance(e.__cause__, SerializationFailure):
                logger.exception("SerializationFailure in %s operation", operation_name)
                return Response(
                    {"detail": "Too many concurrent updates. Please retry."},
                    status=status.HTTP_409_CONFLICT,
                )
            elif isinstance(e.__cause__, DeadlockDetected):
                logger.exception("DeadlockDetected in %s operation", operation_name)
                return Response(
                    {"detail": "Internal server error. Please try again later."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        return None

    @pgtransaction.atomic(isolation_level=pgtransaction.SERIALIZABLE, retry=3)
    def _atomic_create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @pgtransaction.atomic(isolation_level=pgtransaction.SERIALIZABLE, retry=3)
    def _atomic_update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @pgtransaction.atomic(isolation_level=pgtransaction.SERIALIZABLE, retry=3)
    def _atomic_destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """Create with SERIALIZABLE isolation and automatic retry."""
        try:
            return self._atomic_create(request, *args, **kwargs)
        except OperationalError as e:
            response = self._handle_concurrency_error(e, "create")
            if response:
                return response
            raise

    def update(self, request, *args, **kwargs):
        """Update with SERIALIZABLE isolation and automatic retry."""
        try:
            return self._atomic_update(request, *args, **kwargs)
        except OperationalError as e:
            response = self._handle_concurrency_error(e, "update")
            if response:
                return response
            raise

    def destroy(self, request, *args, **kwargs):
        """Destroy with SERIALIZABLE isolation and automatic retry."""
        try:
            return self._atomic_destroy(request, *args, **kwargs)
        except OperationalError as e:
            response = self._handle_concurrency_error(e, "destroy")
            if response:
                return response
            raise
