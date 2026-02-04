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

from management.atomic_transactions import ISOLATION_LEVEL, is_atomic_disabled  # noqa: I100, I202

logger = logging.getLogger(__name__)


class AtomicOperationsMixin:
    """
    Mixin providing atomic create/update/destroy with SERIALIZABLE isolation.

    Set ATOMIC_RETRY_DISABLED=True in settings to skip the transaction wrapper entirely.
    """

    atomic_retry = 3

    def _handle_concurrency_error(self, e, operation_name):
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

    def _run_atomic(self, operation, request, *args, **kwargs):
        if is_atomic_disabled():
            return operation(request, *args, **kwargs)

        @pgtransaction.atomic(isolation_level=ISOLATION_LEVEL, retry=self.atomic_retry)
        def atomic_operation():
            return operation(request, *args, **kwargs)

        return atomic_operation()

    def create(self, request, *args, **kwargs):
        """Create with atomic transaction and concurrency handling."""
        try:
            return self._run_atomic(super().create, request, *args, **kwargs)
        except OperationalError as e:
            response = self._handle_concurrency_error(e, "create")
            if response:
                return response
            raise

    def update(self, request, *args, **kwargs):
        """Update with atomic transaction and concurrency handling."""
        try:
            return self._run_atomic(super().update, request, *args, **kwargs)
        except OperationalError as e:
            response = self._handle_concurrency_error(e, "update")
            if response:
                return response
            raise

    def destroy(self, request, *args, **kwargs):
        """Destroy with atomic transaction and concurrency handling."""
        try:
            return self._run_atomic(super().destroy, request, *args, **kwargs)
        except OperationalError as e:
            response = self._handle_concurrency_error(e, "destroy")
            if response:
                return response
            raise
