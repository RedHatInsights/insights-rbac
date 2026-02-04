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
"""Decorators for v2 services."""

import functools

import pgtransaction
from django.conf import settings
from django.db import transaction


def atomic(func):
    """
    Decorator to wrap service methods in a SERIALIZABLE transaction.
    If already inside a transaction (e.g., from view layer), creates a savepoint.

    Set ATOMIC_RETRY_DISABLED=True in settings to use standard atomic (for tests).
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if getattr(settings, "ATOMIC_RETRY_DISABLED", False):
            with transaction.atomic():
                return func(*args, **kwargs)
        else:
            with pgtransaction.atomic(isolation_level=pgtransaction.SERIALIZABLE):
                return func(*args, **kwargs)

    return wrapper
