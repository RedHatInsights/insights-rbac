#
# Copyright 2019 Red Hat, Inc.
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
"""Celery Health Check."""
from time import sleep

import health_check
from rest_framework import permissions
from rest_framework.decorators import permission_classes
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from django.urls import resolve

rbacHealthCheck = health_check.contrib.celery_ping.backends.CeleryPingHealthCheck()

@permission_classes((permissions.AllowAny,))
def delay():
    """Delay 10 seconds for async."""
    sleep(10)


@permission_classes((permissions.AllowAny,))
def check_health():
    """Check the health of the workers and brokers."""
    # If the celery workers or redis connection are unavailable, then return a 500 error.
    # Otherwise, return a 200 status."""

    check_status = rbacHealthCheck.check_status()
    return check_status