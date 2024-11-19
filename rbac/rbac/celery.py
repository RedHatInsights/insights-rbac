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
"""Celery setup."""
from __future__ import absolute_import, unicode_literals

import os

from app_common_python import LoadedConfig
from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_ready
from django.conf import settings

from prometheus_client import CollectorRegistry, generate_latest, multiprocess, start_http_server

# set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "rbac.settings")

app = Celery("rbac")  # pylint: disable=invalid-name

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object("django.conf:settings", namespace="CELERY")

app.conf.beat_schedule = {
    "car-wash-daily": {
        "task": "api.tasks.cross_account_cleanup",
        "schedule": crontab(minute=0, hour=0),
        "args": [],
    },  # noqa: E231, E501
    "schedule-redis-check": {
        "task": "management.tasks.run_redis_cache_health",
        "schedule": 30,
        "args": [],
    },
}

if settings.PRINCIPAL_CLEANUP_DELETION_ENABLED_UMB:
    if settings.UMB_JOB_ENABLED:  # TODO: This is temp flag, remove it after populating user_id
        app.conf.beat_schedule["principal-cleanup-every-minute"] = {
            "task": "management.tasks.principal_cleanup_via_umb",
            "schedule": 60,  # Every 60 second
            "args": [],
        }
else:
    app.conf.beat_schedule["principal-cleanup-every-sevenish-days"] = {
        "task": "management.tasks.principal_cleanup",
        "schedule": crontab(0, 0, day_of_month="7-28/7"),
        "args": [],
    }

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()


@worker_ready.connect
def start_metrics_server(sender=None, **kwargs):
    """Start the metrics server."""

    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
    generate_latest(registry)
    start_http_server(LoadedConfig.metricsPort, addr="0.0.0.0", registry=registry)
