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

from celery import Celery
from celery.schedules import crontab

# set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "rbac.settings")

app = Celery("rbac")  # pylint: disable=invalid-name

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object("django.conf:settings", namespace="CELERY")

app.conf.beat_schedule = {
    "principal-cleanup-every-sevenish-days": {
        "task": "management.tasks.principal_cleanup",
        "schedule": crontab(0, 0, day_of_month="7-28/7"),
        "args": [],
    },
    "car-wash-daily": {
        "task": "api.tasks.cross_account_cleanup",
        "schedule": crontab(minute=0, hour=0),
        "args": [],
    },  # noqa: E231, E501
}

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()
