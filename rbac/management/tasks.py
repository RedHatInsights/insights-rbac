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
"""Celery tasks."""
from __future__ import absolute_import, unicode_literals

from celery import shared_task
from django.core.management import call_command
from management.principal.cleaner import clean_tenants_principals


@shared_task
def principal_cleanup():
    """Celery task to clean up principals no longer existing."""
    clean_tenants_principals()


@shared_task
def run_migrations_in_worker():
    """Celery task to run migrations."""
    call_command("migrate_schemas")
