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
def run_migrations_in_worker(tenant_list):
    """Celery task to run migrations."""
    if tenant_list:
        for tenant in tenant_list:
            call_command("migrate_schemas", tenant_name=tenant)
        return

    call_command("migrate_schemas")


@shared_task
def run_seeds_in_worker(kwargs):
    """Celery task to run seeds."""
    call_command("seeds", **kwargs)


@shared_task
def run_reconcile_tenant_relations_in_worker(kwargs):
    """Celery task to reconcile tenant relations."""
    call_command("reconcile_tenant_relations", **kwargs)


@shared_task
def run_sync_schemas_in_worker(kwargs):
    """Celery task to sync schemas."""
    call_command("sync_schemas", **kwargs)
