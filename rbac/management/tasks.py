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
from internal.utils import (
    clean_invalid_workspace_resource_definitions,
    cleanup_tenant_orphan_bindings,
    get_replicator,
    replicate_missing_binding_tuples,
)
from management.health.healthcheck import redis_health
from management.principal.cleaner import (
    clean_tenants_principals,
    process_principal_events_from_umb,
)
from migration_tool.migrate import migrate_data
from migration_tool.migrate_binding_scope import migrate_all_role_bindings


@shared_task
def principal_cleanup():
    """Celery task to clean up principals no longer existing."""
    clean_tenants_principals()


@shared_task
def principal_cleanup_via_umb():
    """Celery task to clean up principals no longer existing."""
    process_principal_events_from_umb()


@shared_task
def run_migrations_in_worker():
    """Celery task to run migrations."""
    call_command("migrate")


@shared_task
def run_seeds_in_worker(kwargs):
    """Celery task to run seeds."""
    call_command("seeds", **kwargs)


@shared_task
def run_sync_schemas_in_worker(kwargs):
    """Celery task to sync schemas."""
    call_command("sync_schemas", **kwargs)


@shared_task
def run_ocm_performance_in_worker():
    """Celery task to run ocm performance tests."""
    call_command("ocm_performance")


@shared_task
def run_redis_cache_health():
    """Celery task to check health of redis cache."""
    redis_health()


@shared_task
def migrate_data_in_worker(kwargs):
    """Celery task to migrate data from V1 to V2 spiceDB schema."""
    migrate_data(**kwargs)


@shared_task
def migrate_binding_scope_in_worker(write_relationships: str = "True"):
    """
    Celery task to migrate role binding scopes.

    Args:
        write_relationships: How to handle replication.
            - "True" or "outbox": Create V2 models and replicate to outbox (default)
            - "logging": Create V2 models and log what would be replicated
            - "False": Create V2 models without replication
    """
    replicator = get_replicator(write_relationships)
    return migrate_all_role_bindings(replicator=replicator)


@shared_task
def fix_missing_binding_base_tuples_in_worker(binding_ids=None):
    """
    Celery task to fix missing base tuples for bindings.

    Args:
        binding_ids (list[int], optional): List of binding IDs to fix. If None, fixes all bindings.

    Returns:
        dict: Results with bindings_checked, bindings_fixed, and tuples_added count.
    """
    return replicate_missing_binding_tuples(binding_ids=binding_ids)


@shared_task
def clean_invalid_workspace_resource_definitions_in_worker(dry_run=False):
    """
    Celery task to clean invalid workspace resource definitions.

    Args:
        dry_run (bool): If True, only report what would be changed without making changes.

    Returns:
        dict: Results with roles_checked, resource_definitions_fixed, bindings_deleted, and changes list.
    """
    return clean_invalid_workspace_resource_definitions(dry_run=dry_run)


@shared_task
def cleanup_tenant_orphan_bindings_in_worker(org_id, dry_run=False):
    """
    Celery task to clean up orphaned role binding relationships for a tenant.

    Args:
        org_id (str): Organization ID for the tenant to clean up
        dry_run (bool): If True, only report what would be deleted without making changes

    Returns:
        dict: Results with cleanup counts and migration results
    """
    return cleanup_tenant_orphan_bindings(org_id=org_id, dry_run=dry_run)
