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

"""Handler for workspace seeding."""
import json
import logging
import os

from django.conf import settings
from django.db import transaction
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.tenant_service.v2 import V2TenantBootstrapService
from management.workspace.model import Workspace

from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def _make_workspace(data, tenant, default_workspace):
    """Create or update a workspace under the default workspace."""
    name = data.get("name")
    description = data.get("description", "")
    workspace_type = data.get("type", "standard")

    # Check if workspace already exists
    workspace = Workspace.objects.filter(name=name, tenant=tenant, parent=default_workspace).first()

    if workspace:
        # Update existing workspace description if changed
        if workspace.description != description:
            workspace.description = description
            workspace.save()
            logger.info(f"Updated workspace '{name}' for tenant {tenant.org_id}")
        else:
            logger.debug(f"No changes for workspace '{name}' in tenant {tenant.org_id}")
    else:
        # Create new workspace
        workspace = Workspace.objects.create(
            name=name, description=description, type=workspace_type, parent=default_workspace, tenant=tenant
        )
        logger.info(f"Created workspace '{name}' for tenant {tenant.org_id}")

    return workspace


def _update_or_create_workspaces(workspaces_data, tenant, default_workspace):
    """Update or create workspaces from list for a specific tenant."""
    created_count = 0
    for workspace in workspaces_data:
        try:
            workspace = _make_workspace(workspace, tenant, default_workspace)
            if workspace:
                created_count += 1
        except Exception as e:
            logger.error(
                f"Failed to update or create workspace: {workspace.get('name')} "
                f"for tenant {tenant.org_id} with error: {e}"
            )
    return created_count


def seed_workspaces():
    """Seed standard workspaces from JSON definitions for all tenants."""
    workspaces_directory = os.path.join(settings.BASE_DIR, "management", "workspace", "definitions")

    if not os.path.exists(workspaces_directory):
        logger.warning(f"Workspace definitions directory not found: {workspaces_directory}")
        return

    workspace_files = [
        f
        for f in os.listdir(workspaces_directory)
        if os.path.isfile(os.path.join(workspaces_directory, f)) and f.endswith(".json")
    ]

    if not workspace_files:
        logger.info("No workspace definition files found. Skipping workspace seeding.")
        return

    # Get all non-public tenants
    all_tenants = Tenant.objects.exclude(tenant_name="public")

    if not all_tenants.exists():
        logger.info("No tenants found for workspace seeding.")
        return

    # Bootstrap tenants if V2_BOOTSTRAP_TENANT is enabled
    if settings.V2_BOOTSTRAP_TENANT:
        bootstrap_service = V2TenantBootstrapService(OutboxReplicator())
        for tenant in all_tenants:
            try:
                bootstrap_service.bootstrap_tenant(tenant)
            except Exception as e:
                logger.error(f"Failed to bootstrap tenant {tenant.org_id}: {e}")

    # Get all tenants that have been bootstrapped (have default workspace)
    tenants = Tenant.objects.exclude(tenant_name="public").filter(workspace__type=Workspace.Types.DEFAULT).distinct()

    total_created = 0

    for workspace_file_name in workspace_files:
        workspace_file_path = os.path.join(workspaces_directory, workspace_file_name)
        with open(workspace_file_path) as json_file:
            data = json.load(json_file)
            workspaces_list = data.get("workspaces", [])

            if not workspaces_list:
                logger.warning(f"No workspaces found in {workspace_file_name}")
                continue

            logger.info(f"Processing {len(workspaces_list)} workspace(s) from {workspace_file_name}")

            # Process workspaces for each tenant
            if not tenants:
                logger.warning(
                    "No suitable tenants found for workspace seeding, likely not bootstrapped. Skipping seeding."
                )
                return
            else:
                for tenant in tenants:
                    # Get the default workspace for this tenant
                    default_workspace = Workspace.objects.filter(tenant=tenant, type=Workspace.Types.DEFAULT).first()

                    if not default_workspace:
                        logger.warning(f"Default workspace not found for tenant {tenant.org_id}. Skipping.")
                        continue

                    with transaction.atomic():
                        count = _update_or_create_workspaces(workspaces_list, tenant, default_workspace)
                        total_created += count

    logger.info(
        f"Workspace seeding completed. Created/updated {total_created} workspaces across {tenants.count()} tenants."
    )
