#!/usr/bin/env python3
"""
Update all principals in the database to generate their relations.

This script calls V2TenantBootstrapService.update_user() for each principal
to create their default group membership relations.

Usage:
    DJANGO_READ_DOT_ENV_FILE=True RBAC_LOG_RELATIONS=true pipenv run python scripts/update_all_principals.py
"""

import sys
import os

# Add rbac directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
rbac_dir = os.path.join(os.path.dirname(script_dir), "rbac")
if rbac_dir not in sys.path:
    sys.path.insert(0, rbac_dir)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "rbac.settings")

import django

django.setup()

from management.principal.model import Principal
from api.models import Tenant, User
from management.tenant_service.v2 import V2TenantBootstrapService
from management.relation_replicator.outbox_replicator import OutboxReplicator
import logging

logger = logging.getLogger(__name__)


def main():
    """Update all principals to generate relations."""
    # Initialize the bootstrap service with outbox replicator
    replicator = OutboxReplicator()
    bootstrap_service = V2TenantBootstrapService(replicator=replicator)

    # Get all principals (excluding public tenant)
    principals = Principal.objects.exclude(tenant__tenant_name="public").select_related("tenant")
    total = principals.count()

    # Print marker that startup/seeding is complete (for parse_relations.py --filter-seeds)
    print("Starting principal updates", file=sys.stderr)
    logger.info(f"Found {total} principals to update")
    print(f"Found {total} principals to update", file=sys.stderr)

    updated = 0
    skipped = 0

    for principal in principals:
        # Create a User object from the principal
        # Note: This doesn't save to DB, just creates object for update_user
        user = User(
            username=principal.username,
            user_id=principal.user_id,
            org_id=principal.tenant.org_id,
            account=principal.tenant.account_id,
            admin=principal.type == "admin",
            is_active=True,
            is_service_account=principal.service_account_id is not None,
        )

        # Skip if user_id is missing
        if not user.user_id:
            logger.warning(f"Skipping principal without user_id: {principal.username}")
            skipped += 1
            continue

        try:
            # Get or bootstrap the tenant
            bootstrapped = bootstrap_service.bootstrap_tenant(principal.tenant)

            # Update the user (this will create relations)
            bootstrap_service.update_user(user, upsert=False, bootstrapped_tenant=bootstrapped)
            updated += 1

            if updated % 10 == 0:
                logger.info(f"Updated {updated}/{total} principals")

        except Exception as e:
            logger.error(f"Failed to update principal {principal.username}: {e}")
            skipped += 1

    print(f"\nUpdate complete:", file=sys.stderr)
    print(f"  Updated: {updated}", file=sys.stderr)
    print(f"  Skipped: {skipped}", file=sys.stderr)
    print(f"  Total: {total}", file=sys.stderr)


if __name__ == "__main__":
    main()
