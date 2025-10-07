#!/usr/bin/env python3
"""
Bootstrap all tenants via internal API endpoint.

This script:
1. Fetches all tenants from RBAC database
2. Calls POST /api/utils/bootstrap_tenant/ with the org_ids to bootstrap them
3. The bootstrap process will create workspaces and replicate relations (if RBAC_LOG_RELATIONS=true)
4. Output can be piped to parse_relations.py for visualization

Usage:
    # Bootstrap all tenants and show compact output
    RBAC_LOG_RELATIONS=true python scripts/bootstrap_all_tenants.py | ./scripts/parse_relations.py --zed --compact --show-names

    # Bootstrap all tenants with visual graph
    RBAC_LOG_RELATIONS=true python scripts/bootstrap_all_tenants.py | ./scripts/parse_relations.py --visual --show-names

    # Bootstrap all tenants and execute to SpiceDB
    RBAC_LOG_RELATIONS=true python scripts/bootstrap_all_tenants.py | ./scripts/parse_relations.py --zed --execute
"""

import sys
import os
import requests
import json
import argparse
import logging


def configure_logging():
    """Configure logging for the script."""
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add stderr handler with our format
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


logger = logging.getLogger(__name__)


def setup_django():
    """Setup Django environment for database access."""
    try:
        # Add rbac directory to path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rbac_dir = os.path.join(os.path.dirname(script_dir), "rbac")
        if os.path.exists(rbac_dir) and rbac_dir not in sys.path:
            sys.path.insert(0, rbac_dir)

        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "rbac.settings")
        import django

        django.setup()

        # Reconfigure logging after Django setup (Django overrides it)
        configure_logging()

        return True
    except Exception as e:
        logger.error(f"Django setup failed: {e}")
        return False


def bootstrap_all_tenants(
    base_url="http://localhost:8000", force=False, pending_only=False
):
    """
    Bootstrap all tenants (or only pending ones).

    Args:
        base_url: The base URL of the RBAC server
        force: Whether to force bootstrap even if already bootstrapped
        pending_only: If True, only bootstrap pending tenants. If False, bootstrap ALL tenants.

    Returns:
        True if successful, False otherwise
    """
    # Configure logging first (before Django setup for pending_only case)
    if pending_only:
        configure_logging()

    if pending_only:
        # Step 1a: Get list of pending org_ids only
        pending_url = f"{base_url}/api/utils/bootstrap_pending_tenants/"
        logger.info(f"Fetching pending tenants from {pending_url}...")

        try:
            response = requests.get(pending_url, timeout=30)
            response.raise_for_status()
            data = response.json()
            org_ids = data.get("org_ids", [])

            if not org_ids:
                logger.info("No pending tenants found.")
                return True

            logger.info(f"Found {len(org_ids)} pending tenants: {org_ids}")

        except requests.RequestException as e:
            logger.error(f"Error fetching pending tenants: {e}")
            return False
    else:
        # Step 1b: Get ALL tenants from the RBAC database
        logger.info("Fetching all tenants from RBAC database...")

        if not setup_django():
            logger.error("Could not setup Django environment to access database.")
            return False

        try:
            from api.models import Tenant

            # Get all tenants from database, excluding public tenant
            tenants = Tenant.objects.exclude(org_id__isnull=True).exclude(org_id="")

            # Get the public tenant to exclude it
            try:
                public_tenant = Tenant._get_public_tenant()
                tenants = tenants.exclude(id=public_tenant.id)
            except Exception:
                # If public tenant doesn't exist, continue
                pass

            org_ids = list(tenants.values_list("org_id", flat=True))

            if not org_ids:
                logger.info("No tenants found in database.")
                return True

            logger.info(f"Found {len(org_ids)} total tenants in database.")
            logger.info(f"Org IDs: {org_ids}")

        except Exception as e:
            logger.error(f"Error fetching tenants from database: {e}")
            return False
    # Step 2: Bootstrap the tenants directly using Django ORM (not HTTP API)
    # This way we can see the relation logs in stdout
    logger.info(f"Bootstrapping {len(org_ids)} tenants directly via Django ORM...")

    # Django is already setup from step 1 (unless we're in pending_only mode)
    if pending_only and not setup_django():
        logger.error("Could not setup Django environment for bootstrapping.")
        return False

    try:
        from django.db import transaction
        from management.tenant_service.v2 import V2TenantBootstrapService
        from management.relation_replicator.outbox_replicator import OutboxReplicator
        from api.models import Tenant

        bootstrap_service = V2TenantBootstrapService(OutboxReplicator())

        for org_id in org_ids:
            logger.info(f"Bootstrapping tenant: {org_id}")
            try:
                tenant = Tenant.objects.get(org_id=org_id)
                with transaction.atomic():
                    bootstrap_service.bootstrap_tenant(tenant, force=force)
                logger.info(f"Successfully bootstrapped tenant: {org_id}")
            except Tenant.DoesNotExist:
                logger.error(f"Tenant with org_id {org_id} not found in database")
            except Exception as e:
                logger.error(f"Error bootstrapping tenant {org_id}: {e}")

        logger.info(f"Finished bootstrapping {len(org_ids)} tenants.")
        return True

    except Exception as e:
        logger.error(f"Error during bootstrap process: {e}")
        import traceback

        logger.error(traceback.format_exc())
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Bootstrap tenants via internal API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Base URL of the RBAC server (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force bootstrap even if already bootstrapped (requires force=true, cannot be used when replication is on)",
    )
    parser.add_argument(
        "--pending-only",
        action="store_true",
        help="Only bootstrap pending tenants (default: bootstrap ALL tenants in database)",
    )

    args = parser.parse_args()

    success = bootstrap_all_tenants(
        base_url=args.base_url, force=args.force, pending_only=args.pending_only
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
