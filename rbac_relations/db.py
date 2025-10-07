"""Database access utilities for RBAC resources."""

import os
import re
import sys
from typing import Optional, Dict


def setup_django() -> bool:
    """
    Setup Django environment for database access.

    Returns:
        True if setup successful, False otherwise
    """
    try:
        # Add rbac directory to path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rbac_dir = os.path.join(os.path.dirname(script_dir), "rbac")
        if os.path.exists(rbac_dir) and rbac_dir not in sys.path:
            sys.path.insert(0, rbac_dir)

        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "rbac.settings")
        import django

        django.setup()
        return True
    except Exception as e:
        print(f"Debug: Django setup failed: {e}", file=sys.stderr)
        return False


def _get_workspace_name(cursor, resource_id: str, debug: bool = False) -> Optional[str]:
    """Get workspace name from database."""
    cursor.execute(
        "SELECT name FROM management_workspace WHERE id::text = %s",
        [resource_id],
    )
    if row := cursor.fetchone():
        return row[0]
    if debug:
        print(f"[DEBUG] Workspace {resource_id} not found", file=sys.stderr)
    return None


def _get_role_name(cursor, resource_id: str, debug: bool = False) -> Optional[str]:
    """Get role name from database."""
    # Try v1 role first (direct lookup by uuid)
    cursor.execute(
        "SELECT COALESCE(display_name, name) FROM management_role WHERE uuid::text = %s",
        [resource_id],
    )
    if row := cursor.fetchone():
        return row[0]

    # Try v2 role (lookup via binding mapping)
    cursor.execute(
        """
        SELECT COALESCE(r.display_name, r.name)
        FROM management_bindingmapping bm
        JOIN management_role r ON bm.role_id = r.id
        WHERE bm.mappings->>'role' IS NOT NULL
        AND (bm.mappings->'role'->>'id') = %s
    """,
        [resource_id],
    )
    if row := cursor.fetchone():
        return row[0]

    # Try policy table (system policies for groups)
    cursor.execute(
        """
        SELECT p.name, g.name as group_name
        FROM management_policy p
        JOIN management_group g ON p.group_id = g.id
        WHERE p.uuid::text = %s
    """,
        [resource_id],
    )
    if row := cursor.fetchone():
        policy_name, group_name = row
        # Extract group UUID from policy name if present
        if re.search(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            policy_name,
        ):
            # Policy name format: "System Policy for Group <uuid>"
            # Display as: "Group: <group_name>"
            return f"Group: {group_name}"
        return policy_name

    if debug:
        print(
            f"[DEBUG] Role {resource_id} not found in management_role, binding mappings, or policy",
            file=sys.stderr,
        )
    return None


def _get_group_name(cursor, resource_id: str, debug: bool = False) -> Optional[str]:
    """Get group name from database."""
    cursor.execute(
        """
        SELECT name, platform_default, admin_default
        FROM management_group
        WHERE uuid::text = %s
    """,
        [resource_id],
    )
    if row := cursor.fetchone():
        group_name, platform_default, admin_default = row
        # Add indicator for default groups
        if admin_default:
            return f"{group_name} (admin default)"
        elif platform_default:
            return f"{group_name} (platform default)"
        else:
            return group_name

    # Group doesn't exist yet - check TenantMapping for default/admin default groups
    cursor.execute(
        """
        SELECT
            CASE
                WHEN default_group_uuid::text = %s THEN 'Default access (platform default)'
                WHEN default_admin_group_uuid::text = %s THEN 'Default admin access (admin default)'
                ELSE NULL
            END as group_name
        FROM management_tenantmapping
        WHERE default_group_uuid::text = %s OR default_admin_group_uuid::text = %s
        LIMIT 1
    """,
        [resource_id, resource_id, resource_id, resource_id],
    )
    if (mapping_row := cursor.fetchone()) and mapping_row[0]:
        return mapping_row[0]

    if debug:
        print(f"[DEBUG] Group {resource_id} not found", file=sys.stderr)
    return None


def get_resource_name(
    resource_type: str,
    resource_id: str,
    name_cache: Dict[str, Optional[str]],
    force_refresh: bool = False,
    debug: bool = False,
) -> Optional[str]:
    """
    Fetch resource name from RBAC database.

    Args:
        resource_type: Type of resource (workspace, role, group, etc.)
        resource_id: ID of the resource
        name_cache: Cache dictionary for resource names
        force_refresh: If True, bypass cache and fetch fresh data
        debug: If True, print debug messages

    Returns:
        Resource name or None if not found
    """
    # Check cache first (unless force refresh)
    cache_key = f"{resource_type}:{resource_id}"
    if not force_refresh and cache_key in name_cache:
        return name_cache[cache_key]

    # Wildcard and special cases
    if resource_id == "*":
        name_cache[cache_key] = None
        return None

    if resource_id.startswith("localhost/"):
        # Principal username
        username = resource_id.split("/", 1)[1]
        name_cache[cache_key] = username
        return username

    try:
        # Import Django ORM
        from django.db import connection

        name = None

        # Use raw SQL queries to fetch names from management tables
        with connection.cursor() as cursor:
            if resource_type in ("workspace", "rbac/workspace"):
                name = _get_workspace_name(cursor, resource_id, debug)
            elif resource_type in ("role", "rbac/role"):
                name = _get_role_name(cursor, resource_id, debug)
            elif resource_type in ("group", "rbac/group"):
                name = _get_group_name(cursor, resource_id, debug)
            elif resource_type in ("role_binding", "rbac/role_binding"):
                # Role bindings don't have names, just show type
                name = None
            elif resource_type in ("principal", "rbac/principal"):
                # Already handled above
                pass

        name_cache[cache_key] = name
        return name
    except Exception as e:
        if debug:
            print(
                f"[DEBUG] Error fetching name for {resource_type}:{resource_id}: {e}",
                file=sys.stderr,
            )
        name_cache[cache_key] = None
        return None


def refresh_missing_names(graph: Dict, name_cache: Dict[str, Optional[str]]) -> int:
    """
    Refresh names for all nodes that don't have names yet.

    Args:
        graph: Graph structure with nodes
        name_cache: Cache dictionary for resource names

    Returns:
        Number of names refreshed
    """
    refreshed_count = 0
    for node_data in graph.values():
        node_type = node_data["type"]
        node_uuid = node_data["id"]
        cache_key = f"{node_type}:{node_uuid}"

        # If this node has no name cached or cached as None, try refreshing
        if cache_key not in name_cache or name_cache[cache_key] is None:
            old_name = name_cache.get(cache_key)
            new_name = get_resource_name(node_type, node_uuid, name_cache, force_refresh=True)
            if new_name and new_name != old_name:
                refreshed_count += 1

    return refreshed_count
