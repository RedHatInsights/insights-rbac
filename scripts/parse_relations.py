#!/usr/bin/env python3
"""
Parse RBAC relations from logs and optionally convert to zed commands.

Usage:
    # Just extract relations
    DJANGO_READ_DOT_ENV_FILE=True ./rbac/manage.py migrate_relations 2>&1 | ./scripts/parse_relations.py

    # Convert to zed commands
    DJANGO_READ_DOT_ENV_FILE=True ./rbac/manage.py migrate_relations 2>&1 | ./scripts/parse_relations.py --zed

    # Execute zed commands directly
    DJANGO_READ_DOT_ENV_FILE=True ./rbac/manage.py migrate_relations 2>&1 | ./scripts/parse_relations.py --zed --execute

    # From a log file
    cat migration.log | ./scripts/parse_relations.py --zed

    # Save to file
    pipenv run python rbac/manage.py migrate_relations 2>&1 | ./scripts/parse_relations.py --zed > zed_commands.sh

    # Filter out seeding logs when running server
    RBAC_LOG_RELATIONS=true python rbac/manage.py runserver 2>&1 | ./scripts/parse_relations.py --zed --compact --filter-seeds
"""

import re
import sys
import argparse
import subprocess
import hashlib
import os
import select
import threading
import time
import shutil


# Terminal color codes
class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"


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
        return True
    except Exception as e:
        print(f"Debug: Django setup failed: {e}", file=sys.stderr)
        return False


def get_resource_name(
    resource_type, resource_id, name_cache, force_refresh=False, debug=False
):
    """Fetch resource name from RBAC database."""
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
            if resource_type == "workspace" or resource_type == "rbac/workspace":
                cursor.execute(
                    "SELECT name FROM management_workspace WHERE id::text = %s",
                    [resource_id],
                )
                row = cursor.fetchone()
                if row:
                    name = row[0]
                elif debug:
                    print(f"[DEBUG] Workspace {resource_id} not found", file=sys.stderr)
            elif resource_type == "role" or resource_type == "rbac/role":
                # Try v1 role first (direct lookup by uuid)
                cursor.execute(
                    "SELECT COALESCE(display_name, name) FROM management_role WHERE uuid::text = %s",
                    [resource_id],
                )
                row = cursor.fetchone()
                if row:
                    name = row[0]
                else:
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
                    row = cursor.fetchone()
                    if row:
                        name = row[0]
                    else:
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
                        row = cursor.fetchone()
                        if row:
                            policy_name = row[0]
                            group_name = row[1]
                            # Extract group UUID from policy name if present
                            import re

                            match = re.search(
                                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                                policy_name,
                            )
                            if match:
                                # Policy name format: "System Policy for Group <uuid>"
                                # Display as: "Group: <group_name>"
                                name = f"Group: {group_name}"
                            else:
                                name = policy_name
                        elif debug:
                            print(
                                f"[DEBUG] Role {resource_id} not found in management_role, binding mappings, or policy",
                                file=sys.stderr,
                            )
            elif resource_type == "group" or resource_type == "rbac/group":
                cursor.execute(
                    """
                    SELECT name, platform_default, admin_default
                    FROM management_group
                    WHERE uuid::text = %s
                """,
                    [resource_id],
                )
                row = cursor.fetchone()
                if row:
                    group_name = row[0]
                    platform_default = row[1]
                    admin_default = row[2]

                    # Add indicator for default groups
                    if admin_default:
                        name = f"{group_name} (admin default)"
                    elif platform_default:
                        name = f"{group_name} (platform default)"
                    else:
                        name = group_name
                else:
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
                    mapping_row = cursor.fetchone()
                    if mapping_row and mapping_row[0]:
                        name = mapping_row[0]
                    elif debug:
                        print(f"[DEBUG] Group {resource_id} not found", file=sys.stderr)
            elif (
                resource_type == "role_binding" or resource_type == "rbac/role_binding"
            ):
                # Role bindings don't have names, just show type
                name = None
            elif resource_type == "principal" or resource_type == "rbac/principal":
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


def refresh_missing_names(graph, name_cache):
    """Refresh names for all nodes that don't have names yet."""
    refreshed_count = 0
    for node_id, node_data in graph.items():
        node_type = node_data["type"]
        node_uuid = node_data["id"]
        cache_key = f"{node_type}:{node_uuid}"

        # If this node has no name cached or cached as None, try refreshing
        if cache_key not in name_cache or name_cache[cache_key] is None:
            old_name = name_cache.get(cache_key)
            new_name = get_resource_name(
                node_type, node_uuid, name_cache, force_refresh=True
            )
            if new_name and new_name != old_name:
                refreshed_count += 1

    return refreshed_count


def get_uuid_color(uuid_str, uuid_colors):
    """Get a consistent color for a UUID."""
    if uuid_str not in uuid_colors:
        # Generate color based on hash of UUID
        hash_val = int(hashlib.md5(uuid_str.encode()).hexdigest(), 16)
        colors = [
            Colors.BRIGHT_CYAN,
            Colors.BRIGHT_GREEN,
            Colors.BRIGHT_YELLOW,
            Colors.BRIGHT_BLUE,
            Colors.BRIGHT_MAGENTA,
            Colors.CYAN,
            Colors.GREEN,
            Colors.YELLOW,
            Colors.BLUE,
            Colors.MAGENTA,
            "\033[38;5;214m",  # Orange
            "\033[38;5;208m",  # Dark orange
            "\033[38;5;201m",  # Pink
            "\033[38;5;51m",  # Bright cyan
            "\033[38;5;118m",  # Bright green
            "\033[38;5;226m",  # Bright yellow
            "\033[38;5;159m",  # Light blue
            "\033[38;5;213m",  # Light magenta
            "\033[38;5;87m",  # Sky blue
            "\033[38;5;120m",  # Lime green
            "\033[38;5;228m",  # Light yellow
            "\033[38;5;219m",  # Light pink
            "\033[38;5;117m",  # Powder blue
            "\033[38;5;156m",  # Mint green
        ]
        uuid_colors[uuid_str] = colors[hash_val % len(colors)]
    return uuid_colors[uuid_str]


def interactive_input_handler(
    all_relations, permission_cache, stop_event, render_trigger, auto_check_mode
):
    """
    Handle interactive input for permission checking.
    Runs in a separate thread to listen for user input from /dev/tty.
    """
    tty_input = None
    try:
        # Open /dev/tty for reading user input (separate from stdin which is piped)
        # This may fail in non-terminal environments (e.g., cron, CI/CD pipelines)
        tty_input = open("/dev/tty", "r")

        while not stop_event.is_set():
            # Check if input is available
            if select.select([tty_input], [], [], 0.1)[0]:
                try:
                    # Read line
                    line = tty_input.readline().strip()

                    if not line:
                        continue

                    # Check for mode toggle commands
                    if line.lower() == "show_zed_checks":
                        auto_check_mode["enabled"] = True
                        # Check all existing relations
                        for idx in range(len(all_relations)):
                            if idx not in permission_cache:
                                rel = all_relations[idx]
                                has_perm, msg, cmd = check_permission_with_zed(rel)
                                permission_cache[idx] = (has_perm, msg, cmd)
                        render_trigger["needed"] = True
                        continue

                    if line.lower() == "hide_zed_checks":
                        auto_check_mode["enabled"] = False
                        # Clear permission cache
                        permission_cache.clear()
                        render_trigger["needed"] = True
                        continue

                    # Check for "all" command
                    if line.lower() == "all":
                        # Check all relations
                        for idx in range(len(all_relations)):
                            rel = all_relations[idx]
                            has_perm, msg, cmd = check_permission_with_zed(rel)
                            permission_cache[idx] = (has_perm, msg, cmd)
                        # Signal that a render is needed
                        render_trigger["needed"] = True
                        continue

                    # Try to parse as index
                    try:
                        idx = int(line)
                        if 0 <= idx < len(all_relations):
                            # Check this relation
                            rel = all_relations[idx]
                            has_perm, msg, cmd = check_permission_with_zed(rel)
                            permission_cache[idx] = (has_perm, msg, cmd)
                            # Signal that a render is needed
                            render_trigger["needed"] = True
                        else:
                            # Invalid index - store error
                            permission_cache[-1] = (
                                False,
                                f"Invalid index: {idx} (valid: 0-{len(all_relations)-1})",
                                "",
                            )
                            render_trigger["needed"] = True
                    except ValueError:
                        # Not a number - ignore
                        pass
                except Exception:
                    # Ignore errors in input handling
                    pass
    except (FileNotFoundError, OSError) as e:
        # /dev/tty is not available in this environment (e.g., non-terminal, Windows, containerized environment)
        # Log to stderr but don't crash - interactive mode just won't work
        print(
            f"Warning: Interactive mode unavailable - /dev/tty cannot be opened ({e}). "
            "Running in non-interactive environment.",
            file=sys.stderr,
        )
    except Exception:
        # Other unexpected errors - just exit gracefully
        pass
    finally:
        if tty_input:
            try:
                tty_input.close()
            except Exception:
                pass


def build_graph_structure(relations):
    """
    Build a graph structure from relations.

    Returns:
        dict: {node_id: {'type': type, 'edges': [(relation, target_node_id)]}}
    """
    graph = {}

    for rel in relations:
        resource_node = f"{rel['resource_type']}:{rel['resource_id']}"
        subject_node = f"{rel['subject_type']}:{rel['subject_id']}"

        # Add resource node
        if resource_node not in graph:
            graph[resource_node] = {
                "type": rel["resource_type"],
                "id": rel["resource_id"],
                "edges": [],
            }

        # Add subject node
        if subject_node not in graph:
            graph[subject_node] = {
                "type": rel["subject_type"],
                "id": rel["subject_id"],
                "edges": [],
            }

        # Add edge from resource to subject
        edge_label = rel["relation"]
        if rel["subject_relation"]:
            edge_label += f"#{rel['subject_relation']}"

        graph[resource_node]["edges"].append((edge_label, subject_node))

    return graph


def render_graph(
    graph,
    uuid_colors,
    enable_color=True,
    clear_screen=True,
    show_names=False,
    name_cache=None,
    last_refresh_count=0,
    manual_refresh_hint=False,
    interactive=False,
    all_relations=None,
    permission_cache=None,
    auto_check_mode=None,
):
    """Render the graph as ASCII art with hierarchical structure."""
    if not graph:
        return

    # Always clear screen for visual mode to avoid overlapping text
    # clear_screen parameter now controls whether this is the first render or an update
    print("\033[2J\033[H", end="")  # Clear screen and move cursor to top

    # Header
    header_text = "Relation Graph Visualization"
    if manual_refresh_hint:
        header_text += " (Press Enter to refresh names)"
    if interactive:
        header_text += " - Interactive Mode (type index, 'all', 'show_zed_checks', 'hide_zed_checks')"

    if enable_color:
        print(f"{Colors.BOLD}{Colors.CYAN}╔{'═' * 120}╗{Colors.RESET}")
        print(
            f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET} {Colors.BOLD}{header_text}{Colors.RESET}"
            + " " * (120 - len(header_text) - 2)
            + f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}"
        )
        print(f"{Colors.BOLD}{Colors.CYAN}╚{'═' * 120}╝{Colors.RESET}")
    else:
        print("=" * 120)
        print(f" {header_text}")
        print("=" * 120)
    print()

    # Find root nodes (nodes that are not targets of any edges)
    all_targets = set()
    for node_data in graph.values():
        for _, target_node in node_data["edges"]:
            all_targets.add(target_node)

    root_nodes = [
        node_id for node_id in graph.keys() if node_id not in all_targets
    ] or [node_id for node_id, node_data in graph.items() if node_data["edges"]]

    visited = set()

    # Build edge-to-relation mapping for interactive mode
    edge_to_relation = {}
    if interactive and all_relations:
        for idx, rel in enumerate(all_relations):
            resource_node = f"{rel['resource_type']}:{rel['resource_id']}"
            subject_node = f"{rel['subject_type']}:{rel['subject_id']}"
            edge_label = rel["relation"]
            if rel["subject_relation"]:
                edge_label += f"#{rel['subject_relation']}"

            # Create edge key
            edge_key = (resource_node, edge_label, subject_node)
            edge_to_relation[edge_key] = (idx, rel)

    def format_node_display(node_type, node_uuid):
        """Format a node display with optional name."""
        if enable_color:
            uuid_color = get_uuid_color(node_uuid, uuid_colors)
            display = f"{Colors.BRIGHT_WHITE}{node_type}{Colors.RESET}:{uuid_color}{node_uuid}{Colors.RESET}"
        else:
            display = f"{node_type}:{node_uuid}"

        # Add name if requested
        if show_names and name_cache is not None:
            name = get_resource_name(node_type, node_uuid, name_cache)
            if name:
                if enable_color:
                    display += f" {Colors.BRIGHT_BLACK}[{name}]{Colors.RESET}"
                else:
                    display += f" [{name}]"

        return display

    def render_subtree(node_id, prefix="", depth=0, max_depth=10):
        """Recursively render a node's subtree."""
        if depth > max_depth or node_id in visited:
            return

        visited.add(node_id)

        node_data = graph.get(node_id)
        if not node_data:
            return

        edges = node_data["edges"]
        for i, (edge_label, target_node) in enumerate(edges):
            is_last_edge = i == len(edges) - 1

            target_data = graph.get(target_node)
            if not target_data:
                continue

            target_type = target_data["type"]
            target_uuid = target_data["id"]

            # Draw the edge
            edge_connector = "└──" if is_last_edge else "├──"
            if enable_color:
                edge_color = Colors.BOLD + Colors.MAGENTA
                edge_display = f"[{edge_color}{edge_label}{Colors.RESET}]"
            else:
                edge_display = f"[{edge_label}]"

            # Add index and permission check result for interactive mode
            prefix_display = ""
            if interactive:
                # Get the current node (resource) to build edge key
                edge_key = (node_id, edge_label, target_node)
                if edge_key in edge_to_relation:
                    rel_idx, rel = edge_to_relation[edge_key]

                    # Show index
                    if enable_color:
                        index_display = (
                            f"{Colors.BRIGHT_BLACK}[{rel_idx}]{Colors.RESET}"
                        )
                    else:
                        index_display = f"[{rel_idx}]"

                    # Show permission check result if available
                    if permission_cache and rel_idx in permission_cache:
                        cache_entry = permission_cache[rel_idx]
                        has_permission = (
                            cache_entry[0] if len(cache_entry) >= 1 else False
                        )
                        if has_permission:
                            if enable_color:
                                prefix_display = (
                                    f"{Colors.GREEN}✓{Colors.RESET} {index_display} "
                                )
                            else:
                                prefix_display = f"✓ {index_display} "
                        else:
                            if enable_color:
                                prefix_display = (
                                    f"{Colors.RED}✗{Colors.RESET} {index_display} "
                                )
                            else:
                                prefix_display = f"✗ {index_display} "
                    else:
                        prefix_display = f"{index_display} "

            print(f"{prefix}{edge_connector}{prefix_display}{edge_display}──>", end=" ")

            # Check if target has already been visited (avoid cycles)
            if target_node in visited:
                # Just show the target without expanding it
                target_display = format_node_display(target_type, target_uuid)
                if enable_color:
                    target_display += f" {Colors.BRIGHT_BLACK}(see above){Colors.RESET}"
                else:
                    target_display += " (see above)"
                print(target_display)
            else:
                # Show the target node
                target_display = format_node_display(target_type, target_uuid)
                print(target_display)

                # Recursively render the target's children
                edge_extension = "    " if is_last_edge else "│   "
                target_prefix = prefix + edge_extension

                # Recurse into the target node
                render_subtree(target_node, target_prefix, depth + 1, max_depth)

    def render_node(node_id, prefix="", is_last=True, depth=0):
        """Render a root node and its subtree."""
        node_data = graph.get(node_id)
        if not node_data:
            return

        node_type = node_data["type"]
        node_uuid = node_data["id"]

        # Format the node display
        node_display = format_node_display(node_type, node_uuid)

        # Draw the root node
        if depth == 0:
            print(f"{node_display}")
        else:
            connector = "└──" if is_last else "├──"
            print(f"{prefix}{connector} {node_display}")

        # Prepare prefix for children
        extension = "    " if is_last else "│   "
        child_prefix = prefix + extension

        # Recursively render the subtree
        render_subtree(node_id, child_prefix)

    # Render from each root
    for i, root in enumerate(root_nodes):
        is_last_root = i == len(root_nodes) - 1
        render_node(root, "", is_last_root, depth=0)
        if not is_last_root:
            print()

    print()

    # Summary
    num_nodes = len(graph)
    num_edges = sum(len(node_data["edges"]) for node_data in graph.values())

    summary_parts = [
        f"Nodes: {num_nodes}",
        f"Edges: {num_edges}",
        f"Roots: {len(root_nodes)}",
    ]
    if last_refresh_count > 0:
        summary_parts.append(f"Refreshed: {last_refresh_count}")

    # Add permission check statistics if in interactive mode
    if interactive and permission_cache:
        # Count checked permissions (excluding error entries like -1)
        checked_count = sum(idx >= 0 for idx in permission_cache.keys())
        if checked_count > 0:
            # Count how many exist vs don't exist
            exists_count = sum(
                idx >= 0 and len(cache_entry) >= 1 and cache_entry[0]
                for idx, cache_entry in permission_cache.items()
            )
            missing_count = sum(
                idx >= 0 and len(cache_entry) >= 1 and not cache_entry[0]
                for idx, cache_entry in permission_cache.items()
            )

            check_status = ""
            if auto_check_mode and auto_check_mode.get("enabled", False):
                check_status = " [AUTO]"

            if enable_color:
                summary_parts.append(
                    f"Checked: {checked_count}{check_status} ({Colors.GREEN}✓{Colors.RESET} {exists_count}, {Colors.RED}✗{Colors.RESET} {missing_count})"
                )
            else:
                summary_parts.append(
                    f"Checked: {checked_count}{check_status} (✓ {exists_count}, ✗ {missing_count})"
                )

    if enable_color:
        print(f"{Colors.BRIGHT_BLACK}{'─' * 120}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}{' | '.join(summary_parts)}{Colors.RESET}")
    else:
        print("-" * 120)
        print(" | ".join(summary_parts))

    # Show zed check commands if in auto-check mode
    if (
        interactive
        and auto_check_mode
        and auto_check_mode.get("enabled", False)
        and permission_cache
    ):
        print()
        if enable_color:
            print(f"{Colors.BRIGHT_BLACK}{'─' * 120}{Colors.RESET}")
            print(
                f"{Colors.BOLD}{Colors.CYAN}Zed Permission Check Commands:{Colors.RESET}"
            )
        else:
            print("-" * 120)
            print("Zed Permission Check Commands:")
        print()

        # Display check commands for all checked relations
        for idx in sorted(permission_cache.keys()):
            if idx >= 0 and idx < len(all_relations):
                cache_entry = permission_cache[idx]
                if len(cache_entry) >= 3:
                    has_perm, msg, cmd = cache_entry
                    # Show the command with result indicator
                    if enable_color:
                        status_icon = (
                            f"{Colors.GREEN}✓{Colors.RESET}"
                            if has_perm
                            else f"{Colors.RED}✗{Colors.RESET}"
                        )
                        print(
                            f"  {status_icon} [{idx}] {Colors.BRIGHT_BLACK}{cmd}{Colors.RESET}"
                        )
                    else:
                        status_icon = "✓" if has_perm else "✗"
                        print(f"  {status_icon} [{idx}] {cmd}")

    # Show commands footer in interactive mode
    if interactive:
        print()
        commands_text = "Commands: [0-N] check relation | 'all' check all | 'show_zed_checks' auto-check mode | 'hide_zed_checks' hide checks"
        if enable_color:
            print(f"{Colors.BRIGHT_BLACK}{commands_text}{Colors.RESET}")
        else:
            print(commands_text)


def colorize_relation(
    relation_str, uuid_colors, enable_color=True, show_names=False, name_cache=None
):
    """Add syntax highlighting to a relation string."""
    if not enable_color:
        # Even without color, we might want to show names
        if show_names and name_cache is not None:
            parts = relation_str.split()
            if len(parts) < 3:
                return relation_str

            result_parts = []
            for i, part in enumerate(parts):
                if ":" in part:
                    # Extract type and id
                    if "#" in part:
                        type_id, sub_rel = part.rsplit("#", 1)
                        type_part, id_part = type_id.split(":", 1)
                        display = f"{type_part}:{id_part}"

                        # Add name (before the #relation)
                        name = get_resource_name(type_part, id_part, name_cache)
                        if name:
                            display += f" [{name}]"

                        # Add the subject relation
                        display += f"#{sub_rel}"
                        result_parts.append(display)
                    else:
                        type_part, id_part = part.split(":", 1)
                        display = f"{type_part}:{id_part}"

                        # Add name
                        name = get_resource_name(type_part, id_part, name_cache)
                        if name:
                            display += f" [{name}]"

                        result_parts.append(display)
                else:
                    result_parts.append(part)

            return " ".join(result_parts)

        return relation_str

    # Pattern: resource_type:resource_id relation subject_type:subject_id[#subject_relation]
    parts = relation_str.split()
    if len(parts) < 3:
        return relation_str

    colored_parts = []
    for i, part in enumerate(parts):
        if ":" in part:
            # This is a resource or subject (type:id or type:id#relation)
            if "#" in part:
                # Has subject relation
                type_id, sub_rel = part.rsplit("#", 1)
                type_part, id_part = type_id.split(":", 1)

                # Color the UUID
                uuid_color = get_uuid_color(id_part, uuid_colors)
                colored_part = f"{Colors.BRIGHT_WHITE}{type_part}{Colors.RESET}:{uuid_color}{id_part}{Colors.RESET}"

                # Add name if requested (before the #relation)
                if show_names and name_cache is not None:
                    name = get_resource_name(type_part, id_part, name_cache)
                    if name:
                        colored_part += f" {Colors.BRIGHT_BLACK}[{name}]{Colors.RESET}"

                # Add the subject relation
                colored_part += f"#{Colors.MAGENTA}{sub_rel}{Colors.RESET}"
            else:
                type_part, id_part = part.split(":", 1)

                # Check if it's a UUID or wildcard
                if id_part == "*":
                    colored_part = f"{Colors.BRIGHT_WHITE}{type_part}{Colors.RESET}:{Colors.RED}{id_part}{Colors.RESET}"
                else:
                    uuid_color = get_uuid_color(id_part, uuid_colors)
                    colored_part = f"{Colors.BRIGHT_WHITE}{type_part}{Colors.RESET}:{uuid_color}{id_part}{Colors.RESET}"

                # Add name if requested
                if show_names and name_cache is not None:
                    name = get_resource_name(type_part, id_part, name_cache)
                    if name:
                        colored_part += f" {Colors.BRIGHT_BLACK}[{name}]{Colors.RESET}"

            colored_parts.append(colored_part)
        else:
            # This is a relation name
            colored_parts.append(f"{Colors.BOLD}{Colors.MAGENTA}{part}{Colors.RESET}")

    return " ".join(colored_parts)


def parse_relation(line):
    """
    Parse a relation line like:
    role_binding:9ccf2995-104c-465f-b6e2-71a9300ce9ca#role@role:b28522be-6044-4592-9f3f-65641fb645a3
    group:94bb1277-4e83-464c-9812-5447ca43b053#member@principal:localhost/lpichler-eng

    Returns:
        dict with resource_type, resource_id, relation, subject_type, subject_id, subject_relation
        or None if not a valid relation
    """
    # Match pattern: resource_type:resource_id#relation@subject_type:subject_id[#subject_relation]
    # Allow alphanumeric, hyphens, asterisks, slashes, and dots in IDs
    pattern = (
        r"(\w+):([a-zA-Z0-9\-\*\/\.]+)#(\w+)@(\w+):([a-zA-Z0-9\-\*\/\.]+)(?:#(\w+))?"
    )

    match = re.match(pattern, line.strip())
    if not match:
        return None

    resource_type, resource_id, relation, subject_type, subject_id, subject_relation = (
        match.groups()
    )

    return {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "relation": relation,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "subject_relation": subject_relation,
        "raw": line.strip(),
    }


def build_zed_check_command(relation_dict):
    """
    Build a zed permission check command for a relation.

    Returns:
        str: The zed permission check command
    """
    resource_type = relation_dict["resource_type"]
    if "/" not in resource_type:
        resource_type = f"rbac/{resource_type}"

    subject_type = relation_dict["subject_type"]
    if "/" not in subject_type:
        subject_type = f"rbac/{subject_type}"

    # Replace wildcards with 'all' for zed commands
    resource_id = relation_dict["resource_id"].replace("*", "all")
    subject_id = relation_dict["subject_id"].replace("*", "all")

    resource = f"{resource_type}:{resource_id}"
    subject = f"{subject_type}:{subject_id}"

    # The permission is the relation name
    permission = relation_dict["relation"]
    if not permission.startswith("t_"):
        permission = f"t_{permission}"

    # Add subject relation if present
    if relation_dict["subject_relation"]:
        subject_rel = relation_dict["subject_relation"]
        if subject_rel.startswith("t_"):
            subject_rel = subject_rel[2:]
        subject = f"{subject}#{subject_rel}"
    elif subject_type == "rbac/group":
        subject = f"{subject}#member"

    return f"zed permission check {resource} {permission} {subject}"


def is_zed_available():
    """Check if the 'zed' binary is available in PATH."""
    return shutil.which("zed") is not None


def check_permission_with_zed(relation_dict):
    """
    Check if a relation exists in SpiceDB using zed permission check.

    Returns:
        tuple: (bool, str, str) - (permission exists, output message, check command)
    """
    # Build the check command
    check_cmd = build_zed_check_command(relation_dict)

    if not is_zed_available():
        return (False, "'zed' binary not found in PATH.", check_cmd)

    try:
        result = subprocess.run(
            check_cmd.split(), capture_output=True, text=True, timeout=5
        )

        # Check if the output indicates permission exists
        # zed outputs "true" or "false" based on permission check
        output = result.stdout.strip().lower()
        has_permission = output == "true" or "true" in output

        return (
            has_permission,
            result.stdout.strip() if result.stdout else result.stderr.strip(),
            check_cmd,
        )
    except subprocess.TimeoutExpired:
        return (False, "Timeout", check_cmd)
    except FileNotFoundError:
        return (False, "zed command not found", check_cmd)
    except Exception as e:
        return (False, f"Subprocess failed: {str(e)}", check_cmd)


def format_as_zed(relation_dict):
    """
    Convert a parsed relation to zed command format.

    Example:
        zed relationship touch rbac/role_binding:UUID t_role rbac/role:UUID
    """
    # Add rbac/ namespace prefix if not present
    resource_type = relation_dict["resource_type"]
    if "/" not in resource_type:
        resource_type = f"rbac/{resource_type}"

    subject_type = relation_dict["subject_type"]
    if "/" not in subject_type:
        subject_type = f"rbac/{subject_type}"

    resource = f"{resource_type}:{relation_dict['resource_id']}"
    subject = f"{subject_type}:{relation_dict['subject_id']}"

    # Add t_ prefix to relation name if it doesn't already have it
    # The SpiceDB schema uses t_ prefix for all relations
    relation_name = relation_dict["relation"]
    if not relation_name.startswith("t_"):
        relation_name = f"t_{relation_name}"

    if relation_dict["subject_relation"]:
        # Subject relations reference permissions, not relations, so NO t_ prefix
        # e.g., group#member (not group#t_member)
        subject_rel = relation_dict["subject_relation"]
        # Remove t_ prefix if it exists (from logging output)
        if subject_rel.startswith("t_"):
            subject_rel = subject_rel[2:]
        subject = f"{subject}#{subject_rel}"
    elif subject_type == "rbac/group":
        # Groups require #member suffix when used as subjects
        # Note: use 'member' (the permission) not 't_member' (the relation)
        subject = f"{subject}#member"

    return f"zed relationship touch {resource} {relation_name} {subject}"


def extract_relations_from_line(line):
    """
    Extract relation from a log line.
    Handles different log formats:
    - Migration tool: INFO: role:UUID#relation@subject:ID
    - Dual write JSON logs: {"log":{"original":"role:UUID#relation@subject:ID"}}
    - Direct relation format: role:UUID#relation@subject:ID
    """
    # Look for lines that contain relation patterns
    if "#" not in line or "@" not in line:
        return None

    # Try to extract from JSON log format first
    if '"original":"' in line or '"original":' in line:
        import json

        try:
            # Find the JSON part
            json_start = line.find("{")
            if json_start != -1:
                json_obj = json.loads(line[json_start:])
                if "log" in json_obj and "original" in json_obj["log"]:
                    original = json_obj["log"]["original"]
                    result = parse_relation(original)
                    if result:
                        return result
        except (json.JSONDecodeError, KeyError):
            pass

    # Try to extract the relation part after INFO:
    if "INFO:" in line:
        parts = line.split("INFO:", 1)
        if len(parts) == 2:
            content = parts[1].strip()
            # Remove RELATION_ADDED: or RELATION_REMOVED: prefix if present
            for prefix in ["RELATION_ADDED:", "RELATION_REMOVED:", "REMOVE:"]:
                if content.startswith(prefix):
                    content = content[len(prefix) :].strip()
                    break
            result = parse_relation(content)
            if result:
                return result

    # Try parsing the whole line (for direct relation format)
    return parse_relation(line)


def main():
    parser = argparse.ArgumentParser(
        description="Parse RBAC relations from logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--zed", action="store_true", help="Convert relations to zed command format"
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Output raw relation format (default if --zed not specified)",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress header comments")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute zed commands (requires --zed flag)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show which relations are being created/touched",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Show only the zed command format (resource relation subject) without status symbols",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable syntax highlighting"
    )
    parser.add_argument(
        "--visual",
        action="store_true",
        help="Display relations as an ASCII graph structure (regenerates after each relation)",
    )
    parser.add_argument(
        "--visual-static",
        action="store_true",
        help="Display relations as an ASCII graph structure (only once at the end)",
    )
    parser.add_argument(
        "--show-names",
        action="store_true",
        help="Fetch and display names from RBAC database for resources (requires Django environment)",
    )
    parser.add_argument(
        "--filter-seeds",
        action="store_true",
        help="Filter out seeding-related log messages (for cleaner output when running server)",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help='Enable interactive mode (type index, "all", "show_zed_checks", "hide_zed_checks")',
    )

    args = parser.parse_args()

    # Validate execute flag
    if args.execute and not args.zed:
        parser.error("--execute requires --zed flag")

    # Default to raw if neither specified
    if not args.zed and not args.raw:
        args.raw = True

    if not args.quiet and not args.compact:
        if args.zed:
            print("# Generated zed commands from RBAC relations")
        else:
            print("# Extracted relations from RBAC logs")
        print()

    # Setup Django if --show-names is requested
    name_cache = {}
    if args.show_names and not setup_django():
        print(
            "Warning: Failed to setup Django environment. Names will not be shown.",
            file=sys.stderr,
        )
        args.show_names = False

    relation_count = 0
    uuid_colors = {}  # Track UUID to color mapping
    # Enable colors by default unless explicitly disabled with --no-color
    # (even when piping, since compact mode looks better with colors)
    enable_color = not args.no_color
    first_relation_in_batch = True  # Track first relation in a batch
    current_batch_uuid_colors = {}  # Colors for current request batch
    all_relations = []  # Store all parsed relations for visual mode

    # Interactive mode support
    permission_cache = {}  # Cache for permission check results {index: (bool, message)}
    input_thread = None
    stop_event = threading.Event()
    render_trigger = {"needed": False}  # Flag to trigger re-renders
    auto_check_mode = {"enabled": False}  # Flag for automatic permission checking mode

    # Start interactive input handler if in interactive visual mode
    if args.interactive and (args.visual or args.visual_static):
        input_thread = threading.Thread(
            target=interactive_input_handler,
            args=(
                all_relations,
                permission_cache,
                stop_event,
                render_trigger,
                auto_check_mode,
            ),
            daemon=True,
        )
        input_thread.start()

    # Visual mode throttling
    last_render_time = 0
    render_interval = 0.5  # Redraw at most every 0.5 seconds
    render_batch_size = 5  # Or redraw every N relations
    relations_since_render = 0
    screen_cleared = False  # Track if we've cleared the screen once

    # Patterns that indicate a new request/batch
    request_patterns = [
        r"POST.*workspaces",
        r"PUT.*workspaces",
        r"DELETE.*workspaces",
        r"POST.*roles",
        r"PUT.*roles",
        r"DELETE.*roles",
        r"POST.*groups",
        r"Publishing replication event",
        r"CREATE_WORKSPACE",
        r"CREATE_ROLE",
        r"CREATE_GROUP",
        r"ASSIGN_ROLE",
    ]

    # Patterns for seeding-related log messages to filter out
    seed_filter_patterns = (
        [
            r"Seeding permission changes",
            r"Seeding role changes",
            r"Seeding group changes",
            r"Finished seeding",
            r"eligible for removal",
            r"No change in system role",
            r"Created system role",
            r"Updated system role",
            r"Replicated system role",
            r"Default access already exists",
            r"Default admin access already exists",
            r"Watching for file changes",
            r"Performing system checks",
            r"System check identified",
            r"Django version",
            r"Starting development server",
            r"Quit the server with",
            r"October \d+, \d+",  # Date line
            r"\w+ \d+, \d+",  # Any date like "January 01, 2025"
        ]
        if args.filter_seeds
        else []
    )

    # Track if we're still in startup/seeding phase
    in_startup_phase = args.filter_seeds
    # Support both server startup and script startup markers
    seeding_complete_markers = [
        r"Starting development server at",
        r"Starting principal updates",
    ]

    stdin_closed = False
    try:
        while True:
            # Check for interactive render triggers even when no new input
            if (
                args.interactive
                and (args.visual or args.visual_static)
                and render_trigger.get("needed", False)
            ):
                render_trigger["needed"] = False
                if all_relations:
                    graph = build_graph_structure(all_relations)
                    refreshed_count = 0
                    if args.show_names:
                        refreshed_count = refresh_missing_names(graph, name_cache)

                    if args.visual:
                        render_graph(
                            graph,
                            uuid_colors,
                            enable_color,
                            clear_screen=not screen_cleared,
                            show_names=args.show_names,
                            name_cache=name_cache,
                            last_refresh_count=refreshed_count,
                            manual_refresh_hint=False,
                            interactive=args.interactive,
                            all_relations=all_relations,
                            permission_cache=permission_cache,
                            auto_check_mode=auto_check_mode,
                        )
                        screen_cleared = True
                    elif args.visual_static:
                        # For static mode, re-render immediately to show updates
                        render_graph(
                            graph,
                            uuid_colors,
                            enable_color,
                            clear_screen=True,
                            show_names=args.show_names,
                            name_cache=name_cache,
                            last_refresh_count=refreshed_count,
                            manual_refresh_hint=False,
                            interactive=args.interactive,
                            all_relations=all_relations,
                            permission_cache=permission_cache,
                            auto_check_mode=auto_check_mode,
                        )

            # Check if input is available with timeout
            if not stdin_closed and select.select([sys.stdin], [], [], 0.1)[0]:
                line = sys.stdin.readline()
                if not line:
                    # EOF reached on stdin
                    stdin_closed = True
                    # In interactive mode, don't exit - continue waiting for interactive commands
                    if args.interactive and (args.visual or args.visual_static):
                        continue
                    else:
                        break
            else:
                # No input available, continue to check render triggers
                # In interactive mode, keep running even after stdin closes
                if (
                    stdin_closed
                    and args.interactive
                    and (args.visual or args.visual_static)
                ):
                    # Keep the loop alive for interactive commands
                    time.sleep(0.1)
                    continue
                elif stdin_closed:
                    # Not in interactive mode and stdin closed, exit
                    break
                else:
                    continue

            # Check if seeding is complete (check all markers)
            if in_startup_phase and any(
                re.search(marker, line) for marker in seeding_complete_markers
            ):
                in_startup_phase = False
                continue  # Skip this line too

            # Skip everything during startup phase
            if in_startup_phase:
                continue

            # Filter out seeding logs if requested
            if args.filter_seeds and any(
                re.search(pattern, line) for pattern in seed_filter_patterns
            ):
                continue

            # Check if this line indicates a new request
            is_new_request = any(
                re.search(pattern, line, re.IGNORECASE) for pattern in request_patterns
            )

            # Visual mode: render pending relations when a new request starts
            if (
                is_new_request
                and not first_relation_in_batch
                and args.visual
                and relations_since_render > 0
            ):
                graph = build_graph_structure(all_relations)
                refreshed_count = 0
                if args.show_names:
                    refreshed_count = refresh_missing_names(graph, name_cache)

                clear_this_time = not screen_cleared
                screen_cleared = True

                render_graph(
                    graph,
                    uuid_colors,
                    enable_color,
                    clear_screen=clear_this_time,
                    show_names=args.show_names,
                    name_cache=name_cache,
                    last_refresh_count=refreshed_count,
                    manual_refresh_hint=False,
                    interactive=args.interactive,
                    all_relations=all_relations,
                    permission_cache=permission_cache,
                    auto_check_mode=auto_check_mode,
                )

                last_render_time = time.time()
                relations_since_render = 0

            if is_new_request and not first_relation_in_batch and args.compact:
                # Print separator before new request
                if enable_color:
                    print(f"{Colors.BRIGHT_BLACK}{'─' * 80}{Colors.RESET}")
                else:
                    print()
                # Reset UUID colors for new batch to get fresh colors
                current_batch_uuid_colors = {}
                first_relation_in_batch = True

            relation = extract_relations_from_line(line)
            if relation:
                relation_count += 1
                first_relation_in_batch = False
                all_relations.append(relation)

                # Auto-check new relation if in auto-check mode
                if args.interactive and auto_check_mode.get("enabled", False):
                    idx = len(all_relations) - 1
                    has_perm, msg, cmd = check_permission_with_zed(relation)
                    permission_cache[idx] = (has_perm, msg, cmd)

                # Visual mode: execute zed commands if requested, then regenerate graph
                if args.visual:
                    # Execute zed command if --execute flag is set
                    if args.zed and args.execute:
                        zed_cmd = format_as_zed(relation)
                        try:
                            result = subprocess.run(
                                zed_cmd.split(),
                                capture_output=True,
                                text=True,
                                check=True,
                            )
                            # Silent execution in visual mode - errors only
                        except subprocess.CalledProcessError as e:
                            # Only show errors
                            print(f"\n✗ Failed: {zed_cmd}", file=sys.stderr)
                            if e.stderr:
                                print(f"  Error: {e.stderr}", file=sys.stderr)
                        except FileNotFoundError:
                            print(
                                f"\n✗ Error: 'zed' command not found. Is zed installed?",
                                file=sys.stderr,
                            )
                            sys.exit(1)

                    # Now update the graph
                    relations_since_render += 1
                    current_time = time.time()

                    # Decide whether to render based on time, batch size, or interactive trigger
                    should_render = (
                        relations_since_render >= render_batch_size
                        or (current_time - last_render_time) >= render_interval
                        or (args.interactive and render_trigger.get("needed", False))
                    )

                    if should_render:
                        # Clear the render trigger
                        if args.interactive:
                            render_trigger["needed"] = False
                        graph = build_graph_structure(all_relations)

                        # Refresh missing names on every render
                        refreshed_count = 0
                        if args.show_names:
                            refreshed_count = refresh_missing_names(graph, name_cache)

                        # Only clear screen once at the start, then reuse the same window
                        clear_this_time = not screen_cleared
                        screen_cleared = True

                        render_graph(
                            graph,
                            uuid_colors,
                            enable_color,
                            clear_screen=clear_this_time,
                            show_names=args.show_names,
                            name_cache=name_cache,
                            last_refresh_count=refreshed_count,
                            manual_refresh_hint=False,
                            interactive=args.interactive,
                            all_relations=all_relations,
                            permission_cache=permission_cache,
                            auto_check_mode=auto_check_mode,
                        )

                        last_render_time = current_time
                        relations_since_render = 0
                    continue  # Skip normal output in visual mode

                # Visual static mode: just collect, don't display yet
                if args.visual_static:
                    continue  # Skip normal output in visual static mode

                if args.zed:
                    zed_cmd = format_as_zed(relation)
                    if args.execute:
                        # Execute the zed command
                        if args.verbose and not args.compact:
                            print(f"→ {zed_cmd}")
                        try:
                            result = subprocess.run(
                                zed_cmd.split(),
                                capture_output=True,
                                text=True,
                                check=True,
                            )
                            if args.compact:
                                # Compact mode: show just "resource relation subject"
                                parts = zed_cmd.split()
                                if (
                                    len(parts) >= 5
                                ):  # zed relationship touch resource relation subject
                                    compact_str = f"{parts[3]} {parts[4]} {parts[5]}"
                                    print(
                                        colorize_relation(
                                            compact_str,
                                            current_batch_uuid_colors,
                                            enable_color,
                                            show_names=args.show_names,
                                            name_cache=name_cache,
                                        )
                                    )
                                # Don't print stdout (token) in compact mode
                            elif not args.quiet and not args.verbose:
                                print(f"✓ {zed_cmd}")
                            elif args.verbose:
                                print(f"✓ Success")

                            # Only show stdout if not in compact mode
                            if result.stdout and not args.compact:
                                print(result.stdout, end="")
                        except subprocess.CalledProcessError as e:
                            if not args.compact:
                                print(f"✗ Failed: {zed_cmd}", file=sys.stderr)
                                if e.stderr:
                                    print(f"  Error: {e.stderr}", file=sys.stderr)
                        except FileNotFoundError:
                            print(
                                f"✗ Error: 'zed' command not found. Is zed installed?",
                                file=sys.stderr,
                            )
                            sys.exit(1)
                    else:
                        if args.compact:
                            # Compact mode: show just "resource relation subject"
                            parts = zed_cmd.split()
                            if (
                                len(parts) >= 5
                            ):  # zed relationship touch resource relation subject
                                compact_str = f"{parts[3]} {parts[4]} {parts[5]}"
                                print(
                                    colorize_relation(
                                        compact_str,
                                        current_batch_uuid_colors,
                                        enable_color,
                                        show_names=args.show_names,
                                        name_cache=name_cache,
                                    )
                                )
                        else:
                            print(zed_cmd)
                else:
                    print(relation["raw"])
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        # Handle broken pipe gracefully (e.g., when piping to head)
        pass

    # Final render for visual mode if there are unrendered relations
    if args.visual and all_relations and relations_since_render > 0:
        graph = build_graph_structure(all_relations)
        refreshed_count = 0
        if args.show_names:
            refreshed_count = refresh_missing_names(graph, name_cache)

        clear_this_time = not screen_cleared
        render_graph(
            graph,
            uuid_colors,
            enable_color,
            clear_screen=clear_this_time,
            show_names=args.show_names,
            name_cache=name_cache,
            last_refresh_count=refreshed_count,
            manual_refresh_hint=False,
            interactive=args.interactive,
            all_relations=all_relations,
            permission_cache=permission_cache,
            auto_check_mode=auto_check_mode,
        )

    # Final render for visual static mode - show once at the end
    if args.visual_static and all_relations:
        graph = build_graph_structure(all_relations)
        refreshed_count = 0
        if args.show_names:
            refreshed_count = refresh_missing_names(graph, name_cache)

        render_graph(
            graph,
            uuid_colors,
            enable_color,
            clear_screen=True,
            show_names=args.show_names,
            name_cache=name_cache,
            last_refresh_count=refreshed_count,
            manual_refresh_hint=False,
            interactive=args.interactive,
            all_relations=all_relations,
            permission_cache=permission_cache,
            auto_check_mode=auto_check_mode,
        )

    # Stop interactive input thread if it was started
    if input_thread:
        stop_event.set()
        input_thread.join(timeout=1.0)

    if (
        not args.quiet
        and not args.compact
        and not args.visual
        and not args.visual_static
    ):
        print(f"\n# Total relations found: {relation_count}", file=sys.stderr)


if __name__ == "__main__":
    main()
