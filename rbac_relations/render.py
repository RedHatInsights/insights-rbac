"""Rendering and visualization utilities for RBAC relations."""

from typing import Dict, List, Optional
from .colors import Colors, get_uuid_color
from .db import get_resource_name


def build_graph_structure(relations: List[Dict]) -> Dict:
    """
    Build a graph structure from relations.

    Args:
        relations: List of parsed relation dictionaries

    Returns:
        dict: {node_id: {'type': type, 'id': id, 'edges': [(relation, target_node_id)]}}
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


def colorize_relation(
    relation_str: str,
    uuid_colors: Dict[str, str],
    enable_color: bool = True,
    show_names: bool = False,
    name_cache: Optional[Dict[str, Optional[str]]] = None,
) -> str:
    """
    Add syntax highlighting to a relation string.

    Args:
        relation_str: Relation string to colorize
        uuid_colors: Dictionary mapping UUIDs to colors
        enable_color: Whether to enable color output
        show_names: Whether to show resource names
        name_cache: Cache for resource names

    Returns:
        Colorized relation string
    """
    parts = relation_str.split()
    if len(parts) < 3:
        return relation_str

    # Helper to process a part (resource or subject)
    def process_part(part: str) -> str:
        if ":" not in part:
            # This is a relation name
            if enable_color:
                return f"{Colors.BOLD}{Colors.MAGENTA}{part}{Colors.RESET}"
            return part

        # Extract type and id
        if "#" in part:
            type_id, sub_rel = part.rsplit("#", 1)
            type_part, id_part = type_id.split(":", 1)

            if enable_color:
                uuid_color = get_uuid_color(id_part, uuid_colors)
                display = f"{Colors.BRIGHT_WHITE}{type_part}{Colors.RESET}:{uuid_color}{id_part}{Colors.RESET}"
            else:
                display = f"{type_part}:{id_part}"

            # Add name if requested
            if show_names and name_cache is not None:
                if name := get_resource_name(type_part, id_part, name_cache):
                    if enable_color:
                        display += f" {Colors.BRIGHT_BLACK}[{name}]{Colors.RESET}"
                    else:
                        display += f" [{name}]"

            # Add the subject relation
            if enable_color:
                display += f"#{Colors.MAGENTA}{sub_rel}{Colors.RESET}"
            else:
                display += f"#{sub_rel}"

            return display
        else:
            type_part, id_part = part.split(":", 1)

            if enable_color:
                if id_part == "*":
                    display = f"{Colors.BRIGHT_WHITE}{type_part}{Colors.RESET}:{Colors.RED}{id_part}{Colors.RESET}"
                else:
                    uuid_color = get_uuid_color(id_part, uuid_colors)
                    display = f"{Colors.BRIGHT_WHITE}{type_part}{Colors.RESET}:{uuid_color}{id_part}{Colors.RESET}"
            else:
                display = f"{type_part}:{id_part}"

            # Add name if requested
            if show_names and name_cache is not None:
                if name := get_resource_name(type_part, id_part, name_cache):
                    if enable_color:
                        display += f" {Colors.BRIGHT_BLACK}[{name}]{Colors.RESET}"
                    else:
                        display += f" [{name}]"

            return display

    return " ".join(process_part(part) for part in parts)


def render_graph(
    graph: Dict,
    uuid_colors: Dict[str, str],
    enable_color: bool = True,
    clear_screen: bool = True,
    show_names: bool = False,
    name_cache: Optional[Dict[str, Optional[str]]] = None,
    last_refresh_count: int = 0,
    manual_refresh_hint: bool = False,
    interactive: bool = False,
    all_relations: Optional[List[Dict]] = None,
    permission_cache: Optional[Dict[int, tuple]] = None,
    auto_check_mode: Optional[Dict] = None,
) -> None:
    """
    Render the graph as ASCII art with hierarchical structure.

    Args:
        graph: Graph structure to render
        uuid_colors: Dictionary mapping UUIDs to colors
        enable_color: Whether to enable color output
        clear_screen: Whether to clear the screen before rendering
        show_names: Whether to show resource names
        name_cache: Cache for resource names
        last_refresh_count: Number of names refreshed in last update
        manual_refresh_hint: Whether to show manual refresh hint
        interactive: Whether in interactive mode
        all_relations: List of all relations (for interactive mode)
        permission_cache: Cache for permission check results
        auto_check_mode: Auto-check mode state
    """
    if not graph:
        return

    # Always clear screen for visual mode to avoid overlapping text
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
    all_targets = {target_node for node_data in graph.values() for _, target_node in node_data["edges"]}

    root_nodes = [node_id for node_id in graph.keys() if node_id not in all_targets] or [
        node_id for node_id, node_data in graph.items() if node_data["edges"]
    ]

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

    def format_node_display(node_type: str, node_uuid: str) -> str:
        """Format a node display with optional name."""
        if enable_color:
            uuid_color = get_uuid_color(node_uuid, uuid_colors)
            display = f"{Colors.BRIGHT_WHITE}{node_type}{Colors.RESET}:{uuid_color}{node_uuid}{Colors.RESET}"
        else:
            display = f"{node_type}:{node_uuid}"

        # Add name if requested
        if show_names and name_cache is not None:
            if name := get_resource_name(node_type, node_uuid, name_cache):
                if enable_color:
                    display += f" {Colors.BRIGHT_BLACK}[{name}]{Colors.RESET}"
                else:
                    display += f" [{name}]"

        return display

    def render_subtree(node_id: str, prefix: str = "", depth: int = 0, max_depth: int = 10) -> None:
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
                        index_display = f"{Colors.BRIGHT_BLACK}[{rel_idx}]{Colors.RESET}"
                    else:
                        index_display = f"[{rel_idx}]"

                    # Show permission check result if available
                    if permission_cache and rel_idx in permission_cache:
                        cache_entry = permission_cache[rel_idx]
                        has_permission = cache_entry[0] if len(cache_entry) >= 1 else False
                        if has_permission:
                            if enable_color:
                                prefix_display = f"{Colors.GREEN}✓{Colors.RESET} {index_display} "
                            else:
                                prefix_display = f"✓ {index_display} "
                        else:
                            if enable_color:
                                prefix_display = f"{Colors.RED}✗{Colors.RESET} {index_display} "
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

    def render_node(node_id: str, prefix: str = "", is_last: bool = True, depth: int = 0) -> None:
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
                idx >= 0 and len(cache_entry) >= 1 and cache_entry[0] for idx, cache_entry in permission_cache.items()
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
                summary_parts.append(f"Checked: {checked_count}{check_status} (✓ {exists_count}, ✗ {missing_count})")

    if enable_color:
        print(f"{Colors.BRIGHT_BLACK}{'─' * 120}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}{' | '.join(summary_parts)}{Colors.RESET}")
    else:
        print("-" * 120)
        print(" | ".join(summary_parts))

    # Show zed check commands if in auto-check mode
    if interactive and auto_check_mode and auto_check_mode.get("enabled", False) and permission_cache:
        print()
        if enable_color:
            print(f"{Colors.BRIGHT_BLACK}{'─' * 120}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}Zed Permission Check Commands:{Colors.RESET}")
        else:
            print("-" * 120)
            print("Zed Permission Check Commands:")
        print()

        # Display check commands for all checked relations
        for idx in sorted(permission_cache.keys()):
            if idx >= 0 and all_relations and idx < len(all_relations):
                cache_entry = permission_cache[idx]
                if len(cache_entry) >= 3:
                    has_perm, msg, cmd = cache_entry
                    # Show the command with result indicator
                    if enable_color:
                        status_icon = f"{Colors.GREEN}✓{Colors.RESET}" if has_perm else f"{Colors.RED}✗{Colors.RESET}"
                        print(f"  {status_icon} [{idx}] {Colors.BRIGHT_BLACK}{cmd}{Colors.RESET}")
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
