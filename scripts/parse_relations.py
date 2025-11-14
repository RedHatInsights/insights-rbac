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

import sys
import os
import argparse
import subprocess
import select
import threading
import time
import re
import shlex

# Add parent directory to path to import rbac_relations package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rbac_relations.parser import extract_relations_from_line
from rbac_relations.zed import (
    format_as_zed,
    format_as_zed_string,
    check_permission_with_zed,
)
from rbac_relations.db import setup_django, refresh_missing_names
from rbac_relations.colors import Colors
from rbac_relations.render import build_graph_structure, render_graph, colorize_relation
from rbac_relations.interactive import interactive_input_handler


# Request patterns
REQUEST_PATTERNS = [
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

# Seed filter patterns
SEED_FILTER_PATTERNS = [
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
    r"October \d+, \d+",
    r"\w+ \d+, \d+",
]

SEEDING_COMPLETE_MARKERS = [
    r"Starting development server at",
    r"Starting principal updates",
]


def execute_zed_command(cmd_args, compact=False, verbose=False, quiet=False, enable_color=True):
    """
    Execute a zed command safely.

    Args:
        cmd_args: List of command arguments
        compact: Whether in compact mode
        verbose: Whether in verbose mode
        quiet: Whether in quiet mode
        enable_color: Whether to enable color output

    Returns:
        True if successful, False otherwise
    """
    cmd_str = " ".join(shlex.quote(arg) for arg in cmd_args)

    if verbose and not compact:
        print(f"→ {cmd_str}")

    try:
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            check=True,
        )
        if compact:
            # Compact mode: show just "resource relation subject"
            if len(cmd_args) >= 6:  # zed relationship touch resource relation subject
                compact_str = f"{cmd_args[3]} {cmd_args[4]} {cmd_args[5]}"
                return compact_str
            return None
        elif not quiet and not verbose:
            print(f"✓ {cmd_str}")
        elif verbose:
            print("✓ Success")

        # Return stdout if available and not in compact mode
        if result.stdout and not compact:
            return result.stdout
        return True
    except subprocess.CalledProcessError as e:
        if not compact:
            print(f"✗ Failed: {cmd_str}", file=sys.stderr)
            if e.stderr:
                print(f"  Error: {e.stderr}", file=sys.stderr)
        return False
    except FileNotFoundError:
        print(
            "✗ Error: 'zed' command not found. Is zed installed?",
            file=sys.stderr,
        )
        sys.exit(1)


def process_relation_output(
    relation,
    args,
    current_batch_uuid_colors,
    enable_color,
    name_cache,
):
    """Process and output a single relation based on arguments."""
    if args.zed:
        zed_cmd = format_as_zed(relation)
        if args.execute:
            # Execute the zed command
            result = execute_zed_command(
                zed_cmd,
                compact=args.compact,
                verbose=args.verbose,
                quiet=args.quiet,
                enable_color=enable_color,
            )
            if args.compact and isinstance(result, str):
                print(
                    colorize_relation(
                        result,
                        current_batch_uuid_colors,
                        enable_color,
                        show_names=args.show_names,
                        name_cache=name_cache,
                    )
                )
            elif isinstance(result, str):
                print(result, end="")
        else:
            if args.compact:
                # Compact mode: show just "resource relation subject"
                if len(zed_cmd) >= 6:
                    compact_str = f"{zed_cmd[3]} {zed_cmd[4]} {zed_cmd[5]}"
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
                print(format_as_zed_string(relation))
    else:
        print(relation["raw"])


def should_filter_line(line, in_startup_phase, args):
    """Check if a line should be filtered out."""
    # Check if seeding is complete
    if in_startup_phase:
        for marker in SEEDING_COMPLETE_MARKERS:
            if re.search(marker, line):
                return True, False  # Filter this line, exit startup phase

    # Skip everything during startup phase
    if in_startup_phase:
        return True, True  # Filter this line, stay in startup phase

    # Filter out seeding logs if requested
    if args.filter_seeds:
        for pattern in SEED_FILTER_PATTERNS:
            if re.search(pattern, line):
                return True, in_startup_phase

    return False, in_startup_phase


def render_graph_if_needed(
    all_relations,
    args,
    uuid_colors,
    enable_color,
    name_cache,
    screen_cleared,
    permission_cache,
    auto_check_mode,
):
    """Render graph if conditions are met."""
    if not all_relations:
        return screen_cleared

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
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Parse RBAC relations from logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--zed", action="store_true", help="Convert relations to zed command format")
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
    parser.add_argument("--no-color", action="store_true", help="Disable syntax highlighting")
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
    uuid_colors = {}
    enable_color = not args.no_color
    first_relation_in_batch = True
    current_batch_uuid_colors = {}
    all_relations = []

    # Interactive mode support
    permission_cache = {}
    input_thread = None
    stop_event = threading.Event()
    render_trigger = {"needed": False}
    auto_check_mode = {"enabled": False}

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
    render_interval = 0.5
    render_batch_size = 5
    relations_since_render = 0
    screen_cleared = False

    # Track startup phase
    in_startup_phase = args.filter_seeds

    stdin_closed = False
    try:
        while True:
            # Check for interactive render triggers
            if args.interactive and (args.visual or args.visual_static) and render_trigger.get("needed", False):
                render_trigger["needed"] = False
                if all_relations:
                    screen_cleared = render_graph_if_needed(
                        all_relations,
                        args,
                        uuid_colors,
                        enable_color,
                        name_cache,
                        screen_cleared,
                        permission_cache,
                        auto_check_mode,
                    )

            # Check if input is available with timeout
            if not stdin_closed and select.select([sys.stdin], [], [], 0.1)[0]:
                line = sys.stdin.readline()
                if not line:
                    stdin_closed = True
                    if args.interactive and (args.visual or args.visual_static):
                        continue
                    else:
                        break
            else:
                if stdin_closed and args.interactive and (args.visual or args.visual_static):
                    time.sleep(0.1)
                    continue
                elif stdin_closed:
                    break
                else:
                    continue

            # Filter line if needed
            should_skip, in_startup_phase = should_filter_line(line, in_startup_phase, args)
            if should_skip:
                continue

            # Check if this line indicates a new request
            is_new_request = any(re.search(pattern, line, re.IGNORECASE) for pattern in REQUEST_PATTERNS)

            # Visual mode: render pending relations when a new request starts
            if is_new_request and not first_relation_in_batch and args.visual and relations_since_render > 0:
                screen_cleared = render_graph_if_needed(
                    all_relations,
                    args,
                    uuid_colors,
                    enable_color,
                    name_cache,
                    screen_cleared,
                    permission_cache,
                    auto_check_mode,
                )
                last_render_time = time.time()
                relations_since_render = 0

            if is_new_request and not first_relation_in_batch and args.compact:
                # Print separator before new request
                if enable_color:
                    print(f"{Colors.BRIGHT_BLACK}{'─' * 80}{Colors.RESET}")
                else:
                    print()
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
                    if args.zed and args.execute:
                        zed_cmd = format_as_zed(relation)
                        result = execute_zed_command(zed_cmd, compact=True, enable_color=enable_color)
                        if result is False:
                            print(
                                f"\n✗ Failed: {format_as_zed_string(relation)}",
                                file=sys.stderr,
                            )

                    relations_since_render += 1
                    current_time = time.time()

                    should_render = (
                        relations_since_render >= render_batch_size
                        or (current_time - last_render_time) >= render_interval
                        or (args.interactive and render_trigger.get("needed", False))
                    )

                    if should_render:
                        if args.interactive:
                            render_trigger["needed"] = False

                        screen_cleared = render_graph_if_needed(
                            all_relations,
                            args,
                            uuid_colors,
                            enable_color,
                            name_cache,
                            screen_cleared,
                            permission_cache,
                            auto_check_mode,
                        )
                        last_render_time = current_time
                        relations_since_render = 0
                    continue

                # Visual static mode: just collect, don't display yet
                if args.visual_static:
                    continue

                process_relation_output(
                    relation,
                    args,
                    current_batch_uuid_colors,
                    enable_color,
                    name_cache,
                )
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        pass

    # Final render for visual mode
    if args.visual and all_relations and relations_since_render > 0:
        render_graph_if_needed(
            all_relations,
            args,
            uuid_colors,
            enable_color,
            name_cache,
            screen_cleared,
            permission_cache,
            auto_check_mode,
        )

    # Final render for visual static mode
    if args.visual_static and all_relations:
        render_graph_if_needed(
            all_relations,
            args,
            uuid_colors,
            enable_color,
            name_cache,
            True,  # Always clear screen for static mode
            permission_cache,
            auto_check_mode,
        )

    # Stop interactive input thread
    if input_thread:
        stop_event.set()
        input_thread.join(timeout=1.0)

    if not args.quiet and not args.compact and not args.visual and not args.visual_static:
        print(f"\n# Total relations found: {relation_count}", file=sys.stderr)


if __name__ == "__main__":
    main()
