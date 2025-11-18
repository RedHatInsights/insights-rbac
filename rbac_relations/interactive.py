"""Interactive mode utilities for permission checking."""

import select
import sys
from typing import Dict, List
from .zed import check_permission_with_zed


def interactive_input_handler(
    all_relations: List[Dict],
    permission_cache: Dict[int, tuple],
    stop_event,
    render_trigger: Dict[str, bool],
    auto_check_mode: Dict[str, bool],
) -> None:
    """
    Handle interactive input for permission checking.
    Runs in a separate thread to listen for user input from /dev/tty.

    Args:
        all_relations: List of all parsed relations
        permission_cache: Cache for permission check results
        stop_event: Threading event to signal shutdown
        render_trigger: Dict with 'needed' flag to trigger re-renders
        auto_check_mode: Dict with 'enabled' flag for auto-check mode
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

                    # Handle commands
                    if _handle_command(
                        line,
                        all_relations,
                        permission_cache,
                        render_trigger,
                        auto_check_mode,
                    ):
                        continue

                except Exception:
                    # Ignore errors in input handling
                    pass
    except OSError as e:
        # /dev/tty is not available in this environment
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


def _handle_command(
    line: str,
    all_relations: List[Dict],
    permission_cache: Dict[int, tuple],
    render_trigger: Dict[str, bool],
    auto_check_mode: Dict[str, bool],
) -> bool:
    """
    Handle a single interactive command.

    Args:
        line: Command line input
        all_relations: List of all parsed relations
        permission_cache: Cache for permission check results
        render_trigger: Dict with 'needed' flag to trigger re-renders
        auto_check_mode: Dict with 'enabled' flag for auto-check mode

    Returns:
        True if command was handled, False otherwise
    """
    line_lower = line.lower()

    # Check for mode toggle commands
    if line_lower == "show_zed_checks":
        auto_check_mode["enabled"] = True
        # Check all existing relations
        for idx in range(len(all_relations)):
            if idx not in permission_cache:
                rel = all_relations[idx]
                has_perm, msg, cmd = check_permission_with_zed(rel)
                permission_cache[idx] = (has_perm, msg, cmd)
        render_trigger["needed"] = True
        return True

    if line_lower == "hide_zed_checks":
        auto_check_mode["enabled"] = False
        # Clear permission cache
        permission_cache.clear()
        render_trigger["needed"] = True
        return True

    # Check for "all" command
    if line_lower == "all":
        # Check all relations
        for idx in range(len(all_relations)):
            rel = all_relations[idx]
            has_perm, msg, cmd = check_permission_with_zed(rel)
            permission_cache[idx] = (has_perm, msg, cmd)
        # Signal that a render is needed
        render_trigger["needed"] = True
        return True

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
        return True
    except ValueError:
        # Not a number - ignore
        return False
