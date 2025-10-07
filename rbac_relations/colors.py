"""Terminal color utilities for RBAC relations."""

import hashlib


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


def get_uuid_color(uuid_str, uuid_colors):
    """
    Get a consistent color for a UUID.

    Args:
        uuid_str: The UUID string to get a color for
        uuid_colors: Dictionary mapping UUIDs to colors (modified in place)

    Returns:
        ANSI color code string
    """
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
