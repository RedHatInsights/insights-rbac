"""Zed command utilities for SpiceDB operations."""

import shlex
import shutil
import subprocess
from typing import Dict, Tuple, List


def is_zed_available() -> bool:
    """Check if the 'zed' binary is available in PATH."""
    return shutil.which("zed") is not None


def build_zed_check_command(relation: Dict) -> List[str]:
    """
    Build a zed permission check command for a relation.

    Args:
        relation: Parsed relation dictionary

    Returns:
        List of command arguments for subprocess
    """
    resource_type = relation["resource_type"]
    if "/" not in resource_type:
        resource_type = f"rbac/{resource_type}"

    subject_type = relation["subject_type"]
    if "/" not in subject_type:
        subject_type = f"rbac/{subject_type}"

    # Replace wildcards with 'all' for zed commands
    resource_id = relation["resource_id"].replace("*", "all")
    subject_id = relation["subject_id"].replace("*", "all")

    resource = f"{resource_type}:{resource_id}"
    subject = f"{subject_type}:{subject_id}"

    # The permission is the relation name
    permission = relation["relation"]
    if not permission.startswith("t_"):
        permission = f"t_{permission}"

    # Add subject relation if present
    if relation["subject_relation"]:
        subject_rel = relation["subject_relation"]
        if subject_rel.startswith("t_"):
            subject_rel = subject_rel[2:]
        subject = f"{subject}#{subject_rel}"
    elif subject_type == "rbac/group":
        subject = f"{subject}#member"

    return ["zed", "permission", "check", resource, permission, subject]


def check_permission_with_zed(relation: Dict) -> Tuple[bool, str, str]:
    """
    Check if a relation exists in SpiceDB using zed permission check.

    Args:
        relation: Parsed relation dictionary

    Returns:
        tuple: (permission exists, output message, check command string)
    """
    # Build the check command
    cmd = build_zed_check_command(relation)
    cmd_str = " ".join(shlex.quote(arg) for arg in cmd)

    if not is_zed_available():
        return (False, "'zed' binary not found in PATH.", cmd_str)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

        # Check if the output indicates permission exists
        # zed outputs "true" or "false" based on permission check
        output = result.stdout.strip().lower()
        has_permission = output == "true" or "true" in output

        return (
            has_permission,
            result.stdout.strip() if result.stdout else result.stderr.strip(),
            cmd_str,
        )
    except subprocess.TimeoutExpired:
        return (False, "Timeout", cmd_str)
    except FileNotFoundError:
        return (False, "zed command not found", cmd_str)
    except Exception as e:
        return (False, f"Subprocess failed: {str(e)}", cmd_str)


def format_as_zed(relation: Dict) -> List[str]:
    """
    Convert a parsed relation to zed command arguments.

    Args:
        relation: Parsed relation dictionary

    Returns:
        List of command arguments for subprocess

    Example:
        ["zed", "relationship", "touch", "rbac/role_binding:UUID", "t_role", "rbac/role:UUID"]
    """
    # Add rbac/ namespace prefix if not present
    resource_type = relation["resource_type"]
    if "/" not in resource_type:
        resource_type = f"rbac/{resource_type}"

    subject_type = relation["subject_type"]
    if "/" not in subject_type:
        subject_type = f"rbac/{subject_type}"

    resource = f"{resource_type}:{relation['resource_id']}"
    subject = f"{subject_type}:{relation['subject_id']}"

    # Add t_ prefix to relation name if it doesn't already have it
    # The SpiceDB schema uses t_ prefix for all relations
    relation_name = relation["relation"]
    if not relation_name.startswith("t_"):
        relation_name = f"t_{relation_name}"

    if relation["subject_relation"]:
        # Subject relations reference permissions, not relations, so NO t_ prefix
        # e.g., group#member (not group#t_member)
        subject_rel = relation["subject_relation"]
        # Remove t_ prefix if it exists (from logging output)
        if subject_rel.startswith("t_"):
            subject_rel = subject_rel[2:]
        subject = f"{subject}#{subject_rel}"
    elif subject_type == "rbac/group":
        # Groups require #member suffix when used as subjects
        # Note: use 'member' (the permission) not 't_member' (the relation)
        subject = f"{subject}#member"

    return ["zed", "relationship", "touch", resource, relation_name, subject]


def format_as_zed_string(relation: Dict) -> str:
    """
    Convert a parsed relation to zed command string.

    Args:
        relation: Parsed relation dictionary

    Returns:
        Shell-quoted command string
    """
    cmd = format_as_zed(relation)
    return " ".join(shlex.quote(arg) for arg in cmd)
