#!/usr/bin/env python3
"""
Check if a principal has access to inventory permissions in a workspace.

Usage:
    # Check if a principal has inventory_host_view permission in a workspace
    ./scripts/check_workspace_permissions.py --workspace <workspace-id> --principal <principal-id> --permission inventory_host_view

    # Check multiple inventory permissions
    ./scripts/check_workspace_permissions.py --workspace <workspace-id> --principal <principal-id> --check-inventory

    # Check through group membership
    ./scripts/check_workspace_permissions.py --workspace <workspace-id> --group <group-id> --permission inventory_host_view
"""

import argparse
import subprocess
import sys
import json
import shutil


def run_zed_check(
    resource_type,
    resource_id,
    permission,
    subject_type,
    subject_id,
    subject_relation=None,
):
    """
    Run zed permission check command.

    Returns:
        tuple: (has_permission: bool, output: str)
    """
    # Check if zed is available
    if not shutil.which("zed"):
        print(
            "✗ Error: 'zed' command not found in PATH. Is zed installed?",
            file=sys.stderr,
        )
        sys.exit(1)

    subject = f"rbac/{subject_type}:{subject_id}"
    if subject_relation:
        subject = f"{subject}#{subject_relation}"

    cmd = [
        "zed",
        "permission",
        "check",
        f"rbac/{resource_type}:{resource_id}",
        permission,
        subject,
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=30
        )

        # zed returns "true" or "false" in stdout
        has_permission = result.stdout.strip().lower() == "true"
        return has_permission, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out after 30 seconds"
    except PermissionError:
        return False, "Permission denied when executing zed command"
    except FileNotFoundError:
        # This shouldn't happen due to the check above, but handle it anyway
        print("✗ Error: 'zed' command not found. Is zed installed?", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


def check_permission(
    workspace_id, permission, principal_id=None, group_id=None, verbose=False
):
    """
    Check if principal or group has permission in workspace.
    """
    if principal_id:
        subject_type = "principal"
        subject_id = principal_id
        subject_relation = None
        subject_display = f"principal:{principal_id}"
    elif group_id:
        subject_type = "group"
        subject_id = group_id
        subject_relation = "member"
        subject_display = f"group:{group_id}#member"
    else:
        print("✗ Error: Must specify either --principal or --group", file=sys.stderr)
        sys.exit(1)

    cmd_display = f"zed permission check rbac/workspace:{workspace_id} {permission} rbac/{subject_display}"

    if verbose:
        print(f"→ Checking: {cmd_display}")

    has_permission, output = run_zed_check(
        "workspace",
        workspace_id,
        permission,
        subject_type,
        subject_id,
        subject_relation,
    )

    if has_permission:
        print(
            f"✓ GRANTED: {subject_display} has '{permission}' on workspace:{workspace_id}"
        )
        if verbose:
            print(f"  {output.strip()}")
        return True
    else:
        print(
            f"✗ DENIED: {subject_display} does NOT have '{permission}' on workspace:{workspace_id}"
        )
        if verbose:
            print(f"  {output.strip()}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Check workspace permissions for principals or groups",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--workspace", required=True, help="Workspace UUID to check")
    parser.add_argument(
        "--principal", help="Principal ID to check (e.g., localhost/username)"
    )
    parser.add_argument("--group", help="Group UUID to check")
    parser.add_argument(
        "--permission", help="Specific permission to check (e.g., inventory_host_view)"
    )
    parser.add_argument(
        "--check-inventory",
        action="store_true",
        help="Check all inventory host permissions",
    )
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")

    args = parser.parse_args()

    # Validate inputs
    if not args.principal and not args.group:
        parser.error("Must specify either --principal or --group")

    if args.principal and args.group:
        parser.error("Cannot specify both --principal and --group")

    if not args.permission and not args.check_inventory:
        parser.error("Must specify either --permission or --check-inventory")

    # Determine which permissions to check
    permissions = []
    if args.check_inventory:
        permissions = [
            "inventory_host_view",
            "inventory_host_update",
            "inventory_host_delete",
            "inventory_host_move",
        ]
    elif args.permission:
        permissions = [args.permission]

    # Run checks
    print(f"\nChecking permissions in workspace: {args.workspace}")
    if args.principal:
        print(f"For principal: {args.principal}")
    else:
        print(f"For group: {args.group}")
    print("=" * 80)

    results = {}
    for perm in permissions:
        granted = check_permission(
            args.workspace,
            perm,
            principal_id=args.principal,
            group_id=args.group,
            verbose=args.verbose,
        )
        results[perm] = granted

    # Summary
    print("\n" + "=" * 80)
    granted_count = sum(results.values())
    total_count = len(results)
    print(f"Summary: {granted_count}/{total_count} permissions granted")

    # Exit with error code if any permission was denied
    sys.exit(0 if granted_count == total_count else 1)


if __name__ == "__main__":
    main()
