#!/usr/bin/env python3
"""
Reset all system role versions to 1.

This is useful when testing the --force-create-relationships flag,
which only creates relations for roles that haven't changed.
By resetting all versions to 1, the next seeds run will update all roles
and regenerate all their relations.

Usage:
    DJANGO_READ_DOT_ENV_FILE=True pipenv run python scripts/reset_role_versions.py
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

from management.role.model import Role
from api.models import Tenant


def print_next_steps():
    """Print instructions for next steps after resetting role versions."""
    print()
    print("You can now run:")
    print(
        "  DJANGO_READ_DOT_ENV_FILE=True RBAC_LOG_RELATIONS=true pipenv run python rbac/manage.py seeds --force-create-relationships"
    )
    print()
    print("To visualize the relations:")
    print("  ... | ./scripts/parse_relations.py --visual-static --show-names --no-color")


def main():
    """Reset all system role versions to 1."""
    public_tenant = Tenant.objects.get(tenant_name="public")

    # Get current role count and versions
    roles = Role.objects.filter(tenant=public_tenant)
    total = roles.count()

    print(f"Found {total} system roles")

    # Reset all role versions to 1
    updated = roles.update(version=1)

    print(f"Reset {updated} role versions to 1")
    print_next_steps()


if __name__ == "__main__":
    main()
