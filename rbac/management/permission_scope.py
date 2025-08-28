"""
Permission scope helper for determining workspace/tenant binding levels.

This module defines which applications bind to which scopes:
- TENANT: Highest level (tenant-wide permissions)
- ROOT: Root workspace level
- DEFAULT: Default workspace level (lowest)

Application scope mapping is configured via Django settings:
- ROOT_SCOPE_APPS: Comma-separated list of apps that bind to root workspace
- TENANT_SCOPE_APPS: Comma-separated list of apps that bind to tenant level
- Apps not explicitly configured default to DEFAULT scope
"""

from enum import IntEnum
from typing import Iterable

from django.conf import settings


class Scope(IntEnum):
    """Permission scope levels, ordered from lowest to highest."""

    DEFAULT = 1  # Default workspace level
    ROOT = 2  # Root workspace level
    TENANT = 3  # Tenant level (highest)


def _build_app_scope_mapping() -> dict[str, Scope]:
    """Build the application scope mapping from Django settings."""
    mapping = {}

    # Root scope applications from settings
    root_apps = settings.ROOT_SCOPE_APPS
    for app in root_apps.split(","):
        app = app.strip()
        if app:
            mapping[app] = Scope.ROOT

    # Tenant scope applications from settings
    tenant_apps = settings.TENANT_SCOPE_APPS
    for app in tenant_apps.split(","):
        app = app.strip()
        if app:
            mapping[app] = Scope.TENANT

    # Apps not explicitly configured will default to DEFAULT scope
    # via the fallback in scope_for_permission()
    return mapping


# Map application names to their binding scope
APP_SCOPE_MAPPING: dict[str, Scope] = _build_app_scope_mapping()


def scope_for_permission(permission: str) -> Scope:
    """
    Determine the scope for a given permission string.

    Args:
        permission: Permission string in format "app:resource:verb"

    Returns:
        Scope enum value based on the application name
    """
    if not permission or ":" not in permission:
        return Scope.DEFAULT

    app_name = permission.split(":", 1)[0]
    return APP_SCOPE_MAPPING.get(app_name, Scope.DEFAULT)


def highest_scope_for_permissions(permissions: Iterable[str]) -> Scope:
    """
    Find the highest scope among a collection of permissions.

    Args:
        permissions: Iterable of permission strings

    Returns:
        The highest Scope found, or DEFAULT if no permissions
    """
    if not permissions:
        return Scope.DEFAULT

    return max((scope_for_permission(perm) for perm in permissions), default=Scope.DEFAULT)


def v2_permission_to_v1(v2_permission: str) -> str:
    """
    Convert V2 permission format back to V1 format.

    Args:
        v2_permission: V2 permission in format "app_resource_verb"

    Returns:
        V1 permission in format "app:resource:verb"
    """
    parts = v2_permission.split("_")
    if len(parts) >= 3:
        return f"{parts[0]}:{parts[1]}:{parts[2]}"
    return v2_permission  # Return as-is if format is unexpected


def v2_permissions_to_v1(v2_permissions: Iterable[str]) -> list[str]:
    """
    Convert a collection of V2 permissions to V1 format.

    Args:
        v2_permissions: Iterable of V2 permission strings

    Returns:
        List of V1 permission strings
    """
    return [v2_permission_to_v1(perm) for perm in v2_permissions]


def highest_scope_for_v2_permissions(v2_permissions: Iterable[str]) -> Scope:
    """
    Find the highest scope among a collection of V2 permissions.

    Args:
        v2_permissions: Iterable of V2 permission strings

    Returns:
        The highest Scope found, or DEFAULT if no permissions
    """
    v1_permissions = v2_permissions_to_v1(v2_permissions)
    return highest_scope_for_permissions(v1_permissions)
