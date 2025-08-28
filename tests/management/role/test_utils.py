"""Shared test utilities for role-related tests."""

from management.permission_scope import Scope, _build_permission_scope_mapping


def _build_app_scope_mapping() -> dict[str, Scope]:
    """
    Build app scope mapping from Django settings for testing compatibility.

    Returns:
        Dictionary mapping app names to their scopes
    """
    # Extract just the app scope mapping from the full mapping
    _, _, _, _, _, app_names = _build_permission_scope_mapping()
    return app_names
