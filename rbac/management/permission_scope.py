"""
Permission scope helper for determining workspace/tenant binding levels.

This module defines which permissions bind to which scopes:
- TENANT: Highest level (tenant-wide permissions)
- ROOT: Root workspace level
- DEFAULT: Default workspace level (lowest)

Permission scope mapping supports granular configuration via Django settings:
- ROOT_SCOPE_PERMISSIONS: Comma-separated list of permission patterns
  (e.g., "advisor:*:*, cost-management:azure.subscription_guid:read")
- TENANT_SCOPE_PERMISSIONS: Comma-separated list of permission patterns
  (e.g., "rbac:*:*, cost-management:costs:*")

Note: The scope_for_permission() function assumes input permissions are always
in valid "app:resource_type:verb" format.

Matching precedence (highest to lowest):
1. Exact app:resource_type:verb match in permission lists
2. Wildcard app:resource_type:* match in permission lists
3. Wildcard app:*:verb match in permission lists
4. Wildcard app:*:* match in permission lists
5. Default to DEFAULT scope
"""

from enum import IntEnum

from django.conf import settings
from migration_tool.models import V2boundresource, cleanNameForV2SchemaCompatibility


class Scope(IntEnum):
    """Permission scope levels, ordered from lowest to highest."""

    DEFAULT = 1  # Default workspace level
    ROOT = 2  # Root workspace level
    TENANT = 3  # Tenant level (highest)


class ImplicitResourceService:
    """
    Service for determining permission scopes and creating resources based on permissions.

    This service encapsulates all the permission scope logic and can be initialized
    with custom mappings for testing.
    """

    def __init__(
        self,
        root_scope_permissions: str = None,
        tenant_scope_permissions: str = None,
    ):
        """
        Initialize the service with permission mappings.

        Args:
            root_scope_permissions: Comma-separated ROOT scope permission patterns
            tenant_scope_permissions: Comma-separated TENANT scope permission patterns
        """
        # Use provided values or fall back to Django settings
        self.root_scope_permissions = root_scope_permissions or getattr(settings, "ROOT_SCOPE_PERMISSIONS", "")
        self.tenant_scope_permissions = tenant_scope_permissions or getattr(settings, "TENANT_SCOPE_PERMISSIONS", "")

        # Build mappings
        (
            self.exact_permissions,
            self.resource_wildcards,
            self.verb_wildcards,
            self.double_wildcards,
        ) = self._build_mappings()

    def refresh_from_settings(self) -> None:
        """Rebuild mappings from current Django settings.

        Useful in tests where settings are overridden.
        """
        new_root = getattr(settings, "ROOT_SCOPE_PERMISSIONS", "")
        new_tenant = getattr(settings, "TENANT_SCOPE_PERMISSIONS", "")

        # No-op if nothing changed to avoid unnecessary work
        if new_root == getattr(self, "root_scope_permissions", None) and new_tenant == getattr(
            self, "tenant_scope_permissions", None
        ):
            return

        self.root_scope_permissions = new_root
        self.tenant_scope_permissions = new_tenant
        (
            self.exact_permissions,
            self.resource_wildcards,
            self.verb_wildcards,
            self.double_wildcards,
        ) = self._build_mappings()

    def _build_mappings(self) -> tuple[
        dict[str, Scope],
        dict[str, Scope],
        dict[str, Scope],
        dict[str, Scope],
    ]:
        """Build permission scope mappings from instance settings."""
        exact_permissions = {}
        resource_wildcards = {}  # app:*:verb patterns
        verb_wildcards = {}  # app:resource:* patterns
        double_wildcards = {}  # app:*:* patterns

        def _process_permission_patterns(patterns: str, scope: Scope):
            """Process permission patterns and add to appropriate mappings (both V1 and V2 formats).

            Enforces app:resource_type:verb format. Bare app names are not allowed.
            Use wildcards like 'app:*:*' for app-level scope configuration.
            """
            for pattern in patterns.split(","):
                pattern = pattern.strip()
                if not pattern:
                    continue

                colon_count = pattern.count(":")

                if colon_count == 0:
                    # Reject bare app names - require explicit format
                    raise ValueError(
                        f"Invalid permission pattern '{pattern}'. "
                        f"Use full format 'app:resource_type:verb' or wildcards like 'app:*:*'"
                    )
                elif colon_count == 1:
                    # Reject app:resource format - require full three-part format
                    raise ValueError(
                        f"Invalid permission pattern '{pattern}'. "
                        f"Use full format 'app:resource_type:verb' or wildcards like 'app:*:*'"
                    )
                elif colon_count == 2:
                    # Full permission: "advisor:systems:read"
                    app, resource, verb = pattern.split(":")

                    # Handle wildcards
                    if resource == "*" and verb == "*":
                        # app:*:*
                        double_wildcards[pattern] = scope
                        # V2 format using cleanNameForV2SchemaCompatibility
                        v2_pattern = cleanNameForV2SchemaCompatibility(pattern)
                        double_wildcards[v2_pattern] = scope
                    elif resource == "*":
                        # app:*:verb
                        resource_wildcards[pattern] = scope
                        # V2 format using cleanNameForV2SchemaCompatibility
                        v2_pattern = cleanNameForV2SchemaCompatibility(pattern)
                        resource_wildcards[v2_pattern] = scope
                    elif verb == "*":
                        # app:resource:*
                        verb_wildcards[pattern] = scope
                        # V2 format using cleanNameForV2SchemaCompatibility
                        v2_pattern = cleanNameForV2SchemaCompatibility(pattern)
                        verb_wildcards[v2_pattern] = scope
                    else:
                        # Exact permission: app:resource:verb
                        exact_permissions[pattern] = scope
                        # V2 format using cleanNameForV2SchemaCompatibility
                        v2_pattern = cleanNameForV2SchemaCompatibility(pattern)
                        exact_permissions[v2_pattern] = scope

        # Process ROOT scope patterns
        _process_permission_patterns(self.root_scope_permissions, Scope.ROOT)

        # Process TENANT scope patterns
        _process_permission_patterns(self.tenant_scope_permissions, Scope.TENANT)

        return (
            exact_permissions,
            resource_wildcards,
            verb_wildcards,
            double_wildcards,
        )

    def scope_for_permission(self, permission: str) -> Scope:
        """
        Determine the scope for a given permission string with granular matching including wildcards.

        Args:
            permission: Permission string in V1 format "app:resource_type:verb"

        Returns:
            Scope enum value based on the most specific match found
        """
        # 1. Check exact permission match (most specific)
        if permission in self.exact_permissions:
            return self.exact_permissions[permission]

        # 2. Check wildcard patterns (in order of specificity)
        parts = permission.split(":")
        if len(parts) == 3:
            app, resource, verb = parts

            # Check app:resource:* patterns
            app_resource_star = f"{app}:{resource}:*"
            if app_resource_star in self.verb_wildcards:
                return self.verb_wildcards[app_resource_star]

            # Check app:*:verb patterns
            app_star_verb = f"{app}:*:{verb}"
            if app_star_verb in self.resource_wildcards:
                return self.resource_wildcards[app_star_verb]

            # Check app:*:* patterns
            app_star_star = f"{app}:*:*"
            if app_star_star in self.double_wildcards:
                return self.double_wildcards[app_star_star]

        # 3. Default scope (no fallback patterns)
        return Scope.DEFAULT

    def highest_scope_for_permissions(self, permissions) -> Scope:
        """Find the highest scope among a collection of V1 permissions."""
        if not permissions:
            return Scope.DEFAULT

        scopes = [self.scope_for_permission(perm) for perm in permissions]
        result = max(scopes, default=Scope.DEFAULT)
        return result

    def create_v2_bound_resource_for_permissions(
        self,
        permissions,
        tenant_org_id: str,
        root_workspace_id: str = None,
        default_workspace_id: str = None,
    ):
        """Create a V2boundresource based on the highest scope among the given permissions."""
        scope = self.highest_scope_for_permissions(permissions)

        if scope == Scope.TENANT:
            # Tenant-level permissions bind to the tenant resource
            tenant_resource_id = f"{settings.PRINCIPAL_USER_DOMAIN}/{tenant_org_id}"
            return V2boundresource(resource_type=("rbac", "tenant"), resource_id=tenant_resource_id)
        elif scope == Scope.ROOT:
            # Use root workspace if available, fallback to default workspace
            workspace_id = root_workspace_id if root_workspace_id else default_workspace_id
            if not workspace_id:
                raise ValueError("workspace_id is required for ROOT scope permissions")
            return V2boundresource(resource_type=("rbac", "workspace"), resource_id=workspace_id)
        else:  # DEFAULT scope
            if not default_workspace_id:
                raise ValueError("default_workspace_id is required for DEFAULT scope permissions")
            return V2boundresource(resource_type=("rbac", "workspace"), resource_id=default_workspace_id)


# Create default service instance using Django settings
_implicit_resource_service = ImplicitResourceService()
