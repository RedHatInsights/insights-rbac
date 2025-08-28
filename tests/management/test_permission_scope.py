"""
Tests for permission scope functionality.
"""

from unittest.mock import patch
from django.test import TestCase, override_settings
from management.permission_scope import (
    Scope,
    ImplicitResourceService,
)


class ConfigurablePermissionScopeTests(TestCase):
    """Test permission scope with configurable app mappings."""

    def test_scope_for_permission_with_custom_settings(self):
        """Test scope determination with custom app configurations using wildcards."""
        service = ImplicitResourceService(
            root_scope_permissions="custom_root_app:*:*",
            tenant_scope_permissions="custom_tenant_app:*:*",
        )

        # Custom configured apps
        self.assertEqual(service.scope_for_permission("custom_root_app:resource:verb"), Scope.ROOT)
        self.assertEqual(service.scope_for_permission("custom_tenant_app:resource:verb"), Scope.TENANT)

        # Unconfigured apps should default to DEFAULT
        self.assertEqual(service.scope_for_permission("unknown_app:resource:verb"), Scope.DEFAULT)
        self.assertEqual(service.scope_for_permission("inventory:groups:read"), Scope.DEFAULT)

    def test_scope_for_permission_all_default_when_empty_settings(self):
        """Test that all apps get DEFAULT scope when settings are empty."""
        service = ImplicitResourceService(
            root_scope_permissions="",
            tenant_scope_permissions="",
        )

        # All apps should default to DEFAULT scope
        test_apps = ["rbac", "advisor", "inventory", "cost-management", "unknown"]
        for app in test_apps:
            with self.subTest(app=app):
                self.assertEqual(service.scope_for_permission(f"{app}:resource:verb"), Scope.DEFAULT)

    def test_highest_scope_with_custom_settings(self):
        """Test highest scope calculation with custom app configurations."""
        service = ImplicitResourceService(
            root_scope_permissions="root1:*:*,root2:*:*",
            tenant_scope_permissions="tenant1:*:*,tenant2:*:*",
        )

        permissions = ["tenant1:resource:read", "root1:resource:write"]
        self.assertEqual(service.highest_scope_for_permissions(permissions), Scope.TENANT)


class PermissionScopeTests(TestCase):
    """Test permission scope determination functionality."""

    def test_scope_for_permission_default_apps(self):
        """Test that unconfigured apps default to DEFAULT scope."""
        service = ImplicitResourceService(
            root_scope_permissions="cost-management:*:*",
            tenant_scope_permissions="rbac:*:*",
        )

        # Test apps not in any scope configuration
        apps = ["advisor", "inventory", "unknown_app", "compliance"]
        verbs = ["read", "write", "delete"]
        resources = ["users", "groups", "policies"]

        for app in apps:
            for verb in verbs:
                for resource in resources:
                    permission = f"{app}:{resource}:{verb}"
                with self.subTest(permission=permission):
                    self.assertEqual(service.scope_for_permission(permission), Scope.DEFAULT)

    def test_scope_for_permission_root_apps(self):
        """Test that ROOT scope apps are correctly identified."""
        service = ImplicitResourceService(
            root_scope_permissions="cost-management:*:*,advisor:*:*",
            tenant_scope_permissions="rbac:*:*",
        )

        # Test apps in ROOT scope configuration
        root_apps = ["cost-management", "advisor"]
        verbs = ["read", "write", "delete"]
        resources = ["users", "groups", "policies"]

        for app in root_apps:
            for verb in verbs:
                for resource in resources:
                    permission = f"{app}:{resource}:{verb}"
                with self.subTest(permission=permission):
                    self.assertEqual(service.scope_for_permission(permission), Scope.ROOT)

    def test_scope_for_permission_tenant_apps(self):
        """Test that TENANT scope apps are correctly identified."""
        service = ImplicitResourceService(
            root_scope_permissions="cost-management:*:*",
            tenant_scope_permissions="rbac:*:*,inventory:*:*",
        )

        # Test apps in TENANT scope configuration
        tenant_apps = ["rbac", "inventory"]
        verbs = ["read", "write", "delete"]
        resources = ["users", "groups", "policies"]

        for app in tenant_apps:
            for verb in verbs:
                for resource in resources:
                    permission = f"{app}:{resource}:{verb}"
                with self.subTest(permission=permission):
                    self.assertEqual(service.scope_for_permission(permission), Scope.TENANT)

    def test_scope_for_permission_invalid_format(self):
        """Test that invalid permission formats default to DEFAULT scope."""
        service = ImplicitResourceService()

        invalid_permissions = [
            "invalid_format",
            "app:resource",  # Missing verb
            "app",  # Missing resource and verb
            "",  # Empty string
            "app:resource:verb:extra",  # Too many parts
        ]

        for permission in invalid_permissions:
            with self.subTest(permission=permission):
                self.assertEqual(service.scope_for_permission(permission), Scope.DEFAULT)

    def test_highest_scope_for_permissions(self):
        """Test highest scope determination among multiple permissions."""
        service = ImplicitResourceService(
            root_scope_permissions="root_app:*:*",
            tenant_scope_permissions="tenant_app:*:*",
        )

        # Mixed permissions should return highest scope (TENANT > ROOT > DEFAULT)
        permissions = ["default_app:resource:read", "tenant_app:resource:write"]
        self.assertEqual(service.highest_scope_for_permissions(permissions), Scope.TENANT)

        # ROOT permissions should return ROOT even when mixed with others
        permissions = ["default_app:resource:read", "root_app:resource:write"]
        self.assertEqual(service.highest_scope_for_permissions(permissions), Scope.ROOT)

        # All DEFAULT permissions should return DEFAULT
        permissions = ["default_app1:resource:read", "default_app2:resource:write"]
        self.assertEqual(service.highest_scope_for_permissions(permissions), Scope.DEFAULT)

        # Empty permissions list should return DEFAULT
        self.assertEqual(service.highest_scope_for_permissions([]), Scope.DEFAULT)


class PermissionFormatCompatibilityTests(TestCase):
    """Test V1/V2 permission format compatibility."""

    def test_v1_format_handling(self):
        """Test that scope_for_permission handles V1 permission format correctly."""
        service = ImplicitResourceService(root_scope_permissions="advisor:systems:read")
        v1_scope = service.scope_for_permission("advisor:systems:read")
        self.assertEqual(v1_scope, Scope.ROOT)

    def test_v1_format_with_wildcard_fallback(self):
        """Test V1 format with app-level wildcard matching."""
        service = ImplicitResourceService(tenant_scope_permissions="app:*:*")
        v1_scope = service.scope_for_permission("app:test:read")
        self.assertEqual(v1_scope, Scope.TENANT)

    def test_v1_format_unknown_permission(self):
        """Test V1 format with unknown permission defaults to DEFAULT."""
        service = ImplicitResourceService()
        v1_scope = service.scope_for_permission("unknown:action:read")
        self.assertEqual(v1_scope, Scope.DEFAULT)

    def test_complex_permission_support(self):
        """Test complex permissions with hyphens and dots are supported."""
        service = ImplicitResourceService(root_scope_permissions="cost-management:azure.subscription_guid:read")
        v1_scope = service.scope_for_permission("cost-management:azure.subscription_guid:read")
        self.assertEqual(v1_scope, Scope.ROOT)

    def test_v1_wildcard_support(self):
        """Test V1 format wildcard permission support."""
        service = ImplicitResourceService(root_scope_permissions="cost-management:azure.subscription_guid:*")
        # This should match the wildcard pattern
        v1_wildcard_scope = service.scope_for_permission("cost-management:azure.subscription_guid:read")
        self.assertEqual(v1_wildcard_scope, Scope.ROOT)

    def test_multiple_scope_patterns(self):
        """Test complex scenarios with multiple permission patterns."""
        service = ImplicitResourceService(
            root_scope_permissions="cost-management:*:*",
            tenant_scope_permissions="app:*:read",
        )

        # Test ROOT scope pattern
        scope_1 = service.scope_for_permission("cost-management:azure.subscription_guid:write")
        self.assertEqual(scope_1, Scope.ROOT)

        # Test TENANT scope pattern
        scope_2 = service.scope_for_permission("app:test:read")
        self.assertEqual(scope_2, Scope.TENANT)

        # Test fallback to DEFAULT
        scope_3 = service.scope_for_permission("unknown:anything:write")
        self.assertEqual(scope_3, Scope.DEFAULT)


class V2BoundResourceCreationTests(TestCase):
    """Test V2boundresource creation based on permission scopes."""

    def test_create_v2_bound_resource_for_permissions_tenant_scope(self):
        """Test V2boundresource creation for TENANT scope permissions."""
        service = ImplicitResourceService(tenant_scope_permissions="tenant_app:*:*")

        resource = service.create_v2_bound_resource_for_permissions(
            ["tenant_app:resource:read"],
            tenant_org_id="123456",
            default_workspace_id="workspace_123",
        )
        self.assertEqual(resource.resource_type, ("rbac", "tenant"))
        self.assertEqual(resource.resource_id, "localhost/123456")

    def test_create_v2_bound_resource_for_permissions_root_scope(self):
        """Test V2boundresource creation for ROOT scope permissions."""
        service = ImplicitResourceService(root_scope_permissions="root_app:*:*")

        resource = service.create_v2_bound_resource_for_permissions(
            ["root_app:resource:read"],
            tenant_org_id="123456",
            root_workspace_id="root_123",
        )
        self.assertEqual(resource.resource_type, ("rbac", "workspace"))
        self.assertEqual(resource.resource_id, "root_123")

    def test_create_v2_bound_resource_for_permissions_default_scope(self):
        """Test V2boundresource creation for DEFAULT scope permissions."""
        service = ImplicitResourceService()

        resource = service.create_v2_bound_resource_for_permissions(
            ["unknown_app:resource:read"],
            tenant_org_id="123456",
            default_workspace_id="default_123",
        )
        self.assertEqual(resource.resource_type, ("rbac", "workspace"))
        self.assertEqual(resource.resource_id, "default_123")

    def test_create_v2_bound_resource_for_permissions_mixed_scopes(self):
        """Test V2boundresource creation with mixed scope permissions (highest wins)."""
        service = ImplicitResourceService(
            root_scope_permissions="root_app:*:*",
            tenant_scope_permissions="tenant_app:*:*",
        )

        # Mixed scopes should use highest scope (TENANT)
        resource = service.create_v2_bound_resource_for_permissions(
            ["tenant_app:resource:read", "root_app:resource:write"],
            tenant_org_id="123456",
            root_workspace_id="root_123",
        )
        self.assertEqual(resource.resource_type, ("rbac", "tenant"))
        self.assertEqual(resource.resource_id, "localhost/123456")

    def test_create_v2_bound_resource_for_permissions_root_fallback_to_default(self):
        """Test ROOT scope fallback to default workspace when root_workspace_id not provided."""
        service = ImplicitResourceService(root_scope_permissions="root_app:*:*")

        resource = service.create_v2_bound_resource_for_permissions(
            ["root_app:resource:read"],
            tenant_org_id="123456",
            default_workspace_id="default_123",
            # root_workspace_id not provided
        )
        # Should fallback to default workspace
        self.assertEqual(resource.resource_type, ("rbac", "workspace"))
        self.assertEqual(resource.resource_id, "default_123")

    def test_create_v2_bound_resource_for_permissions_missing_default_workspace(self):
        """Test error when default_workspace_id is required but not provided."""
        service = ImplicitResourceService()

        with self.assertRaises(ValueError) as context:
            service.create_v2_bound_resource_for_permissions(
                ["unknown_app:resource:read"],
                tenant_org_id="123456",
                # default_workspace_id not provided
            )
        self.assertIn("default_workspace_id is required", str(context.exception))

    def test_create_v2_bound_resource_for_permissions_empty_permissions(self):
        """Test V2boundresource creation with empty permissions list."""
        service = ImplicitResourceService()

        resource = service.create_v2_bound_resource_for_permissions(
            [],
            tenant_org_id="123456",
            default_workspace_id="default_123",
        )
        # Empty permissions should default to DEFAULT scope
        self.assertEqual(resource.resource_type, ("rbac", "workspace"))
        self.assertEqual(resource.resource_id, "default_123")
