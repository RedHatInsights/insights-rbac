"""
Tests for permission scope functionality.
"""

from unittest.mock import patch
from django.test import TestCase, override_settings
from management.permission_scope import (
    Scope,
    scope_for_permission,
    highest_scope_for_permissions,
    v2_permission_to_v1,
    v2_permissions_to_v1,
    highest_scope_for_v2_permissions,
    _build_app_scope_mapping,
)


class AppScopeMappingTests(TestCase):
    """Test the dynamic app scope mapping configuration."""

    @override_settings(ROOT_SCOPE_APPS="advisor,vulnerability,drift", TENANT_SCOPE_APPS="rbac,cost-management")
    def test_build_app_scope_mapping_with_settings(self):
        """Test that mapping is built correctly from Django settings."""
        mapping = _build_app_scope_mapping()

        # Root scope apps
        self.assertEqual(mapping.get("advisor"), Scope.ROOT)
        self.assertEqual(mapping.get("vulnerability"), Scope.ROOT)
        self.assertEqual(mapping.get("drift"), Scope.ROOT)

        # Tenant scope apps
        self.assertEqual(mapping.get("rbac"), Scope.TENANT)
        self.assertEqual(mapping.get("cost-management"), Scope.TENANT)

        # Apps not in settings should not be in mapping (will default via fallback)
        self.assertNotIn("inventory", mapping)
        self.assertNotIn("patch", mapping)

    @override_settings(ROOT_SCOPE_APPS="", TENANT_SCOPE_APPS="")
    def test_build_app_scope_mapping_empty_settings(self):
        """Test that empty settings result in empty mapping."""
        mapping = _build_app_scope_mapping()
        self.assertEqual(mapping, {})

    @override_settings(ROOT_SCOPE_APPS=" app1 , app2 , ", TENANT_SCOPE_APPS=" app3 , app4 , ")
    def test_build_app_scope_mapping_with_whitespace(self):
        """Test that whitespace is properly stripped from app names."""
        mapping = _build_app_scope_mapping()

        self.assertEqual(mapping.get("app1"), Scope.ROOT)
        self.assertEqual(mapping.get("app2"), Scope.ROOT)
        self.assertEqual(mapping.get("app3"), Scope.TENANT)
        self.assertEqual(mapping.get("app4"), Scope.TENANT)

        # Should not contain empty strings
        self.assertNotIn("", mapping)

    @override_settings(ROOT_SCOPE_APPS="duplicate_app", TENANT_SCOPE_APPS="duplicate_app")
    def test_build_app_scope_mapping_duplicate_apps(self):
        """Test behavior when app appears in both settings (tenant wins)."""
        mapping = _build_app_scope_mapping()

        # Tenant scope should win since it's processed last
        self.assertEqual(mapping.get("duplicate_app"), Scope.TENANT)

    @override_settings(ROOT_SCOPE_APPS="app1,app2,app3", TENANT_SCOPE_APPS="app4,app5,app6")
    def test_build_app_scope_mapping_multiple_apps(self):
        """Test that multiple apps are processed correctly."""
        mapping = _build_app_scope_mapping()

        # All root apps should be mapped correctly
        for app in ["app1", "app2", "app3"]:
            self.assertEqual(mapping.get(app), Scope.ROOT)

        # All tenant apps should be mapped correctly
        for app in ["app4", "app5", "app6"]:
            self.assertEqual(mapping.get(app), Scope.TENANT)

        # Should have exactly 6 entries
        self.assertEqual(len(mapping), 6)


class ConfigurablePermissionScopeTests(TestCase):
    """Test permission scope with configurable app mappings."""

    @override_settings(ROOT_SCOPE_APPS="custom_root_app", TENANT_SCOPE_APPS="custom_tenant_app")
    def test_scope_for_permission_with_custom_settings(self):
        """Test scope determination with custom app configurations."""
        # Force reload of the mapping with new settings
        with patch("management.permission_scope.APP_SCOPE_MAPPING", _build_app_scope_mapping()):
            # Custom configured apps
            self.assertEqual(scope_for_permission("custom_root_app:resource:verb"), Scope.ROOT)
            self.assertEqual(scope_for_permission("custom_tenant_app:resource:verb"), Scope.TENANT)

            # Unconfigured apps should default to DEFAULT
            self.assertEqual(scope_for_permission("unknown_app:resource:verb"), Scope.DEFAULT)
            self.assertEqual(scope_for_permission("inventory:groups:read"), Scope.DEFAULT)

    @override_settings(ROOT_SCOPE_APPS="", TENANT_SCOPE_APPS="")
    def test_scope_for_permission_all_default_when_empty_settings(self):
        """Test that all apps get DEFAULT scope when settings are empty."""
        # Force reload of the mapping with new settings
        with patch("management.permission_scope.APP_SCOPE_MAPPING", _build_app_scope_mapping()):
            # All apps should default to DEFAULT scope
            test_apps = ["rbac", "advisor", "inventory", "cost-management", "unknown"]
            for app in test_apps:
                with self.subTest(app=app):
                    self.assertEqual(scope_for_permission(f"{app}:resource:verb"), Scope.DEFAULT)

    @override_settings(ROOT_SCOPE_APPS="root1,root2", TENANT_SCOPE_APPS="tenant1,tenant2")
    def test_highest_scope_with_custom_settings(self):
        """Test highest scope calculation with custom app configurations."""
        # Force reload of the mapping with new settings
        with patch("management.permission_scope.APP_SCOPE_MAPPING", _build_app_scope_mapping()):
            permissions = [
                "unknown:resource:verb",  # DEFAULT
                "root1:resource:verb",  # ROOT
                "tenant1:resource:verb",  # TENANT
            ]
            self.assertEqual(highest_scope_for_permissions(permissions), Scope.TENANT)


class PermissionScopeTests(TestCase):
    """
    Test permission scope determination.

    NOTE: These tests assume the default/legacy app mappings are configured.
    If running with custom Django settings, these tests may fail.
    The new tests above (AppScopeMappingTests, ConfigurablePermissionScopeTests)
    test the configurable behavior introduced in the recent changes.
    """

    @override_settings(ROOT_SCOPE_APPS="advisor,vulnerability,drift", TENANT_SCOPE_APPS="rbac,cost-management")
    def test_scope_for_permission_default_apps(self):
        """Test that default apps return DEFAULT scope."""
        # Force reload of the mapping with new settings
        with patch("management.permission_scope.APP_SCOPE_MAPPING", _build_app_scope_mapping()):
            test_cases = [
                "inventory:groups:read",
                "patch:systems:write",
                "compliance:reports:read",
                "unknown_app:resource:verb",  # Unknown apps default to DEFAULT
            ]

            for permission in test_cases:
                with self.subTest(permission=permission):
                    self.assertEqual(scope_for_permission(permission), Scope.DEFAULT)

    @override_settings(ROOT_SCOPE_APPS="advisor,vulnerability,drift", TENANT_SCOPE_APPS="rbac,cost-management")
    def test_scope_for_permission_root_apps(self):
        """Test that root apps return ROOT scope."""
        # Force reload of the mapping with new settings
        with patch("management.permission_scope.APP_SCOPE_MAPPING", _build_app_scope_mapping()):
            test_cases = [
                "advisor:recommendation:read",
                "vulnerability:cves:read",
                "drift:baselines:write",
            ]

            for permission in test_cases:
                with self.subTest(permission=permission):
                    self.assertEqual(scope_for_permission(permission), Scope.ROOT)

    @override_settings(ROOT_SCOPE_APPS="advisor,vulnerability,drift", TENANT_SCOPE_APPS="rbac,cost-management")
    def test_scope_for_permission_tenant_apps(self):
        """Test that tenant apps return TENANT scope."""
        # Force reload of the mapping with new settings
        with patch("management.permission_scope.APP_SCOPE_MAPPING", _build_app_scope_mapping()):
            test_cases = [
                "rbac:roles:read",
                "cost-management:costs:read",
            ]

            for permission in test_cases:
                with self.subTest(permission=permission):
                    self.assertEqual(scope_for_permission(permission), Scope.TENANT)

    def test_scope_for_malformed_permission(self):
        """Test that malformed permissions return DEFAULT scope."""
        test_cases = [
            "invalid_permission",
            "",
            "app",
            "app:resource",  # Missing verb
        ]

        for permission in test_cases:
            with self.subTest(permission=permission):
                self.assertEqual(scope_for_permission(permission), Scope.DEFAULT)

    @override_settings(ROOT_SCOPE_APPS="advisor,vulnerability,drift", TENANT_SCOPE_APPS="rbac,cost-management")
    def test_highest_scope_for_permissions(self):
        """Test finding the highest scope among multiple permissions."""
        # Force reload of the mapping with new settings
        with patch("management.permission_scope.APP_SCOPE_MAPPING", _build_app_scope_mapping()):
            # Mixed scopes - should return highest (TENANT)
            permissions = [
                "inventory:groups:read",  # DEFAULT
                "advisor:recommendation:read",  # ROOT
                "rbac:roles:read",  # TENANT
            ]
            self.assertEqual(highest_scope_for_permissions(permissions), Scope.TENANT)

            # Only DEFAULT and ROOT - should return ROOT
            permissions = [
                "inventory:groups:read",  # DEFAULT
                "advisor:recommendation:read",  # ROOT
            ]
            self.assertEqual(highest_scope_for_permissions(permissions), Scope.ROOT)

            # Only DEFAULT - should return DEFAULT
            permissions = ["inventory:groups:read"]
            self.assertEqual(highest_scope_for_permissions(permissions), Scope.DEFAULT)

            # Empty list - should return DEFAULT
            self.assertEqual(highest_scope_for_permissions([]), Scope.DEFAULT)

    def test_v2_permission_to_v1(self):
        """Test converting V2 permission format to V1."""
        test_cases = [
            ("inventory_groups_read", "inventory:groups:read"),
            ("advisor_recommendation_read", "advisor:recommendation:read"),
            ("rbac_roles_write", "rbac:roles:write"),
            ("malformed", "malformed"),  # Should return as-is if malformed
            ("app_resource", "app_resource"),  # Should return as-is if not enough parts
        ]

        for v2_perm, expected_v1 in test_cases:
            with self.subTest(v2_permission=v2_perm):
                self.assertEqual(v2_permission_to_v1(v2_perm), expected_v1)

    def test_v2_permissions_to_v1(self):
        """Test converting list of V2 permissions to V1."""
        v2_permissions = [
            "inventory_groups_read",
            "advisor_recommendation_read",
            "rbac_roles_write",
        ]

        expected_v1 = [
            "inventory:groups:read",
            "advisor:recommendation:read",
            "rbac:roles:write",
        ]

        self.assertEqual(v2_permissions_to_v1(v2_permissions), expected_v1)

    @override_settings(ROOT_SCOPE_APPS="advisor,vulnerability,drift", TENANT_SCOPE_APPS="rbac,cost-management")
    def test_highest_scope_for_v2_permissions(self):
        """Test finding highest scope for V2 permissions."""
        # Force reload of the mapping with new settings
        with patch("management.permission_scope.APP_SCOPE_MAPPING", _build_app_scope_mapping()):
            v2_permissions = [
                "inventory_groups_read",  # DEFAULT
                "advisor_recommendation_read",  # ROOT
                "rbac_roles_read",  # TENANT
            ]

            self.assertEqual(highest_scope_for_v2_permissions(v2_permissions), Scope.TENANT)

    def test_scope_enum_ordering(self):
        """Test that scope enum values are ordered correctly."""
        self.assertLess(Scope.DEFAULT, Scope.ROOT)
        self.assertLess(Scope.ROOT, Scope.TENANT)

        # Test that max() works correctly
        scopes = [Scope.DEFAULT, Scope.TENANT, Scope.ROOT]
        self.assertEqual(max(scopes), Scope.TENANT)
