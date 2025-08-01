"""
Tests for permission scope functionality.
"""

from django.test import TestCase
from management.permission_scope import (
    Scope,
    scope_for_permission,
    highest_scope_for_permissions,
    v2_permission_to_v1,
    v2_permissions_to_v1,
    highest_scope_for_v2_permissions,
)


class PermissionScopeTests(TestCase):
    """Test permission scope determination."""

    def test_scope_for_permission_default_apps(self):
        """Test that default apps return DEFAULT scope."""
        test_cases = [
            "inventory:groups:read",
            "patch:systems:write",
            "compliance:reports:read",
            "unknown_app:resource:verb",  # Unknown apps default to DEFAULT
        ]

        for permission in test_cases:
            with self.subTest(permission=permission):
                self.assertEqual(scope_for_permission(permission), Scope.DEFAULT)

    def test_scope_for_permission_root_apps(self):
        """Test that root apps return ROOT scope."""
        test_cases = [
            "advisor:recommendation:read",
            "vulnerability:cves:read",
            "drift:baselines:write",
        ]

        for permission in test_cases:
            with self.subTest(permission=permission):
                self.assertEqual(scope_for_permission(permission), Scope.ROOT)

    def test_scope_for_permission_tenant_apps(self):
        """Test that tenant apps return TENANT scope."""
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

    def test_highest_scope_for_permissions(self):
        """Test finding the highest scope among multiple permissions."""
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

    def test_highest_scope_for_v2_permissions(self):
        """Test finding highest scope for V2 permissions."""
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
