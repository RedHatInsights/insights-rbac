#
# Copyright 2025 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""
Tests for permission scope functionality.
"""
from django.test import override_settings
from typing import Tuple
from unittest import TestCase
from management.permission_scope import ImplicitResourceService, Scope

DEFAULT_APPS = [
    "advisor",
    "inventory",
    "rbac",
]

INVALID_PERMISSIONS = [
    "",
    "app",
    "app:resource",
    "app:resource:verb:extra",
    "*:resource:verb",
    "app:resource:verb*",
    "app:resource*:verb",
    "app*:resource:verb",
]


class ConstructTest(TestCase):
    def test_construct_invalid_permission(self):
        """Test that ImplicitResourceService cannot be constructed with invalid permissions."""
        for permission in INVALID_PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertRaises(
                    ValueError,
                    ImplicitResourceService,
                    root_scope_permissions=[permission],
                    tenant_scope_permissions=[],
                )

                self.assertRaises(
                    ValueError,
                    ImplicitResourceService,
                    root_scope_permissions=["valid_app:resource:verb", permission],
                    tenant_scope_permissions=[],
                )

                self.assertRaises(
                    ValueError,
                    ImplicitResourceService,
                    root_scope_permissions=[],
                    tenant_scope_permissions=["valid_app:resource:verb", permission],
                )

    def test_construct_conflict(self):
        """Test that ImplicitResourceService cannot be constructed with conflicting assignments."""
        self.assertRaises(
            ValueError,
            ImplicitResourceService,
            root_scope_permissions=["app:resource:verb"],
            tenant_scope_permissions=["app:resource:verb"],
        )


class SinglePermissionTest(TestCase):
    def _assert_scope(self, scope: Scope, service: ImplicitResourceService, permission: str):
        actual_single = service.scope_for_permission(permission)

        self.assertEqual(
            scope,
            actual_single,
            f"Expected permission {permission} to have scope {scope.name}, but got {actual_single.name}",
        )

        actual_max = service.highest_scope_for_permissions([permission])

        self.assertEqual(
            scope,
            actual_max,
            f"Expected highest_scope_for_permissions to be consistent with scope_for_permission, "
            f"but got {scope} from scope_for_permission and {actual_max} from highest_scope_for_permissions "
            f"for permission {permission}",
        )

    def _assert_app_default(self, service: ImplicitResourceService, app: str):
        self._assert_scope(Scope.DEFAULT, service, f"{app}:resource:verb")
        self._assert_scope(Scope.DEFAULT, service, f"{app}:resource:*")
        self._assert_scope(Scope.DEFAULT, service, f"{app}:*:verb")
        self._assert_scope(Scope.DEFAULT, service, f"{app}:*:*")

    def test_empty_settings_default(self):
        """Test that empty scope lists result in all permissions being assigned to the default workspace."""
        service = ImplicitResourceService(
            root_scope_permissions=[],
            tenant_scope_permissions=[],
        )

        for app in DEFAULT_APPS:
            with self.subTest(app=app):
                self._assert_app_default(service, app)

    def test_construct_repeat(self):
        """Test that construction rejects invalid permissions."""
        service = ImplicitResourceService(
            root_scope_permissions=["app:resource:verb", "app:resource:verb"],
            tenant_scope_permissions=["other_app:other_resource:other_verb", "other_app:other_resource:other_verb"],
        )

        self._assert_scope(Scope.ROOT, service, "app:resource:verb")
        self._assert_scope(Scope.TENANT, service, "other_app:other_resource:other_verb")

    def test_single_query_invalid_permission(self):
        """Test that scope_for_permission rejects invalid permissions."""
        service = ImplicitResourceService(root_scope_permissions=[], tenant_scope_permissions=[])

        for permission in INVALID_PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertRaises(ValueError, service.scope_for_permission, permission)

    def test_single_match(self):
        """Test that each form of permission matches the expected set of permissions."""
        # The suffix to use (after "app:"), along with:
        # - Whether this suffix includes "app:resource:verb"
        # - Whether this suffix includes "app:resource:*"
        # - whether this suffix includes "app:*:verb"
        # - Whether this suffix includes "app:*:*"
        # For example, "app:*:*" includes both "app:resource:verb" and "app:resource:*"
        # because "*:*" is at least as broad as "resource:verb" and "resource:*".
        suffix_tests = [
            ("resource:verb", True, False, False, False),
            ("resource:*", True, True, False, False),
            ("*:verb", True, False, True, False),
            ("*:*", True, True, True, True),
        ]

        for suffix, match_simple, match_any_verb, match_any_resource, match_any in suffix_tests:
            with self.subTest(suffix=suffix):
                service = ImplicitResourceService(
                    root_scope_permissions=[f"root:{suffix}"],
                    tenant_scope_permissions=[f"tenant:{suffix}"],
                )

                scope_tests = [
                    ("root", Scope.ROOT),
                    ("tenant", Scope.TENANT),
                ]

                for app, target_scope in scope_tests:
                    with self.subTest(app=app, scope=target_scope):

                        def assert_target_if(condition: bool, permission: str):
                            self._assert_scope(target_scope if condition else Scope.DEFAULT, service, permission)

                        assert_target_if(match_simple, f"{app}:resource:verb")

                        assert_target_if(match_any_verb, f"{app}:resource:other_verb")
                        assert_target_if(match_any_verb, f"{app}:resource:*")

                        assert_target_if(match_any_resource, f"{app}:other_resource:verb")
                        assert_target_if(match_any_resource, f"{app}:*:verb")

                        assert_target_if(match_any, f"{app}:other_resource:other_verb")
                        assert_target_if(match_any, f"{app}:*:*")

                for app in DEFAULT_APPS:
                    with self.subTest(app=app, scope=Scope.DEFAULT):
                        self._assert_app_default(service, app)

    def test_match_exact_full_wildcard(self):
        """Test that an exact match takes precedence over a full wildcard."""
        service = ImplicitResourceService(
            root_scope_permissions=[
                "app:resource:verb",
            ],
            tenant_scope_permissions=[
                "app:*:*",
            ],
        )

        # An exact match should take precedence.
        self._assert_scope(Scope.ROOT, service, "app:resource:verb")

    def test_match_resource_verb_wildcard(self):
        """Test that resource and verb wildcards have the correct priority."""
        service = ImplicitResourceService(
            root_scope_permissions=[
                "app:resource:*",
                "app:override_resource:verb",
            ],
            tenant_scope_permissions=[
                "app:*:verb",
                "app:resource:override_verb",
            ],
        )

        # Exact matches take precedence.
        self._assert_scope(Scope.ROOT, service, "app:override_resource:verb")
        self._assert_scope(Scope.TENANT, service, "app:resource:override_verb")

        # If both wildcards apply, the verb wildcard takes precedence.
        self._assert_scope(Scope.ROOT, service, "app:resource:verb")

    def test_match_mixed_wildcards(self):
        """Test that multiple overlapping wildcards are handled correctly."""
        service = ImplicitResourceService(
            root_scope_permissions=[
                "app:resource:*",
                "app:*:verb",
            ],
            tenant_scope_permissions=[
                "app:resource:verb",
                "app:*:*",
            ],
        )

        # Exact match takes precedence over everything else.
        self._assert_scope(Scope.ROOT, service, "app:resource:*")
        self._assert_scope(Scope.ROOT, service, "app:*:verb")
        self._assert_scope(Scope.TENANT, service, "app:resource:verb")

        # More specific wildcards take precedence over full-app permissions.
        self._assert_scope(Scope.ROOT, service, "app:resource:other_verb")
        self._assert_scope(Scope.ROOT, service, "app:other_resource:verb")


class MaxPermissionTest(TestCase):
    def _assert_max_scope(self, scope: Scope, service: ImplicitResourceService, permissions: list[str]):
        self.assertEqual(scope, service.highest_scope_for_permissions(permissions))

    def test_empty(self):
        """Test that an empty list of permissions is assigned default workspace scope."""
        service = ImplicitResourceService(root_scope_permissions=["app:resource:verb"], tenant_scope_permissions=[])
        self._assert_max_scope(Scope.DEFAULT, service, [])

    def test_invalid(self):
        """Test that invalid permissions are correctly rejected."""
        service = ImplicitResourceService(root_scope_permissions=[], tenant_scope_permissions=["tenant_app:*:*"])

        for permission in INVALID_PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertRaises(
                    ValueError,
                    service.highest_scope_for_permissions,
                    [permission],
                )

                # Assert that we do not exit before validating all inputs,
                # even if a tenant scope permission occurs first.
                self.assertRaises(
                    ValueError,
                    service.highest_scope_for_permissions,
                    ["tenant_app:resource:verb", permission],
                )

    def test_single(self):
        """Test that single permissions are handled correctly."""
        service = ImplicitResourceService(
            root_scope_permissions=["app:resource:verb"],
            tenant_scope_permissions=["other_app:other_resource:other_verb"],
        )

        self._assert_max_scope(
            Scope.DEFAULT,
            service,
            ["elsewhere:resource:verb"],
        )

        self._assert_max_scope(
            Scope.ROOT,
            service,
            ["app:resource:verb"],
        )

        self._assert_max_scope(
            Scope.TENANT,
            service,
            ["other_app:other_resource:other_verb"],
        )

    def test_max_default(self):
        """Test that the max scope being the default workspace is handled correctly."""
        service = ImplicitResourceService(
            root_scope_permissions=["app:*:*", "other_app:*:*"],
            tenant_scope_permissions=[],
        )

        self._assert_max_scope(
            Scope.DEFAULT,
            service,
            ["unrelated:resource:verb", "elsewhere:*:*"],
        )

    def test_max_root(self):
        """Test that the max scope being the root workspace is handled correctly."""
        service = ImplicitResourceService(
            root_scope_permissions=["app:*:*", "other_app:resource:verb"],
            tenant_scope_permissions=["other_app:*:*"],
        )

        self._assert_max_scope(
            Scope.ROOT,
            service,
            ["app:resource:verb", "other_app:resource:verb", "app:*:other_verb", "default_app:*:*"],
        )

    def test_max_tenant(self):
        """Test that the max scope being tenant is handled correctly."""
        service = ImplicitResourceService(
            root_scope_permissions=["root_app:*:*"],
            tenant_scope_permissions=["tenant_app:*:*"],
        )

        self._assert_max_scope(
            Scope.TENANT,
            service,
            ["default_app:resource:verb", "tenant_app:other_resource:other_verb", "root_app:*:verb"],
        )

    def test_repeat(self):
        """Test that repeated permissions are handled correctly."""
        service = ImplicitResourceService(
            root_scope_permissions=["root_app:*:*"],
            tenant_scope_permissions=["tenant_app:*:*"],
        )

        self._assert_max_scope(
            Scope.DEFAULT,
            service,
            ["default_app:resource:verb", "default_app:resource:verb"],
        )

        self._assert_max_scope(
            Scope.ROOT,
            service,
            ["root_app:resource:verb", "root_app:resource:verb"],
        )

        self._assert_max_scope(
            Scope.TENANT,
            service,
            ["tenant_app:resource:verb", "tenant_app:resource:verb"],
        )


class ResourceTest(TestCase):
    org_id = "an_org"
    root_id = "root_workspace"
    default_id = "default_workspace"

    service = ImplicitResourceService(
        root_scope_permissions=["root_app:*:*"],
        tenant_scope_permissions=["tenant_app:*:*"],
    )

    def _assert_resource(self, resource_type: Tuple[str, str], resource_id: str, permissions: list[str]):
        """Assert that v2_bound_resource_for_permission returns the specified result."""
        result = self.service.v2_bound_resource_for_permission(
            permissions,
            tenant_org_id=self.org_id,
            root_workspace_id=self.root_id,
            default_workspace_id=self.default_id,
        )

        self.assertEqual(
            resource_type,
            result.resource_type,
            f"Expected bound resource for permissions {permissions} to be {resource_type}",
        )

        self.assertEqual(
            resource_id,
            result.resource_id,
            f"For permissions {permissions}, got correct resource type {resource_type}, but expected ID {resource_id}",
        )

    def test_invalid(self):
        """Test that invalid permissions are correctly rejected."""
        for permission in INVALID_PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertRaises(
                    ValueError,
                    self.service.v2_bound_resource_for_permission,
                    permissions=[permission],
                    tenant_org_id=self.org_id,
                    root_workspace_id=self.root_id,
                    default_workspace_id=self.default_id,
                )

                # Assert that we do not exit before validating all inputs,
                # even if a tenant scope permission occurs first.
                self.assertRaises(
                    ValueError,
                    self.service.v2_bound_resource_for_permission,
                    permissions=["tenant_app:resource:verb", permission],
                    tenant_org_id=self.org_id,
                    root_workspace_id=self.root_id,
                    default_workspace_id=self.default_id,
                )

    def test_empty(self):
        """Test that an empty set of permissions results in the default workspace."""
        self._assert_resource(
            resource_type=("rbac", "workspace"),
            resource_id=self.default_id,
            permissions=[],
        )

    def test_max_default(self):
        """Test that resources are correctly bound to the default workspace."""
        self._assert_resource(
            resource_type=("rbac", "workspace"),
            resource_id=self.default_id,
            permissions=["default_app:*:verb"],
        )

    def test_max_root(self):
        """Test that resources are correctly bound to the root workspace."""
        self._assert_resource(
            resource_type=("rbac", "workspace"),
            resource_id=self.root_id,
            permissions=["default_app:*:verb", "root_app:resource:*"],
        )

    @override_settings(PRINCIPAL_USER_DOMAIN="some_domain")
    def test_max_tenant(self):
        """Test that resources are correctly bound to the tenant."""
        self._assert_resource(
            resource_type=("rbac", "tenant"),
            resource_id=f"some_domain/{self.org_id}",
            permissions=["default_app:*:verb", "root_app:resource:*", "tenant_app:resource:verb"],
        )


class SettingsTest(TestCase):
    def test_settings_invalid(self):
        """Test that invalid settings are correctly rejected."""
        # The empty string is a valid setting, but no other invalid permission is.
        invalid_settings = [
            setting
            for setting in (
                INVALID_PERMISSIONS
                + [
                    "app:resource:verb;app:resource:verb",
                    "app:resource:verb,",
                    ",app:resource:verb",
                ]
            )
            if setting != ""
        ]

        for setting in invalid_settings:
            with self.subTest(setting=setting):
                with override_settings(ROOT_SCOPE_PERMISSIONS=setting):
                    self.assertRaises(ValueError, ImplicitResourceService.from_settings)

                with override_settings(TENANT_SCOPE_PERMISSIONS=setting):
                    self.assertRaises(ValueError, ImplicitResourceService.from_settings)

    def test_empty(self):
        """Test that blank settings are correctly parsed as no permissions."""
        empty_settings = [
            "",
            " ",
            "        ",
            "\t",
            "\n",
            "\r",
        ]

        for setting in empty_settings:
            with self.subTest(setting=setting):
                with override_settings(ROOT_SCOPE_PERMISSIONS=setting, TENANT_SCOPE_PERMISSIONS=setting):
                    service = ImplicitResourceService.from_settings()

                    self.assertEqual(
                        Scope.DEFAULT,
                        service.scope_for_permission("app:resource:verb"),
                    )

    def test_trim(self):
        """Test that whitespace is trimmed around permissions in settings."""
        with override_settings(
            ROOT_SCOPE_PERMISSIONS="\t  root_app:resource:verb,  root_app:resource:other_verb\n",
            TENANT_SCOPE_PERMISSIONS="\n\ntenant_app:resource:verb \r",
        ):
            service = ImplicitResourceService.from_settings()

            self.assertEqual(
                Scope.ROOT,
                service.scope_for_permission("root_app:resource:verb"),
            )

            self.assertEqual(
                Scope.ROOT,
                service.scope_for_permission("root_app:resource:other_verb"),
            )

            self.assertEqual(
                Scope.TENANT,
                service.scope_for_permission("tenant_app:resource:verb"),
            )

    def test_wildcard(self):
        """Test that wildcards are correctly parsed in settings."""
        with override_settings(
            ROOT_SCOPE_PERMISSIONS="root_app:*:*",
            TENANT_SCOPE_PERMISSIONS="tenant_app:*:*",
        ):
            service = ImplicitResourceService.from_settings()

            self.assertEqual(
                Scope.ROOT,
                service.scope_for_permission("root_app:resource:verb"),
            )

            self.assertEqual(
                Scope.TENANT,
                service.scope_for_permission("tenant_app:resource:verb"),
            )
