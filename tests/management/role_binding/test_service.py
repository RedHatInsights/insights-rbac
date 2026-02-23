#
# Copyright 2025 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Tests for the RoleBindingService and Serializer."""

from django.test import TestCase, override_settings

from management.models import Group, Permission, Principal, Workspace
from management.role.v2_model import RoleV2
from management.role.v2_service import RoleV2Service
from management.role_binding.model import RoleBinding, RoleBindingGroup, RoleBindingPrincipal
from management.role_binding.serializer import RoleBindingByGroupSerializer, RoleBindingFieldSelection
from management.role_binding.service import RoleBindingService
from management.utils import FieldSelectionValidationError
from management.tenant_mapping.model import TenantMapping
from tests.identity_request import IdentityRequest


class FieldSelectionTests(TestCase):
    """Tests for RoleBindingFieldSelection dataclass and parsing."""

    def test_parse_returns_none_for_empty_string(self):
        """Test that parse returns None for empty string."""
        result = RoleBindingFieldSelection.parse("")
        self.assertIsNone(result)

    def test_parse_returns_none_for_none(self):
        """Test that parse returns None for None input."""
        result = RoleBindingFieldSelection.parse(None)
        self.assertIsNone(result)

    def test_parse_root_level_field(self):
        """Test parsing a root level field."""
        result = RoleBindingFieldSelection.parse("last_modified")
        self.assertIsNotNone(result)
        self.assertIn("last_modified", result.root_fields)

    def test_parse_subject_fields(self):
        """Test parsing subject fields."""
        result = RoleBindingFieldSelection.parse("subject(group.name,group.description)")
        self.assertIsNotNone(result)
        self.assertIn("group.name", result.get_nested("subject"))
        self.assertIn("group.description", result.get_nested("subject"))

    def test_parse_role_fields(self):
        """Test parsing role fields."""
        result = RoleBindingFieldSelection.parse("role(name,id)")
        self.assertIsNotNone(result)
        self.assertIn("name", result.get_nested("role"))
        self.assertIn("id", result.get_nested("role"))

    def test_parse_resource_fields(self):
        """Test parsing resource fields."""
        result = RoleBindingFieldSelection.parse("resource(name,type)")
        self.assertIsNotNone(result)
        self.assertIn("name", result.get_nested("resource"))
        self.assertIn("type", result.get_nested("resource"))

    def test_parse_multiple_objects(self):
        """Test parsing multiple object field selections."""
        result = RoleBindingFieldSelection.parse("subject(group.name),role(name),resource(type)")
        self.assertIsNotNone(result)
        self.assertIn("group.name", result.get_nested("subject"))
        self.assertIn("name", result.get_nested("role"))
        self.assertIn("type", result.get_nested("resource"))

    def test_parse_mixed_root_and_object_fields(self):
        """Test parsing mixed root and object fields."""
        result = RoleBindingFieldSelection.parse("last_modified,subject(group.name)")
        self.assertIsNotNone(result)
        self.assertIn("last_modified", result.root_fields)
        self.assertIn("group.name", result.get_nested("subject"))

    def test_parse_handles_whitespace(self):
        """Test that parsing handles whitespace correctly."""
        result = RoleBindingFieldSelection.parse(" subject( group.name , group.description ) ")
        self.assertIsNotNone(result)
        self.assertIn("group.name", result.get_nested("subject"))
        self.assertIn("group.description", result.get_nested("subject"))

    def test_split_fields_respects_parentheses(self):
        """Test that field splitting respects parentheses."""
        parts = RoleBindingFieldSelection._split_fields("subject(a,b),role(c)")
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0], "subject(a,b)")
        self.assertEqual(parts[1], "role(c)")

    def test_parse_raises_error_for_invalid_subject_field(self):
        """Test that parse raises error for invalid subject field."""
        with self.assertRaises(FieldSelectionValidationError) as context:
            RoleBindingFieldSelection.parse("subject(invalid_field)")
        self.assertIn("invalid_field", str(context.exception))

    def test_parse_raises_error_for_invalid_role_field(self):
        """Test that parse raises error for invalid role field."""
        with self.assertRaises(FieldSelectionValidationError) as context:
            RoleBindingFieldSelection.parse("role(invalid_field)")
        self.assertIn("invalid_field", str(context.exception))

    def test_parse_raises_error_for_invalid_resource_field(self):
        """Test that parse raises error for invalid resource field."""
        with self.assertRaises(FieldSelectionValidationError) as context:
            RoleBindingFieldSelection.parse("resource(invalid_field)")
        self.assertIn("invalid_field", str(context.exception))

    def test_parse_raises_error_for_unknown_object_type(self):
        """Test that parse raises error for unknown object type."""
        with self.assertRaises(FieldSelectionValidationError) as context:
            RoleBindingFieldSelection.parse("unknown(field)")
        self.assertIn("Unknown object type", str(context.exception))

    def test_parse_raises_error_for_invalid_root_field(self):
        """Test that parse raises error for invalid root field."""
        with self.assertRaises(FieldSelectionValidationError) as context:
            RoleBindingFieldSelection.parse("invalid_root_field")
        self.assertIn("Unknown field", str(context.exception))


class RoleBindingServiceTests(IdentityRequest):
    """Tests for RoleBindingService."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        # Create workspace hierarchy
        self.root_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.ROOT,
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
        )
        self.default_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.DEFAULT,
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            parent=self.root_workspace,
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            description="Test workspace description",
            tenant=self.tenant,
            type=Workspace.Types.STANDARD,
            parent=self.default_workspace,
        )

        # Create permission and role
        self.permission = Permission.objects.create(
            permission="app:resource:read",
            tenant=self.tenant,
        )

        self.role = RoleV2.objects.create(
            name="test_role",
            tenant=self.tenant,
        )
        self.role.permissions.add(self.permission)

        # Create group with principal
        self.group = Group.objects.create(
            name="test_group",
            description="Test group description",
            tenant=self.tenant,
        )
        self.principal = Principal.objects.create(
            username="testuser",
            tenant=self.tenant,
            type=Principal.Types.USER,
        )
        self.group.principals.add(self.principal)

        # Create role binding
        self.binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id=str(self.workspace.id),
            tenant=self.tenant,
        )
        RoleBindingGroup.objects.create(
            group=self.group,
            binding=self.binding,
        )

        self.service = RoleBindingService(tenant=self.tenant)

    def tearDown(self):
        """Tear down test data."""
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.all().delete()
        self.group.principals.clear()
        Principal.objects.filter(tenant=self.tenant).delete()
        Group.objects.filter(tenant=self.tenant).delete()
        RoleV2.objects.filter(tenant=self.tenant).delete()
        Permission.objects.filter(tenant=self.tenant).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.STANDARD).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.DEFAULT).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.ROOT).delete()
        super().tearDown()

    def test_get_role_bindings_by_subject_returns_groups(self):
        """Test that get_role_bindings_by_subject returns groups."""
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        self.assertEqual(queryset.count(), 1)
        group = queryset.first()
        self.assertEqual(group.name, "test_group")

    def test_get_role_bindings_by_subject_annotates_principal_count(self):
        """Test that groups are annotated with principal count."""
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        group = queryset.first()
        self.assertEqual(group.principalCount, 1)

    def test_get_role_bindings_by_subject_filters_by_subject_id(self):
        """Test filtering by subject_id."""
        # Create another group with a binding
        other_group = Group.objects.create(
            name="other_group",
            tenant=self.tenant,
        )
        other_role = RoleV2.objects.create(
            name="other_role",
            tenant=self.tenant,
        )
        other_binding = RoleBinding.objects.create(
            role=other_role,
            resource_type="workspace",
            resource_id=str(self.workspace.id),
            tenant=self.tenant,
        )
        RoleBindingGroup.objects.create(
            group=other_group,
            binding=other_binding,
        )

        # Filter by original group's UUID
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
            "subject_id": str(self.group.uuid),
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.first().uuid, self.group.uuid)

        # Cleanup
        RoleBindingGroup.objects.filter(binding=other_binding).delete()
        other_binding.delete()
        other_role.delete()
        other_group.delete()

    def test_get_role_bindings_by_subject_filters_by_subject_type_group(self):
        """Test filtering by subject_type='group' returns results."""
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
            "subject_type": "group",
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        self.assertEqual(queryset.count(), 1)

    def test_get_role_bindings_by_subject_filters_by_unsupported_subject_type(self):
        """Test filtering by unsupported subject_type returns empty."""
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
            "subject_type": "user",  # Not currently supported
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        self.assertEqual(queryset.count(), 0)

    def test_get_role_bindings_by_subject_empty_results(self):
        """Test that non-existent resource returns empty queryset."""
        params = {
            "resource_id": "00000000-0000-0000-0000-000000000000",
            "resource_type": "workspace",
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        self.assertEqual(queryset.count(), 0)

    def test_get_resource_name_for_workspace(self):
        """Test getting resource name for workspace."""
        name = self.service.get_resource_name(str(self.workspace.id), "workspace")
        self.assertEqual(name, "Test Workspace")

    def test_get_resource_name_for_nonexistent_workspace(self):
        """Test getting resource name for non-existent workspace."""
        name = self.service.get_resource_name("00000000-0000-0000-0000-000000000000", "workspace")
        self.assertIsNone(name)

    def test_get_resource_name_for_unknown_type(self):
        """Test getting resource name for unknown resource type."""
        name = self.service.get_resource_name("some-id", "unknown_type")
        self.assertIsNone(name)

    def test_build_context(self):
        """Test building serializer context."""
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
        }
        context = self.service.build_context(params)

        self.assertEqual(context["resource_id"], str(self.workspace.id))
        self.assertEqual(context["resource_type"], "workspace")
        self.assertEqual(context["resource_name"], "Test Workspace")
        self.assertIsNone(context["field_selection"])

    def test_build_context_with_fields(self):
        """Test building context with field selection (pre-parsed by input serializer)."""
        field_selection = RoleBindingFieldSelection.parse("subject(group.name)")
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
            "fields": field_selection,
        }
        context = self.service.build_context(params)

        self.assertIsNotNone(context["field_selection"])
        self.assertIn("group.name", context["field_selection"].get_nested("subject"))

    def test_parse_resource_type_with_namespace(self):
        """Test parsing resource type with namespace prefix."""
        ns, name = self.service._parse_resource_type("rbac/workspace")
        self.assertEqual(ns, "rbac")
        self.assertEqual(name, "workspace")

    def test_parse_resource_type_without_namespace(self):
        """Test parsing resource type without namespace defaults to rbac."""
        ns, name = self.service._parse_resource_type("workspace")
        self.assertEqual(ns, "rbac")
        self.assertEqual(name, "workspace")

    def test_parse_resource_type_with_custom_namespace(self):
        """Test parsing resource type with custom namespace."""
        ns, name = self.service._parse_resource_type("custom/resource")
        self.assertEqual(ns, "custom")
        self.assertEqual(name, "resource")

    def test_parse_resource_type_with_multiple_slashes(self):
        """Test parsing resource type with multiple slashes only splits on first."""
        ns, name = self.service._parse_resource_type("ns/path/to/resource")
        self.assertEqual(ns, "ns")
        self.assertEqual(name, "path/to/resource")

    def test_get_role_bindings_by_subject_with_parent_role_bindings_false(self):
        """Test that parent_role_bindings=False returns only direct bindings."""
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
            "parent_role_bindings": False,
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        self.assertEqual(queryset.count(), 1)
        group = queryset.first()
        self.assertEqual(group.name, "test_group")

    def test_get_role_bindings_by_subject_with_parent_role_bindings_none(self):
        """Test that parent_role_bindings=None (default) returns only direct bindings."""
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        self.assertEqual(queryset.count(), 1)

    def test_build_base_queryset_with_binding_uuids_includes_inherited(self):
        """Test that _build_base_queryset includes inherited bindings when UUIDs provided."""
        # Create a second group with binding on a different resource (parent workspace)
        parent_group = Group.objects.create(
            name="parent_group",
            tenant=self.tenant,
        )
        parent_binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id=str(self.default_workspace.id),  # Parent workspace
            tenant=self.tenant,
        )
        RoleBindingGroup.objects.create(
            group=parent_group,
            binding=parent_binding,
        )

        # Query for child workspace but include parent binding UUID
        binding_uuids = [str(parent_binding.uuid)]
        queryset = self.service._build_base_queryset(str(self.workspace.id), "workspace", binding_uuids)

        # Should include both direct binding group and inherited binding group
        self.assertEqual(queryset.count(), 2)
        group_names = set(queryset.values_list("name", flat=True))
        self.assertIn("test_group", group_names)
        self.assertIn("parent_group", group_names)

        # Cleanup
        RoleBindingGroup.objects.filter(binding=parent_binding).delete()
        parent_binding.delete()
        parent_group.delete()

    def test_build_base_queryset_without_binding_uuids_excludes_inherited(self):
        """Test that _build_base_queryset excludes inherited bindings when no UUIDs."""
        # Create a second group with binding on a different resource (parent workspace)
        parent_group = Group.objects.create(
            name="parent_group",
            tenant=self.tenant,
        )
        parent_binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id=str(self.default_workspace.id),  # Parent workspace
            tenant=self.tenant,
        )
        RoleBindingGroup.objects.create(
            group=parent_group,
            binding=parent_binding,
        )

        # Query for child workspace without inherited UUIDs
        queryset = self.service._build_base_queryset(str(self.workspace.id), "workspace", None)

        # Should only include direct binding group
        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.first().name, "test_group")

        # Cleanup
        RoleBindingGroup.objects.filter(binding=parent_binding).delete()
        parent_binding.delete()
        parent_group.delete()

    def test_get_role_bindings_works_without_tenant_mapping(self):
        """Test that role binding queries work when tenant has no TenantMapping.

        This verifies the lazy default binding creation gracefully skips
        when there's no TenantMapping, allowing existing functionality to work.
        """
        # Verify no TenantMapping exists for this tenant
        self.assertFalse(TenantMapping.objects.filter(tenant=self.tenant).exists())

        # Query should still work and return results
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        # Should return our manually created group with binding
        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.first().name, "test_group")

    def test_parse_resource_type_with_namespace(self):
        """Test parsing resource type with namespace prefix."""
        ns, name = self.service._parse_resource_type("rbac/workspace")
        self.assertEqual(ns, "rbac")
        self.assertEqual(name, "workspace")

    def test_parse_resource_type_without_namespace(self):
        """Test parsing resource type without namespace defaults to rbac."""
        ns, name = self.service._parse_resource_type("workspace")
        self.assertEqual(ns, "rbac")
        self.assertEqual(name, "workspace")

    def test_parse_resource_type_with_custom_namespace(self):
        """Test parsing resource type with custom namespace."""
        ns, name = self.service._parse_resource_type("custom/resource")
        self.assertEqual(ns, "custom")
        self.assertEqual(name, "resource")

    def test_parse_resource_type_with_multiple_slashes(self):
        """Test parsing resource type with multiple slashes only splits on first."""
        ns, name = self.service._parse_resource_type("ns/path/to/resource")
        self.assertEqual(ns, "ns")
        self.assertEqual(name, "path/to/resource")

    def test_get_role_bindings_by_subject_with_parent_role_bindings_false(self):
        """Test that parent_role_bindings=False returns only direct bindings."""
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
            "parent_role_bindings": False,
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        self.assertEqual(queryset.count(), 1)
        group = queryset.first()
        self.assertEqual(group.name, "test_group")

    def test_get_role_bindings_by_subject_with_parent_role_bindings_none(self):
        """Test that parent_role_bindings=None (default) returns only direct bindings."""
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
        }
        queryset = self.service.get_role_bindings_by_subject(params)

        self.assertEqual(queryset.count(), 1)

    def test_build_base_queryset_with_binding_uuids_includes_inherited(self):
        """Test that _build_base_queryset includes inherited bindings when UUIDs provided."""
        # Create a second group with binding on a different resource (parent workspace)
        parent_group = Group.objects.create(
            name="parent_group",
            tenant=self.tenant,
        )
        parent_binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id=str(self.default_workspace.id),  # Parent workspace
            tenant=self.tenant,
        )
        RoleBindingGroup.objects.create(
            group=parent_group,
            binding=parent_binding,
        )

        # Query for child workspace but include parent binding UUID
        binding_uuids = [str(parent_binding.uuid)]
        queryset = self.service._build_base_queryset(str(self.workspace.id), "workspace", binding_uuids)

        # Should include both direct binding group and inherited binding group
        self.assertEqual(queryset.count(), 2)
        group_names = set(queryset.values_list("name", flat=True))
        self.assertIn("test_group", group_names)
        self.assertIn("parent_group", group_names)

        # Cleanup
        RoleBindingGroup.objects.filter(binding=parent_binding).delete()
        parent_binding.delete()
        parent_group.delete()

    def test_build_base_queryset_without_binding_uuids_excludes_inherited(self):
        """Test that _build_base_queryset excludes inherited bindings when no UUIDs."""
        # Create a second group with binding on a different resource (parent workspace)
        parent_group = Group.objects.create(
            name="parent_group",
            tenant=self.tenant,
        )
        parent_binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id=str(self.default_workspace.id),  # Parent workspace
            tenant=self.tenant,
        )
        RoleBindingGroup.objects.create(
            group=parent_group,
            binding=parent_binding,
        )

        # Query for child workspace without inherited UUIDs
        queryset = self.service._build_base_queryset(str(self.workspace.id), "workspace", None)

        # Should only include direct binding group
        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.first().name, "test_group")

        # Cleanup
        RoleBindingGroup.objects.filter(binding=parent_binding).delete()
        parent_binding.delete()
        parent_group.delete()


class RoleBindingSerializerTests(IdentityRequest):
    """Tests for RoleBindingByGroupSerializer."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        # Create workspace
        self.root_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.ROOT,
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
        )
        self.default_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.DEFAULT,
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            parent=self.root_workspace,
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            description="Test workspace description",
            tenant=self.tenant,
            type=Workspace.Types.STANDARD,
            parent=self.default_workspace,
        )

        # Create role
        self.role = RoleV2.objects.create(
            name="test_role",
            description="Test role description",
            tenant=self.tenant,
        )

        # Create group with principal
        self.group = Group.objects.create(
            name="test_group",
            description="Test group description",
            tenant=self.tenant,
        )
        self.principal = Principal.objects.create(
            username="testuser",
            tenant=self.tenant,
            type=Principal.Types.USER,
        )
        self.group.principals.add(self.principal)

        # Create role binding
        self.binding = RoleBinding.objects.create(
            role=self.role,
            resource_type="workspace",
            resource_id=str(self.workspace.id),
            tenant=self.tenant,
        )
        RoleBindingGroup.objects.create(
            group=self.group,
            binding=self.binding,
        )

        # Get annotated group for serializer
        self.service = RoleBindingService(tenant=self.tenant)
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
        }
        queryset = self.service.get_role_bindings_by_subject(params)
        self.annotated_group = queryset.first()

        # Base context for serializer
        self.context = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
            "resource_name": "Test Workspace",
            "field_selection": None,
        }

    def tearDown(self):
        """Tear down test data."""
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.all().delete()
        self.group.principals.clear()
        Principal.objects.filter(tenant=self.tenant).delete()
        Group.objects.filter(tenant=self.tenant).delete()
        RoleV2.objects.filter(tenant=self.tenant).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.STANDARD).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.DEFAULT).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.ROOT).delete()
        super().tearDown()

    def test_default_response_includes_all_spec_fields(self):
        """Test that default response includes basic required fields.

        Default behavior returns only:
        - subject (id, type)
        - roles (id only)
        - resource (id only)
        - no last_modified
        """
        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=self.context)
        data = serializer.data

        # Check top-level fields - no last_modified by default
        self.assertNotIn("last_modified", data)
        self.assertIn("subject", data)
        self.assertIn("roles", data)
        self.assertIn("resource", data)

    def test_default_subject_structure_matches_spec(self):
        """Test that subject structure matches default spec.

        Default behavior returns only id and type (no group details).
        """
        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=self.context)
        data = serializer.data

        subject = data["subject"]
        self.assertIn("id", subject)
        self.assertIn("type", subject)
        self.assertEqual(subject["type"], "group")
        # Default behavior: no group details
        self.assertNotIn("group", subject)

    def test_default_roles_structure_matches_spec(self):
        """Test that roles structure matches default spec.

        Default behavior returns only role id.
        """
        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=self.context)
        data = serializer.data

        roles = data["roles"]
        self.assertEqual(len(roles), 1)

        role = roles[0]
        self.assertIn("id", role)
        # Default behavior: no name included
        self.assertNotIn("name", role)
        self.assertNotIn("description", role)
        self.assertNotIn("type", role)
        self.assertNotIn("created", role)
        self.assertNotIn("modified", role)

    def test_default_resource_structure_matches_spec(self):
        """Test that resource structure matches default spec.

        Default behavior returns only resource id.
        """
        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=self.context)
        data = serializer.data

        resource = data["resource"]
        self.assertIn("id", resource)
        # Default behavior: no name or type included
        self.assertNotIn("name", resource)
        self.assertNotIn("type", resource)

    def test_field_selection_filters_subject_fields(self):
        """Test that field selection filters subject group fields.

        Only subject.type is always included. Other fields require explicit request.
        """
        field_selection = RoleBindingFieldSelection.parse("subject(group.name)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=context)
        data = serializer.data

        subject = data["subject"]
        # type is always included
        self.assertIn("type", subject)
        # id is NOT included unless explicitly requested
        self.assertNotIn("id", subject)

        group = subject["group"]
        self.assertIn("name", group)
        self.assertNotIn("description", group)
        self.assertNotIn("user_count", group)

    def test_field_selection_filters_role_fields(self):
        """Test that field selection filters role fields.

        id is always included, plus explicitly requested fields.
        """
        field_selection = RoleBindingFieldSelection.parse("role(name)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=context)
        data = serializer.data

        role = data["roles"][0]
        # id is always included
        self.assertIn("id", role)
        self.assertIn("name", role)

    def test_field_selection_filters_resource_fields(self):
        """Test that field selection filters resource fields.

        id is always included, plus explicitly requested fields.
        """
        field_selection = RoleBindingFieldSelection.parse("resource(type)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=context)
        data = serializer.data

        resource = data["resource"]
        # id is always included
        self.assertIn("id", resource)
        self.assertIn("type", resource)
        self.assertNotIn("name", resource)

    def test_field_selection_excludes_last_modified_when_not_requested(self):
        """Test that last_modified is excluded when not in field selection."""
        field_selection = RoleBindingFieldSelection.parse("subject(group.name)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=context)
        data = serializer.data

        self.assertNotIn("last_modified", data)

    def test_field_selection_includes_last_modified_when_requested(self):
        """Test that last_modified is included when in field selection."""
        field_selection = RoleBindingFieldSelection.parse("last_modified,subject(group.name)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=context)
        data = serializer.data

        self.assertIn("last_modified", data)

    def test_combined_field_selection(self):
        """Test combined field selection across multiple objects."""
        field_selection = RoleBindingFieldSelection.parse(
            "subject(group.name),role(name),resource(name,type),last_modified"
        )
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=context)
        data = serializer.data

        # Check subject
        self.assertIn("name", data["subject"]["group"])
        self.assertNotIn("description", data["subject"]["group"])

        # Check roles
        self.assertIn("name", data["roles"][0])

        # Check resource
        self.assertIn("name", data["resource"])
        self.assertIn("type", data["resource"])

        # Check last_modified
        self.assertIn("last_modified", data)


@override_settings(ATOMIC_RETRY_DISABLED=True)
class UpdateRoleBindingsForSubjectTests(IdentityRequest):
    """Tests for RoleBindingService.update_role_bindings_for_subject method."""

    def setUp(self):
        """Set up test data using services."""
        super().setUp()

        # Create workspace hierarchy
        self.root_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.ROOT,
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
        )
        self.default_workspace = Workspace.objects.create(
            name=Workspace.SpecialNames.DEFAULT,
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            parent=self.root_workspace,
        )
        self.workspace = Workspace.objects.create(
            name="Test Workspace",
            description="Test workspace description",
            tenant=self.tenant,
            type=Workspace.Types.STANDARD,
            parent=self.default_workspace,
        )

        # Create permissions and roles using RoleV2Service
        self.permission1 = Permission.objects.create(permission="app:resource:read", tenant=self.tenant)
        self.permission2 = Permission.objects.create(permission="app:resource:write", tenant=self.tenant)

        self.role_service = RoleV2Service()
        self.role1 = self.role_service.create(
            name="role1",
            description="Test role 1",
            permission_data=[{"application": "app", "resource_type": "resource", "operation": "read"}],
            tenant=self.tenant,
        )
        self.role2 = self.role_service.create(
            name="role2",
            description="Test role 2",
            permission_data=[{"application": "app", "resource_type": "resource", "operation": "write"}],
            tenant=self.tenant,
        )

        # Create group and principal
        self.group = Group.objects.create(
            name="test_group",
            description="Test group description",
            tenant=self.tenant,
        )
        self.principal = Principal.objects.create(
            username="testuser",
            tenant=self.tenant,
            user_id="testuser",
            type=Principal.Types.USER,
        )

        self.service = RoleBindingService(tenant=self.tenant)

    def tearDown(self):
        """Tear down test data."""
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.all().delete()
        Principal.objects.filter(tenant=self.tenant).delete()
        Group.objects.filter(tenant=self.tenant).delete()
        RoleV2.objects.filter(tenant=self.tenant).delete()
        Permission.objects.filter(tenant=self.tenant).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.STANDARD).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.DEFAULT).delete()
        Workspace.objects.filter(tenant=self.tenant, type=Workspace.Types.ROOT).delete()
        super().tearDown()

    def test_update_role_bindings_for_group(self):
        """Test updating role bindings for a group."""
        result = self.service.update_role_bindings_for_subject(
            resource_type="workspace",
            resource_id=str(self.workspace.id),
            subject_type="group",
            subject_id=str(self.group.uuid),
            role_ids=[str(self.role1.uuid), str(self.role2.uuid)],
        )

        expected = {
            "subject_type": "group",
            "subject": self.group,
            "resource_type": "workspace",
            "resource_id": str(self.workspace.id),
            "role_uuids": {self.role1.uuid, self.role2.uuid},
        }
        actual = {
            "subject_type": result.subject_type,
            "subject": result.subject,
            "resource_type": result.resource_type,
            "resource_id": result.resource_id,
            "role_uuids": {r.uuid for r in result.roles},
        }
        self.assertEqual(actual, expected)

    def test_update_role_bindings_for_principal(self):
        """Test updating role bindings for a principal."""
        result = self.service.update_role_bindings_for_subject(
            resource_type="workspace",
            resource_id=str(self.workspace.id),
            subject_type="user",
            subject_id=str(self.principal.uuid),
            role_ids=[str(self.role1.uuid)],
        )

        expected = {
            "subject_type": "user",
            "subject": self.principal,
            "resource_type": "workspace",
            "resource_id": str(self.workspace.id),
            "role_uuids": {self.role1.uuid},
        }
        actual = {
            "subject_type": result.subject_type,
            "subject": result.subject,
            "resource_type": result.resource_type,
            "resource_id": result.resource_id,
            "role_uuids": {r.uuid for r in result.roles},
        }
        self.assertEqual(actual, expected)

    def test_update_replaces_existing_bindings(self):
        """Test that update replaces existing bindings."""
        # First update with role1
        self.service.update_role_bindings_for_subject(
            resource_type="workspace",
            resource_id=str(self.workspace.id),
            subject_type="group",
            subject_id=str(self.group.uuid),
            role_ids=[str(self.role1.uuid)],
        )

        # Second update with role2 only
        result = self.service.update_role_bindings_for_subject(
            resource_type="workspace",
            resource_id=str(self.workspace.id),
            subject_type="group",
            subject_id=str(self.group.uuid),
            role_ids=[str(self.role2.uuid)],
        )

        # Should have only role2 now (role1 was replaced)
        expected = {
            "subject_type": "group",
            "subject": self.group,
            "resource_type": "workspace",
            "resource_id": str(self.workspace.id),
            "role_uuids": {self.role2.uuid},
        }
        actual = {
            "subject_type": result.subject_type,
            "subject": result.subject,
            "resource_type": result.resource_type,
            "resource_id": result.resource_id,
            "role_uuids": {r.uuid for r in result.roles},
        }
        self.assertEqual(actual, expected)

    def test_update_raises_not_found_error(self):
        """Test that update raises NotFoundError for non-existent entities."""
        import uuid

        from management.exceptions import NotFoundError

        def make_cases():
            fake_group_id = str(uuid.uuid4())
            fake_principal_id = str(uuid.uuid4())
            fake_workspace_id = str(uuid.uuid4())

            return [
                # Non-existent group
                (
                    "invalid_group",
                    {
                        "resource_type": "workspace",
                        "resource_id": str(self.workspace.id),
                        "subject_type": "group",
                        "subject_id": fake_group_id,
                        "role_ids": [str(self.role1.uuid)],
                    },
                    "group",
                    fake_group_id,
                ),
                # Non-existent principal
                (
                    "invalid_principal",
                    {
                        "resource_type": "workspace",
                        "resource_id": str(self.workspace.id),
                        "subject_type": "user",
                        "subject_id": fake_principal_id,
                        "role_ids": [str(self.role1.uuid)],
                    },
                    "user",
                    fake_principal_id,
                ),
                # Non-existent workspace
                (
                    "invalid_resource",
                    {
                        "resource_type": "workspace",
                        "resource_id": fake_workspace_id,
                        "subject_type": "group",
                        "subject_id": str(self.group.uuid),
                        "role_ids": [str(self.role1.uuid)],
                    },
                    "workspace",
                    fake_workspace_id,
                ),
            ]

        for description, params, expected_resource_type, expected_resource_id in make_cases():
            with self.subTest(case=description):
                with self.assertRaises(NotFoundError) as context:
                    self.service.update_role_bindings_for_subject(**params)

                self.assertEqual(context.exception.resource_type, expected_resource_type)
                self.assertEqual(context.exception.resource_id, expected_resource_id)
                self.assertIn(expected_resource_id, str(context.exception))

    def test_update_raises_error_for_invalid_role(self):
        """Test that update raises InvalidFieldError for non-existent role."""
        import uuid

        from management.exceptions import InvalidFieldError

        fake_uuid = str(uuid.uuid4())
        with self.assertRaises(InvalidFieldError) as context:
            self.service.update_role_bindings_for_subject(
                resource_type="workspace",
                resource_id=str(self.workspace.id),
                subject_type="group",
                subject_id=str(self.group.uuid),
                role_ids=[fake_uuid],
            )

        self.assertEqual(context.exception.field, "roles")
        self.assertIn(fake_uuid, str(context.exception))

    def test_update_raises_error_for_unsupported_subject_type(self):
        """Test that update raises UnsupportedSubjectTypeError for invalid subject type."""
        from management.subject import UnsupportedSubjectTypeError

        test_cases = [
            ("invalid_type", "invalid_type"),
            ("empty_string", ""),
        ]

        for description, subject_type in test_cases:
            with self.subTest(case=description):
                with self.assertRaises(UnsupportedSubjectTypeError) as context:
                    self.service.update_role_bindings_for_subject(
                        resource_type="workspace",
                        resource_id=str(self.workspace.id),
                        subject_type=subject_type,
                        subject_id=str(self.group.uuid),
                        role_ids=[str(self.role1.uuid)],
                    )

                self.assertEqual(context.exception.subject_type, subject_type)
                self.assertIn("group", context.exception.supported)
                self.assertIn("user", context.exception.supported)

    def test_update_raises_error_for_missing_required_fields(self):
        """Test that update raises RequiredFieldError for missing required fields."""
        from management.exceptions import RequiredFieldError

        test_cases = [
            # Empty resource_type - caught by model validation
            (
                "empty_resource_type",
                {
                    "resource_type": "",
                    "resource_id": str(self.workspace.id),
                    "subject_type": "group",
                    "subject_id": str(self.group.uuid),
                    "role_ids": [str(self.role1.uuid)],
                },
                "resource_type",
            ),
            # Empty resource_id - caught by service validation
            (
                "empty_resource_id",
                {
                    "resource_type": "workspace",
                    "resource_id": "",
                    "subject_type": "group",
                    "subject_id": str(self.group.uuid),
                    "role_ids": [str(self.role1.uuid)],
                },
                "resource_id",
            ),
            # Empty subject_id
            (
                "empty_subject_id",
                {
                    "resource_type": "workspace",
                    "resource_id": str(self.workspace.id),
                    "subject_type": "group",
                    "subject_id": "",
                    "role_ids": [str(self.role1.uuid)],
                },
                "subject_id",
            ),
            # Empty roles list - caught by model validation
            (
                "empty_roles",
                {
                    "resource_type": "workspace",
                    "resource_id": str(self.workspace.id),
                    "subject_type": "group",
                    "subject_id": str(self.group.uuid),
                    "role_ids": [],
                },
                "roles",
            ),
        ]

        for description, params, expected_field in test_cases:
            with self.subTest(case=description):
                with self.assertRaises(RequiredFieldError) as context:
                    self.service.update_role_bindings_for_subject(**params)

                self.assertEqual(context.exception.field_name, expected_field)


@override_settings(ATOMIC_RETRY_DISABLED=True)
class UpdateSubjectAccessOnResourceTests(IdentityRequest):
    """Tests for RoleBindingService._update_subject_access_on_resource persistence logic.

    Each test verifies both the add and remove side of a PUT operation,
    since update-by-subject is a declarative "make it look like this."
    """

    def setUp(self):
        """Set up test data."""
        super().setUp()

        self.role1 = RoleV2.objects.create(name="role1", tenant=self.tenant)
        self.role2 = RoleV2.objects.create(name="role2", tenant=self.tenant)
        self.role3 = RoleV2.objects.create(name="role3", tenant=self.tenant)
        self.role4 = RoleV2.objects.create(name="role4", tenant=self.tenant)

        self.group1 = Group.objects.create(name="group1", tenant=self.tenant)
        self.group2 = Group.objects.create(name="group2", tenant=self.tenant)

        self.user1 = Principal.objects.create(tenant=self.tenant, username="user1", user_id="user1")
        self.user2 = Principal.objects.create(tenant=self.tenant, username="user2", user_id="user2")

        self.service = RoleBindingService(tenant=self.tenant)
        self.ws = "ws-123"

    def tearDown(self):
        """Clean up test data."""
        RoleBindingPrincipal.objects.all().delete()
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.all().delete()
        RoleV2.objects.all().delete()
        Group.objects.all().delete()
        Principal.objects.all().delete()

    # -- helpers ----------------------------------------------------------

    def _roles_for_principal(self, principal):
        """Return the set of roles a principal is linked to on self.ws."""
        return set(
            RoleBindingPrincipal.objects.filter(
                principal=principal,
                binding__resource_id=self.ws,
                binding__resource_type="workspace",
            ).values_list("binding__role__name", flat=True)
        )

    def _roles_for_group(self, group):
        """Return the set of roles a group is linked to on self.ws."""
        return set(
            RoleBindingGroup.objects.filter(
                group=group,
                binding__resource_id=self.ws,
                binding__resource_type="workspace",
            ).values_list("binding__role__name", flat=True)
        )

    def _binding_exists(self, role):
        """Return whether a RoleBinding(ws, role) row exists."""
        return RoleBinding.objects.filter(role=role, resource_id=self.ws, resource_type="workspace").exists()

    def _binding_subject_count(self, role):
        """Return total subjects (groups + principals) attached to the binding."""
        try:
            binding = RoleBinding.objects.get(role=role, resource_id=self.ws, resource_type="workspace")
        except RoleBinding.DoesNotExist:
            return 0
        return binding.group_entries.count() + binding.principal_entries.count()

    def _update_access(self, subject, roles):
        """Shortcut for calling the service method under test."""
        self.service._update_subject_access_on_resource(
            resource_type="workspace",
            resource_id=self.ws,
            subject=subject,
            roles=roles,
        )

    # -- 1. Fresh user, no prior bindings — adds only ---------------------

    def test_fresh_user_no_prior_bindings(self):
        """User has no bindings on the workspace; PUT adds new ones."""
        # Given: user1 has no bindings on ws
        self.assertEqual(self._roles_for_principal(self.user1), set())

        # When: PUT roles=[role3]
        self._update_access(self.user1, [self.role3])

        # Then — added: RoleBinding(ws, role3) created, user1 linked
        self.assertTrue(self._binding_exists(self.role3))
        self.assertEqual(self._roles_for_principal(self.user1), {"role3"})

        # Then — removed: nothing (no prior bindings)
        self.assertEqual(RoleBinding.objects.filter(resource_id=self.ws).count(), 1)

    # -- 2. Complete replacement, old binding orphaned --------------------

    def test_complete_replacement_orphaned_binding_deleted(self):
        """User is the only subject on the old binding; old binding is deleted."""
        # Given: user1 linked to RoleBinding(ws, role1), only subject
        self._update_access(self.user1, [self.role1])
        self.assertTrue(self._binding_exists(self.role1))

        # When: PUT roles=[role3]
        self._update_access(self.user1, [self.role3])

        # Then — added: RoleBinding(ws, role3) created, user1 linked
        self.assertTrue(self._binding_exists(self.role3))
        self.assertEqual(self._roles_for_principal(self.user1), {"role3"})

        # Then — removed: user1 unlinked from role1, binding deleted (orphaned)
        self.assertFalse(self._binding_exists(self.role1))

    # -- 3. Complete replacement, old binding has other users — kept ------

    def test_complete_replacement_shared_binding_kept(self):
        """Another user is on the old binding; binding survives removal."""
        # Given: user1 and user2 both linked to RoleBinding(ws, role1)
        self._update_access(self.user1, [self.role1])
        self._update_access(self.user2, [self.role1])
        self.assertEqual(self._binding_subject_count(self.role1), 2)

        # When: PUT roles=[role3] for user1
        self._update_access(self.user1, [self.role3])

        # Then — added: RoleBinding(ws, role3) created, user1 linked
        self.assertTrue(self._binding_exists(self.role3))
        self.assertEqual(self._roles_for_principal(self.user1), {"role3"})

        # Then — removed: user1 unlinked from role1, but binding kept (user2 still on it)
        self.assertTrue(self._binding_exists(self.role1))
        self.assertEqual(self._binding_subject_count(self.role1), 1)
        self.assertEqual(self._roles_for_principal(self.user2), {"role1"})

    # -- 4. Partial overlap — keep shared, remove old, add new -----------

    def test_partial_overlap(self):
        """Some roles stay, some are removed, some are added."""
        # Given: user1 linked to role1 and role2 (only subject on both)
        self._update_access(self.user1, [self.role1, self.role2])
        self.assertEqual(self._roles_for_principal(self.user1), {"role1", "role2"})

        # When: PUT roles=[role2, role3]
        self._update_access(self.user1, [self.role2, self.role3])

        # Then — added: RoleBinding(ws, role3) created, user1 linked
        self.assertTrue(self._binding_exists(self.role3))

        # Then — kept: user1 still linked to role2
        self.assertTrue(self._binding_exists(self.role2))
        self.assertEqual(self._roles_for_principal(self.user1), {"role2", "role3"})

        # Then — removed: user1 unlinked from role1, binding deleted (orphaned)
        self.assertFalse(self._binding_exists(self.role1))

    # -- 5. Idempotent — request matches current state exactly -----------

    def test_idempotent_same_roles(self):
        """PUT with the same roles is a true no-op — no DB writes."""
        # Given: user1 linked to role1 and role2
        self._update_access(self.user1, [self.role1, self.role2])
        original_binding_ids = set(RoleBinding.objects.filter(resource_id=self.ws).values_list("id", flat=True))
        original_through_ids = set(
            RoleBindingPrincipal.objects.filter(principal=self.user1, binding__resource_id=self.ws).values_list(
                "id", flat=True
            )
        )

        # When: PUT roles=[role1, role2] (same as current)
        self._update_access(self.user1, [self.role1, self.role2])

        # Then — same roles still assigned
        self.assertEqual(self._roles_for_principal(self.user1), {"role1", "role2"})

        # Then — exact same binding rows (IDs unchanged, true no-op)
        current_binding_ids = set(RoleBinding.objects.filter(resource_id=self.ws).values_list("id", flat=True))
        self.assertEqual(original_binding_ids, current_binding_ids)

        # Then — exact same through-table rows (IDs unchanged)
        current_through_ids = set(
            RoleBindingPrincipal.objects.filter(principal=self.user1, binding__resource_id=self.ws).values_list(
                "id", flat=True
            )
        )
        self.assertEqual(original_through_ids, current_through_ids)

    # -- 6. Reuse existing binding from another user ---------------------

    def test_reuse_existing_binding_from_another_user(self):
        """New role already has a binding from another user; reuse it."""
        # Given: user2 linked to RoleBinding(ws, role3); user1 linked to role1 (only subject)
        self._update_access(self.user2, [self.role3])
        self._update_access(self.user1, [self.role1])
        role3_binding_id = RoleBinding.objects.get(role=self.role3, resource_id=self.ws).id

        # When: PUT roles=[role3] for user1
        self._update_access(self.user1, [self.role3])

        # Then — added: user1 linked to existing RoleBinding(ws, role3), no new binding
        self.assertEqual(self._roles_for_principal(self.user1), {"role3"})
        self.assertEqual(
            RoleBinding.objects.get(role=self.role3, resource_id=self.ws).id,
            role3_binding_id,
        )
        self.assertEqual(self._binding_subject_count(self.role3), 2)

        # Then — removed: user1 unlinked from role1, binding deleted (orphaned)
        self.assertFalse(self._binding_exists(self.role1))

        # Then — user2 still linked to role3
        self.assertEqual(self._roles_for_principal(self.user2), {"role3"})

    # -- 7. Mixed orphan outcomes ----------------------------------------

    def test_mixed_orphan_outcomes(self):
        """Some old bindings are orphaned (deleted), some are not (other user)."""
        # Given: user1 on role1 and role2. user2 also on role1 but NOT role2.
        self._update_access(self.user1, [self.role1, self.role2])
        self._update_access(self.user2, [self.role1])

        # When: PUT roles=[role3] for user1
        self._update_access(self.user1, [self.role3])

        # Then — added: RoleBinding(ws, role3) created, user1 linked
        self.assertTrue(self._binding_exists(self.role3))
        self.assertEqual(self._roles_for_principal(self.user1), {"role3"})

        # Then — removed (kept): RoleBinding(ws, role1) kept, user2 still on it
        self.assertTrue(self._binding_exists(self.role1))
        self.assertEqual(self._binding_subject_count(self.role1), 1)
        self.assertEqual(self._roles_for_principal(self.user2), {"role1"})

        # Then — removed (orphaned): RoleBinding(ws, role2) deleted, no one left
        self.assertFalse(self._binding_exists(self.role2))

    # -- 8. Group on same binding — removing user doesn't orphan ---------

    def test_group_on_same_binding_prevents_orphan(self):
        """A group is also on the binding; removing the user doesn't orphan it."""
        # Given: group1 and user1 both linked to RoleBinding(ws, role1)
        self._update_access(self.group1, [self.role1])
        self._update_access(self.user1, [self.role1])
        self.assertEqual(self._binding_subject_count(self.role1), 2)

        # When: PUT roles=[role3] for user1
        self._update_access(self.user1, [self.role3])

        # Then — added: RoleBinding(ws, role3) created, user1 linked
        self.assertTrue(self._binding_exists(self.role3))
        self.assertEqual(self._roles_for_principal(self.user1), {"role3"})

        # Then — removed: user1 unlinked from role1, but binding kept (group1 still on it)
        self.assertTrue(self._binding_exists(self.role1))
        self.assertEqual(self._binding_subject_count(self.role1), 1)
        self.assertEqual(self._roles_for_group(self.group1), {"role1"})

    # -- 9. Cross-resource isolation -------------------------------------

    def test_cross_resource_isolation(self):
        """Updating bindings on one workspace does not affect another."""
        # Given: user1 has role1 on ws-123 and role2 on ws-456
        self._update_access(self.user1, [self.role1])
        self.service._update_subject_access_on_resource(
            resource_type="workspace",
            resource_id="ws-456",
            subject=self.user1,
            roles=[self.role2],
        )

        # When: PUT roles=[role3] for user1 on ws-123
        self._update_access(self.user1, [self.role3])

        # Then — added: RoleBinding(ws-123, role3) created, user1 linked
        self.assertEqual(self._roles_for_principal(self.user1), {"role3"})

        # Then — removed: RoleBinding(ws-123, role1) deleted
        self.assertFalse(self._binding_exists(self.role1))

        # Then — untouched: user1 still has role2 on ws-456
        ws456_roles = set(
            RoleBindingPrincipal.objects.filter(
                principal=self.user1,
                binding__resource_id="ws-456",
                binding__resource_type="workspace",
            ).values_list("binding__role__name", flat=True)
        )
        self.assertEqual(ws456_roles, {"role2"})

    # -- 10. Same flow works for group subject ---------------------------

    def test_same_flow_for_group_subject(self):
        """The full add+remove flow works identically for a group subject."""
        # Given: group1 linked to RoleBinding(ws, role1) (only subject)
        self._update_access(self.group1, [self.role1])
        self.assertTrue(self._binding_exists(self.role1))

        # When: PUT roles=[role3] for group1
        self._update_access(self.group1, [self.role3])

        # Then — added: RoleBinding(ws, role3) created, group1 linked
        self.assertTrue(self._binding_exists(self.role3))
        self.assertEqual(self._roles_for_group(self.group1), {"role3"})

        # Then — removed: group1 unlinked from role1, binding deleted (orphaned)
        self.assertFalse(self._binding_exists(self.role1))
