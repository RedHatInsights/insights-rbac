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

from django.test import TestCase

from management.models import Group, Permission, Principal, Workspace
from management.role.v2_model import RoleBinding, RoleBindingGroup, RoleV2
from management.role_binding.serializer import FieldSelection, RoleBindingBySubjectOutputSerializer
from management.role_binding.service import RoleBindingService
from management.tenant_mapping.model import TenantMapping

from tests.identity_request import IdentityRequest


class FieldSelectionTests(TestCase):
    """Tests for FieldSelection dataclass and parsing."""

    def test_parse_returns_none_for_empty_string(self):
        """Test that parse returns None for empty string."""
        result = FieldSelection.parse("")
        self.assertIsNone(result)

    def test_parse_returns_none_for_none(self):
        """Test that parse returns None for None input."""
        result = FieldSelection.parse(None)
        self.assertIsNone(result)

    def test_parse_root_level_field(self):
        """Test parsing a root level field."""
        result = FieldSelection.parse("last_modified")
        self.assertIsNotNone(result)
        self.assertIn("last_modified", result.root_fields)

    def test_parse_subject_fields(self):
        """Test parsing subject fields."""
        result = FieldSelection.parse("subject(group.name,group.description)")
        self.assertIsNotNone(result)
        self.assertIn("group.name", result.subject_fields)
        self.assertIn("group.description", result.subject_fields)

    def test_parse_role_fields(self):
        """Test parsing role fields."""
        result = FieldSelection.parse("role(name,id)")
        self.assertIsNotNone(result)
        self.assertIn("name", result.role_fields)
        self.assertIn("id", result.role_fields)

    def test_parse_resource_fields(self):
        """Test parsing resource fields."""
        result = FieldSelection.parse("resource(name,type)")
        self.assertIsNotNone(result)
        self.assertIn("name", result.resource_fields)
        self.assertIn("type", result.resource_fields)

    def test_parse_multiple_objects(self):
        """Test parsing multiple object field selections."""
        result = FieldSelection.parse("subject(group.name),role(name),resource(type)")
        self.assertIsNotNone(result)
        self.assertIn("group.name", result.subject_fields)
        self.assertIn("name", result.role_fields)
        self.assertIn("type", result.resource_fields)

    def test_parse_mixed_root_and_object_fields(self):
        """Test parsing mixed root and object fields."""
        result = FieldSelection.parse("last_modified,subject(group.name)")
        self.assertIsNotNone(result)
        self.assertIn("last_modified", result.root_fields)
        self.assertIn("group.name", result.subject_fields)

    def test_parse_handles_whitespace(self):
        """Test that parsing handles whitespace correctly."""
        result = FieldSelection.parse(" subject( group.name , group.description ) ")
        self.assertIsNotNone(result)
        self.assertIn("group.name", result.subject_fields)
        self.assertIn("group.description", result.subject_fields)

    def test_split_fields_respects_parentheses(self):
        """Test that field splitting respects parentheses."""
        parts = FieldSelection._split_fields("subject(a,b),role(c)")
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0], "subject(a,b)")
        self.assertEqual(parts[1], "role(c)")

    def test_parse_raises_error_for_invalid_subject_field(self):
        """Test that parse raises error for invalid subject field."""
        from management.role_binding.serializer import FieldSelectionValidationError

        with self.assertRaises(FieldSelectionValidationError) as context:
            FieldSelection.parse("subject(invalid_field)")
        self.assertIn("invalid_field", str(context.exception))

    def test_parse_raises_error_for_invalid_role_field(self):
        """Test that parse raises error for invalid role field."""
        from management.role_binding.serializer import FieldSelectionValidationError

        with self.assertRaises(FieldSelectionValidationError) as context:
            FieldSelection.parse("role(invalid_field)")
        self.assertIn("invalid_field", str(context.exception))

    def test_parse_raises_error_for_invalid_resource_field(self):
        """Test that parse raises error for invalid resource field."""
        from management.role_binding.serializer import FieldSelectionValidationError

        with self.assertRaises(FieldSelectionValidationError) as context:
            FieldSelection.parse("resource(invalid_field)")
        self.assertIn("invalid_field", str(context.exception))

    def test_parse_raises_error_for_unknown_object_type(self):
        """Test that parse raises error for unknown object type."""
        from management.role_binding.serializer import FieldSelectionValidationError

        with self.assertRaises(FieldSelectionValidationError) as context:
            FieldSelection.parse("unknown(field)")
        self.assertIn("Unknown object type", str(context.exception))

    def test_parse_raises_error_for_invalid_root_field(self):
        """Test that parse raises error for invalid root field."""
        from management.role_binding.serializer import FieldSelectionValidationError

        with self.assertRaises(FieldSelectionValidationError) as context:
            FieldSelection.parse("invalid_root_field")
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
        field_selection = FieldSelection.parse("subject(group.name)")
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
            "fields": field_selection,
        }
        context = self.service.build_context(params)

        self.assertIsNotNone(context["field_selection"])
        self.assertIn("group.name", context["field_selection"].subject_fields)

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
    """Tests for RoleBindingBySubjectOutputSerializer."""

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
        serializer = RoleBindingBySubjectOutputSerializer(self.annotated_group, context=self.context)
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
        serializer = RoleBindingBySubjectOutputSerializer(self.annotated_group, context=self.context)
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
        serializer = RoleBindingBySubjectOutputSerializer(self.annotated_group, context=self.context)
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
        serializer = RoleBindingBySubjectOutputSerializer(self.annotated_group, context=self.context)
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
        field_selection = FieldSelection.parse("subject(group.name)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingBySubjectOutputSerializer(self.annotated_group, context=context)
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
        field_selection = FieldSelection.parse("role(name)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingBySubjectOutputSerializer(self.annotated_group, context=context)
        data = serializer.data

        role = data["roles"][0]
        # id is always included
        self.assertIn("id", role)
        self.assertIn("name", role)

    def test_field_selection_filters_resource_fields(self):
        """Test that field selection filters resource fields.

        id is always included, plus explicitly requested fields.
        """
        field_selection = FieldSelection.parse("resource(type)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingBySubjectOutputSerializer(self.annotated_group, context=context)
        data = serializer.data

        resource = data["resource"]
        # id is always included
        self.assertIn("id", resource)
        self.assertIn("type", resource)
        self.assertNotIn("name", resource)

    def test_field_selection_excludes_last_modified_when_not_requested(self):
        """Test that last_modified is excluded when not in field selection."""
        field_selection = FieldSelection.parse("subject(group.name)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingBySubjectOutputSerializer(self.annotated_group, context=context)
        data = serializer.data

        self.assertNotIn("last_modified", data)

    def test_field_selection_includes_last_modified_when_requested(self):
        """Test that last_modified is included when in field selection."""
        field_selection = FieldSelection.parse("last_modified,subject(group.name)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingBySubjectOutputSerializer(self.annotated_group, context=context)
        data = serializer.data

        self.assertIn("last_modified", data)

    def test_combined_field_selection(self):
        """Test combined field selection across multiple objects."""
        field_selection = FieldSelection.parse("subject(group.name),role(name),resource(name,type),last_modified")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingBySubjectOutputSerializer(self.annotated_group, context=context)
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
