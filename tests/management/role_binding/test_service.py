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
from rest_framework import serializers

from management.models import Group, Permission, Principal, Workspace
from management.role.v2_model import RoleBinding, RoleBindingGroup, RoleV2
from management.role_binding.serializer import RoleBindingByGroupSerializer
from management.role_binding.service import (
    FieldSelection,
    RoleBindingQueryParams,
    RoleBindingService,
)
from tests.identity_request import IdentityRequest


class RoleBindingQueryParamsTests(TestCase):
    """Tests for RoleBindingQueryParams dataclass."""

    def test_valid_required_params(self):
        """Test that valid required params are accepted."""
        params = RoleBindingQueryParams(
            resource_id="workspace-123",
            resource_type="workspace",
        )
        self.assertEqual(params.resource_id, "workspace-123")
        self.assertEqual(params.resource_type, "workspace")

    def test_missing_resource_id_raises_error(self):
        """Test that missing resource_id raises ValidationError."""
        with self.assertRaises(serializers.ValidationError) as context:
            RoleBindingQueryParams(resource_id="", resource_type="workspace")
        self.assertIn("resource_id", str(context.exception))

    def test_missing_resource_type_raises_error(self):
        """Test that missing resource_type raises ValidationError."""
        with self.assertRaises(serializers.ValidationError) as context:
            RoleBindingQueryParams(resource_id="workspace-123", resource_type="")
        self.assertIn("resource_type", str(context.exception))

    def test_optional_params_default_to_none(self):
        """Test that optional params default to None."""
        params = RoleBindingQueryParams(
            resource_id="workspace-123",
            resource_type="workspace",
        )
        self.assertIsNone(params.subject_type)
        self.assertIsNone(params.subject_id)
        self.assertIsNone(params.fields)
        self.assertIsNone(params.order_by)

    def test_optional_params_can_be_set(self):
        """Test that optional params can be set."""
        params = RoleBindingQueryParams(
            resource_id="workspace-123",
            resource_type="workspace",
            subject_type="group",
            subject_id="group-uuid",
            fields="subject(group.name)",
            order_by="-last_modified",
        )
        self.assertEqual(params.subject_type, "group")
        self.assertEqual(params.subject_id, "group-uuid")
        self.assertEqual(params.fields, "subject(group.name)")
        self.assertEqual(params.order_by, "-last_modified")


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

    def test_parse_query_params_valid(self):
        """Test parsing valid query parameters."""
        query_params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
            "subject_type": "group",
            "subject_id": str(self.group.uuid),
        }
        params = self.service.parse_query_params(query_params)

        self.assertEqual(params.resource_id, str(self.workspace.id))
        self.assertEqual(params.resource_type, "workspace")
        self.assertEqual(params.subject_type, "group")
        self.assertEqual(params.subject_id, str(self.group.uuid))

    def test_parse_query_params_strips_null_bytes(self):
        """Test that null bytes are stripped from parameters."""
        query_params = {
            "resource_id": f"\x00{self.workspace.id}\x00",
            "resource_type": "\x00workspace\x00",
        }
        params = self.service.parse_query_params(query_params)

        self.assertEqual(params.resource_id, str(self.workspace.id))
        self.assertEqual(params.resource_type, "workspace")

    def test_parse_query_params_missing_resource_id(self):
        """Test that missing resource_id raises error."""
        query_params = {"resource_type": "workspace"}
        with self.assertRaises(serializers.ValidationError):
            self.service.parse_query_params(query_params)

    def test_parse_query_params_missing_resource_type(self):
        """Test that missing resource_type raises error."""
        query_params = {"resource_id": str(self.workspace.id)}
        with self.assertRaises(serializers.ValidationError):
            self.service.parse_query_params(query_params)

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
        """Test building context with field selection."""
        params = {
            "resource_id": str(self.workspace.id),
            "resource_type": "workspace",
            "fields": "subject(group.name)",
        }
        context = self.service.build_context(params)

        self.assertIsNotNone(context["field_selection"])
        self.assertIn("group.name", context["field_selection"].subject_fields)


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
        field_selection = FieldSelection.parse("subject(group.name)")
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
        field_selection = FieldSelection.parse("role(name)")
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
        field_selection = FieldSelection.parse("resource(type)")
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
        field_selection = FieldSelection.parse("subject(group.name)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=context)
        data = serializer.data

        self.assertNotIn("last_modified", data)

    def test_field_selection_includes_last_modified_when_requested(self):
        """Test that last_modified is included when in field selection."""
        field_selection = FieldSelection.parse("last_modified,subject(group.name)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=context)
        data = serializer.data

        self.assertIn("last_modified", data)

    def test_field_selection_dynamic_group_field_access(self):
        """Test that dynamic field access works for group fields."""
        # Request a field that exists on the model but isn't in defaults
        field_selection = FieldSelection.parse("subject(group.uuid)")
        context = {**self.context, "field_selection": field_selection}

        serializer = RoleBindingByGroupSerializer(self.annotated_group, context=context)
        data = serializer.data

        group = data["subject"]["group"]
        self.assertIn("uuid", group)
        self.assertEqual(str(group["uuid"]), str(self.group.uuid))

    def test_combined_field_selection(self):
        """Test combined field selection across multiple objects."""
        field_selection = FieldSelection.parse("subject(group.name),role(name),resource(name,type),last_modified")
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
