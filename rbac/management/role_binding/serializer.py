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
"""Serializers for role binding management.

This module contains:
- Input serializers: For validating query parameters
- Output serializers: For serializing response data
"""

from typing import Optional

from management.models import Group
from management.role.v2_model import RoleV2
from management.workspace.model import Workspace
from management.role.v2_serializer import RoleIdSerializer
from management.role_binding.model import RoleBinding
from management.role_binding.service import CreateBindingRequest, ExcludeSources, RoleBindingService
from management.subject import SubjectType
from management.utils import FieldSelection, FieldSelectionValidationError
from rest_framework import serializers

_SUBJECT_TYPE_GROUP = "group"
_SUBJECT_TYPE_USER = "user"
_GROUP_FIELD_PREFIX = "group."


class RoleBindingFieldSelection(FieldSelection):
    """Field selection for list/batch-create endpoints (singular ``role``)."""

    VALID_ROOT_FIELDS = {"last_modified"}
    VALID_NESTED_FIELDS = {
        "subject": {"id", "type", "group.name", "group.description", "group.user_count"},
        "role": {"id", "name"},
        "resource": {"id", "name", "type"},
        "sources": {"id", "name", "type"},
    }


class RoleBindingBySubjectFieldSelection(FieldSelection):
    """Field selection for by-subject endpoints (plural ``roles``)."""

    VALID_ROOT_FIELDS = {"last_modified"}
    VALID_NESTED_FIELDS = {
        "subject": {"id", "type", "group.name", "group.description", "group.user_count"},
        "roles": {"id", "name"},
        "resource": {"id", "name", "type"},
    }


class RoleBindingInputSerializerMixin:
    """Shared validation methods for role binding input serializers."""

    def to_internal_value(self, data):
        """Sanitize input data by stripping NUL bytes before field validation."""
        sanitized = {
            key: value.replace("\x00", "") if isinstance(value, str) else value for key, value in data.items()
        }
        return super().to_internal_value(sanitized)

    def validate_fields(self, value):
        """Parse and validate fields parameter into RoleBindingFieldSelection object."""
        if not value:
            return None
        try:
            return RoleBindingFieldSelection.parse(value)
        except FieldSelectionValidationError as e:
            raise serializers.ValidationError(e.message)

    def validate_order_by(self, value):
        """Return None for empty values."""
        return value or None


class RoleBindingListInputSerializer(RoleBindingInputSerializerMixin, serializers.Serializer):
    """Input serializer for role binding list endpoint query parameters.

    GET /role-bindings/
    """

    role_id = serializers.UUIDField(required=False, help_text="Filter by role ID")
    resource_id = serializers.UUIDField(required=False, help_text="Filter by resource ID")
    resource_type = serializers.CharField(required=False, help_text="Filter by resource type")
    subject_type = serializers.CharField(required=False, help_text="Filter by subject type")
    subject_id = serializers.UUIDField(required=False, help_text="Filter by subject ID")
    fields = serializers.CharField(required=False, help_text="Control which fields are included")
    # Validated but not acted on yet; default ordering is by role creation time (UUIDv7).
    # Custom ordering support will be added in a follow-on PR.
    order_by = serializers.CharField(required=False, help_text="Sort by specified field(s)")
    exclude_sources = serializers.ChoiceField(
        choices=ExcludeSources.values,
        required=False,
        default=ExcludeSources.NONE,
        help_text="Exclude bindings: 'none' (default) shows all, 'indirect' hides inherited, 'direct' hides direct. "
        "Requires both resource_id and resource_type to be specified for inherited binding lookups.",
    )

    def validate(self, data):
        """Validate that resource_id and resource_type are both provided when using inherited binding features."""
        exclude_sources = data.get("exclude_sources", ExcludeSources.NONE)
        resource_id = data.get("resource_id")
        resource_type = data.get("resource_type")

        # For inherited bindings (exclude_sources != indirect), we need both resource_id and resource_type
        if exclude_sources != ExcludeSources.INDIRECT:
            if resource_id and not resource_type:
                raise serializers.ValidationError(
                    {
                        "resource_type": "resource_type is required when resource_id is specified with inherited bindings."
                    }
                )
            if resource_type and not resource_id:
                raise serializers.ValidationError(
                    {"resource_id": "resource_id is required when resource_type is specified with inherited bindings."}
                )

        return data


class RoleBindingInputSerializer(serializers.Serializer):
    """Input serializer for role binding query parameters.

    Handles validation of query parameters for the role binding API.
    """

    resource_id = serializers.CharField(required=True, help_text="Filter by resource ID")
    resource_type = serializers.CharField(required=True, help_text="Filter by resource type")
    subject_type = serializers.CharField(required=False, allow_blank=True, help_text="Filter by subject type")
    subject_id = serializers.CharField(required=False, allow_blank=True, help_text="Filter by subject ID (UUID)")
    fields = serializers.CharField(required=False, allow_blank=True, help_text="Control which fields are included")
    order_by = serializers.CharField(required=False, allow_blank=True, help_text="Sort by specified field(s)")
    exclude_sources = serializers.ChoiceField(
        choices=ExcludeSources.values,
        required=False,
        default=ExcludeSources.NONE,
        help_text="Exclude bindings: 'none' (default) shows all, 'indirect' hides inherited, 'direct' hides direct",
    )

    def to_internal_value(self, data):
        """Sanitize input data by stripping NUL bytes before field validation."""
        sanitized = {
            key: value.replace("\x00", "") if isinstance(value, str) else value for key, value in data.items()
        }
        return super().to_internal_value(sanitized)

    def validate_resource_id(self, value):
        """Validate resource_id is provided."""
        if not value:
            raise serializers.ValidationError("resource_id is required to identify the resource for role bindings.")
        return value

    def validate_resource_type(self, value):
        """Validate resource_type is provided."""
        if not value:
            raise serializers.ValidationError(
                "resource_type is required to specify the type of resource (e.g., 'workspace')."
            )
        return value

    def validate_subject_type(self, value):
        """Return None for empty values."""
        return value or None

    def validate_subject_id(self, value):
        """Return None for empty values."""
        return value or None

    def validate_fields(self, value):
        """Parse and validate fields parameter using by-subject selection."""
        if not value:
            return None
        try:
            return RoleBindingBySubjectFieldSelection.parse(value)
        except FieldSelectionValidationError as e:
            raise serializers.ValidationError(e.message)

    def validate_order_by(self, value):
        """Return None for empty values."""
        return value or None


class RoleBindingOutputSerializer(serializers.Serializer):
    """Serializer for role bindings by group.

    This serializer formats Group objects that have been annotated with
    role binding information via the service layer.

    Supports dynamic field selection through the 'field_selection' context parameter.
    Fields are accessed directly on the model using dot notation from the query parameter.

    Field selection syntax:
    - subject(group.name, group.description) - accesses obj.name, obj.description
    - role(name, description) - accesses role.name, role.description
    - resource(name, type) - accesses resource name and type from context
    - last_modified - include root-level field
    """

    last_modified = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def _get_field_selection(self):
        """Get field selection from context."""
        return self.context.get("field_selection")

    def to_representation(self, instance):
        """Override to support field selection.

        Default (no fields param): Returns only basic required fields.
        With fields param: Only explicitly requested fields are included,
        except subject.type which is always included.
        """
        ret = super().to_representation(instance)

        field_selection = self._get_field_selection()

        # Base response always includes core objects
        filtered = {
            "subject": ret.get("subject"),
            "roles": ret.get("roles"),
            "resource": ret.get("resource"),
        }

        # Include last_modified only if explicitly requested
        if field_selection and "last_modified" in field_selection.root_fields:
            filtered["last_modified"] = ret.get("last_modified")

        return filtered

    def get_last_modified(self, obj):
        """Extract last modified timestamp."""
        if isinstance(obj, dict):
            return obj.get("modified") or obj.get("latest_modified")
        return getattr(obj, "latest_modified", None)

    def get_subject(self, obj):
        """Extract subject information from the Group.

        Default (no fields param): Returns only id and type.
        With fields param: Only type is always included. Other fields
        (including id) are only included if explicitly requested.
        """
        if not isinstance(obj, Group):
            return None

        field_selection = self._get_field_selection()

        # Default behavior: only basic fields
        if field_selection is None:
            return {
                "id": obj.uuid,
                "type": "group",
            }

        # With fields param: type is always included
        subject = {"type": "group"}

        # Check if id is explicitly requested
        subject_fields = field_selection.get_nested("subject")
        if "id" in subject_fields:
            subject["id"] = obj.uuid

        # Extract field names from "group.X" paths
        fields_to_include = set()
        for field_path in subject_fields:
            if field_path.startswith("group."):
                fields_to_include.add(field_path[6:])  # Remove "group." prefix

        # Dynamically extract requested fields from the object
        if fields_to_include:
            group_details = {}
            for field_name in fields_to_include:
                # Handle special case for user_count -> principalCount
                if field_name == "user_count":
                    group_details[field_name] = getattr(obj, "principalCount", 0)
                else:
                    value = getattr(obj, field_name, None)
                    if value is not None:
                        group_details[field_name] = value

            if group_details:
                subject["group"] = group_details

        return subject

    def _build_role_data(self, role: RoleV2, field_selection: Optional[FieldSelection]) -> dict:
        """Build role data dictionary from a role object.

        Args:
            role: The role to build data for
            field_selection: Optional field selection to determine which fields to include

        Returns:
            Dictionary with role data (always includes 'id')
        """
        role_data = {"id": role.uuid}

        if field_selection is not None:
            # By-subject uses "roles", list endpoint uses "role" - support both
            role_fields = field_selection.get_nested("role") or field_selection.get_nested("roles")
            for field_name in role_fields:
                if field_name != "id":
                    value = getattr(role, field_name, None)
                    if value is not None:
                        role_data[field_name] = value

        return role_data

    def get_roles(self, obj):
        """Extract roles from the prefetched role bindings.

        Default (no fields param): Returns only role id.
        With fields param: id is always included, plus explicitly requested fields.

        For platform roles, returns their children instead of the platform role itself.
        """
        if isinstance(obj, dict):
            return obj.get("roles", [])

        if not isinstance(obj, Group) or not hasattr(obj, "filtered_bindings"):
            return []

        field_selection = self._get_field_selection()

        # Normalize roles: collect all roles to process (children for platform, role itself for non-platform)
        roles_to_process = []
        seen_role_ids = set()

        for binding_group in obj.filtered_bindings:
            if not hasattr(binding_group, "binding") or not binding_group.binding:
                continue

            role = binding_group.binding.role
            if not role:
                continue

            # For platform roles, use children; for others, use the role itself
            # Note: role.children.all() uses prefetched data from service layer's
            # prefetch_related("role__children"), so this should not cause N+1 queries
            if role.type == RoleV2.Types.PLATFORM:
                roles_to_process.extend(role.children.all())
            else:
                roles_to_process.append(role)

        # Process all normalized roles in a single loop
        roles = []
        for role in roles_to_process:
            if role.uuid in seen_role_ids:
                continue

            role_data = self._build_role_data(role, field_selection)
            roles.append(role_data)
            seen_role_ids.add(role.uuid)

        return roles

    def get_resource(self, obj):
        """Extract resource information from the request context.

        Default (no fields param): Returns only resource id.
        With fields param: id is always included, plus explicitly requested fields.
        Returns None if context has no resource information.
        """
        if isinstance(obj, dict):
            return obj.get("resource", {})

        # Check if context has any resource information
        resource_id = self.context.get("resource_id")
        resource_name = self.context.get("resource_name")
        resource_type = self.context.get("resource_type")

        if not any([resource_id, resource_name, resource_type]):
            return None

        field_selection = self._get_field_selection()

        # id is always included
        resource_data = {"id": resource_id}

        if field_selection is not None:
            # Add explicitly requested fields
            field_values = {
                "name": resource_name,
                "type": resource_type,
            }

            for field_name in field_selection.get_nested("resource"):
                if field_name != "id":
                    value = field_values.get(field_name)
                    if value is not None:
                        resource_data[field_name] = value

        return resource_data


# Backward compatibility alias
RoleBindingByGroupSerializer = RoleBindingOutputSerializer


class RoleBindingOutputSerializerMixin:
    """Shared serializer methods for role binding output serializers.

    Provides common functionality for field selection parsing and data building.
    """

    context: dict

    def _get_field_selection(self) -> Optional[FieldSelection]:
        """Get field selection from context."""
        return self.context.get("field_selection")

    def _extract_group_details(self, group: Group, field_selection: FieldSelection) -> dict:
        """Extract group.* fields from a Group object based on field selection.

        Args:
            group: The Group object to extract fields from
            field_selection: The field selection specifying which fields to include

        Returns:
            Dictionary with extracted group details, or empty dict if none requested
        """
        subject_fields = field_selection.get_nested("subject")
        # Extract field names from "group.X" paths
        fields_to_include = {
            field_path.removeprefix(_GROUP_FIELD_PREFIX)
            for field_path in subject_fields
            if field_path.startswith(_GROUP_FIELD_PREFIX)
        }

        if not fields_to_include:
            return {}

        group_details = {}
        for field_name in fields_to_include:
            # Handle special case for user_count -> principalCount
            if field_name == "user_count":
                group_details[field_name] = getattr(group, "principalCount", 0)
            else:
                value = getattr(group, field_name, None)
                if value is not None:
                    group_details[field_name] = value

        return group_details

    def _build_subject_data(self, group: Group, field_selection: Optional[FieldSelection]) -> dict:
        """Build subject data dictionary from a Group object.

        Args:
            group: The Group object to build subject data from
            field_selection: Optional field selection to determine which fields to include

        Returns:
            Dictionary with subject data (always includes 'type')
        """
        # Default behavior: only basic fields
        if field_selection is None:
            return {
                "id": group.uuid,
                "type": _SUBJECT_TYPE_GROUP,
            }

        # With fields param: type is always included
        subject: dict = {"type": _SUBJECT_TYPE_GROUP}

        # Check if id is explicitly requested
        if "id" in field_selection.get_nested("subject"):
            subject["id"] = group.uuid

        # Extract group.* fields
        group_details = self._extract_group_details(group, field_selection)
        if group_details:
            subject[_SUBJECT_TYPE_GROUP] = group_details

        return subject

    def _build_role_data(self, role: RoleV2, field_selection: Optional[FieldSelection]) -> dict:
        """Build role data dictionary from a role object.

        Args:
            role: The role to build data for
            field_selection: Optional field selection to determine which fields to include

        Returns:
            Dictionary with role data (always includes 'id')
        """
        role_data = {"id": role.uuid}

        if field_selection is not None:
            # Add explicitly requested fields
            for field_name in field_selection.get_nested("role"):
                if field_name != "id":
                    value = getattr(role, field_name, None)
                    if value is not None:
                        role_data[field_name] = value

        return role_data


class RoleBindingListOutputSerializer(RoleBindingOutputSerializerMixin, serializers.Serializer):
    """Output serializer for the role binding list endpoint.

    Handles RoleBinding objects and returns {role, subject, resource, sources}.

    Supports dynamic field selection through the 'field_selection' context parameter.
    Fields are accessed directly on the model using dot notation from the query parameter.

    Field selection syntax:
    - subject(group.name, group.description) - accesses obj.name, obj.description
    - role(name) - accesses role.name
    - resource(type) - accesses resource type from the binding
    - sources(name, type) - accesses sources with optional name and type
    """

    subject = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()
    sources = serializers.SerializerMethodField()

    def get_subject(self, obj: RoleBinding):
        """Extract subject information from the RoleBinding.

        Checks group_entries first, then principal_entries.

        Default (no fields param): Returns only id and type.
        With fields param: Only type is always included. Other fields
        (including id) are only included if explicitly requested.
        """
        field_selection = self._get_field_selection()

        # Try group subject first
        group_entries = getattr(obj, "group_entries", None)
        if group_entries is not None:
            first_entry = group_entries.all()[:1]
            if first_entry:
                group = first_entry[0].group
                return self._build_subject_data(group, field_selection)

        # Try principal subject
        principal_entries = getattr(obj, "principal_entries", None)
        if principal_entries is not None:
            first_entry = principal_entries.all()[:1]
            if first_entry:
                principal = first_entry[0].principal
                if field_selection is None:
                    return {"id": principal.uuid, "type": _SUBJECT_TYPE_USER}
                subject = {"type": _SUBJECT_TYPE_USER}
                if "id" in field_selection.get_nested("subject"):
                    subject["id"] = principal.uuid
                return subject

        return {"type": _SUBJECT_TYPE_GROUP}

    def get_role(self, obj: RoleBinding):
        """Extract role information from the RoleBinding.

        Default (no fields param): Returns only role id.
        With fields param: id is always included, plus explicitly requested fields.
        """
        if not obj.role:
            return None

        field_selection = self._get_field_selection()
        return self._build_role_data(obj.role, field_selection)

    def get_resource(self, obj: RoleBinding):
        """Extract resource information from the RoleBinding.

        Default (no fields param): Returns only resource id.
        With fields param: id is always included, plus explicitly requested fields.
        """
        field_selection = self._get_field_selection()

        resource_data = {"id": obj.resource_id}

        if field_selection is not None:
            if "type" in field_selection.get_nested("resource"):
                resource_data["type"] = obj.resource_type

        return resource_data

    def get_sources(self, obj: RoleBinding):
        """Extract sources information indicating where the role binding is attached.

        Returns a list of resources from which this role binding is sourced.
        For direct bindings, this is the binding's own resource.
        For inherited bindings, this is the parent resource where the binding is attached.

        Default (no fields param): Returns only source id.
        With fields param: id is always included, plus explicitly requested fields (name, type).
        """
        field_selection = self._get_field_selection()

        # The source is always the resource where the binding is actually attached
        source_data: dict = {"id": obj.resource_id}

        if field_selection is not None:
            source_fields = field_selection.get_nested("sources")
            if "type" in source_fields:
                source_data["type"] = obj.resource_type
            if "name" in source_fields:
                # Try to get name from workspace if it's a workspace resource
                source_data["name"] = self._get_resource_name(obj.resource_type, obj.resource_id)

        return [source_data]

    def _get_resource_name(self, resource_type: str, resource_id: str) -> Optional[str]:
        """Get the name of a resource by type and ID.

        Args:
            resource_type: The type of resource (e.g., 'workspace', 'tenant')
            resource_id: The resource identifier

        Returns:
            Resource name or None if not found
        """
        if resource_type == "workspace":
            try:
                request = self.context.get("request")
                tenant = request.tenant if request else None
                if tenant:
                    workspace = Workspace.objects.get(id=resource_id, tenant=tenant)
                else:
                    workspace = Workspace.objects.get(id=resource_id)
                return workspace.name
            except (Workspace.DoesNotExist, ValueError):
                return None
        return None


class ResourceInputSerializer(serializers.Serializer):
    """Validates the resource portion of a role binding request."""

    id = serializers.UUIDField(help_text="UUID of the resource")
    type = serializers.CharField(help_text="Type of resource")


class SubjectInputSerializer(serializers.Serializer):
    """Validates the subject portion of a role binding request."""

    id = serializers.UUIDField(help_text="UUID of the subject")
    type = serializers.ChoiceField(choices=["user", "group"], help_text="Type of subject")


class CreateRoleBindingItemSerializer(serializers.Serializer):
    """Validates a single role binding request item."""

    resource = ResourceInputSerializer()
    subject = SubjectInputSerializer()
    role = RoleIdSerializer()


class BatchCreateRoleBindingRequestSerializer(serializers.Serializer):
    """Validates and processes a batch create role bindings request."""

    service_class = RoleBindingService

    DEFAULT_FIELDS = "resource(id),role(id),subject(id,type)"

    requests = CreateRoleBindingItemSerializer(many=True, min_length=1, max_length=100)
    fields = serializers.CharField(
        required=False, default="", allow_blank=True, help_text="Control which fields are included"
    )

    @property
    def service(self):
        """Return the service instance."""
        return self.context.get("role_binding_service") or self.service_class(tenant=self.context["request"].tenant)

    def validate_fields(self, value):
        """Parse and validate the fields query parameter for response field masking."""
        if not value:
            return RoleBindingFieldSelection.parse(self.DEFAULT_FIELDS)
        try:
            return RoleBindingFieldSelection.parse(value)
        except FieldSelectionValidationError as e:
            raise serializers.ValidationError(e.message)

    def create(self, validated_data):
        """Create role bindings using the service layer."""
        requests = [
            CreateBindingRequest(
                role_id=str(item["role"]["id"]),
                resource_type=item["resource"]["type"],
                resource_id=str(item["resource"]["id"]),
                subject_type=item["subject"]["type"],
                subject_id=str(item["subject"]["id"]),
            )
            for item in validated_data["requests"]
        ]
        return self.service.batch_create(requests)


class RoleBindingFieldMaskingMixin:
    """Shared field-masking logic for role binding response serializers.

    Provides building blocks that apply the ``field_selection`` context to
    individual response sections (subject, roles, resource).

    Subclasses declare ``SerializerMethodField`` and implement ``get_*``
    methods that extract data from their specific input type (e.g. Group
    model vs ``UpdateRoleBindingResult`` dataclass), then delegate to these
    helpers for consistent masking.

    Masking rules
    -------------
    * Default (no ``field_selection``): subject returns ``id`` + ``type``;
      roles returns ``id`` only; resource returns ``id`` only.
    * With ``field_selection``: only explicitly requested fields appear
      and unrequested top-level sections are stripped entirely.
    """

    def __init__(self, *args, **kwargs):
        """Strip unrequested top-level sections when field_selection is present."""
        super().__init__(*args, **kwargs)

        field_selection = self._get_field_selection()
        if field_selection is not None:
            requested = set(field_selection.nested_fields.keys())
            for field_name in set(self.fields) - requested:
                self.fields.pop(field_name)

    def _get_field_selection(self):
        """Get field selection from context."""
        return self.context.get("field_selection")

    # ── Building-block helpers ───────────────────────────────────────

    def _build_subject_data(self, subject_type, subject_obj):
        """Build a subject dict with field masking applied.

        Args:
            subject_type: ``"group"`` or ``"user"`` (a SubjectType value).
            subject_obj: The underlying Group or Principal model instance.
        """
        field_selection = self._get_field_selection()

        if field_selection is None:
            subject = {"id": subject_obj.uuid, "type": subject_type}
            if subject_type == SubjectType.USER:
                subject["user"] = {"username": subject_obj.username}
            return subject

        subject = {}
        subject_fields = field_selection.get_nested("subject")

        if "type" in subject_fields:
            subject["type"] = subject_type
        if "id" in subject_fields:
            subject["id"] = subject_obj.uuid

        if subject_type == SubjectType.GROUP:
            group_details = self._extract_nested_fields("group.", subject_fields, subject_obj)
            if group_details:
                subject["group"] = group_details
        elif subject_type == SubjectType.USER:
            user_details = self._extract_nested_fields("user.", subject_fields, subject_obj)
            if user_details:
                subject["user"] = user_details

        return subject

    def _build_role_data(self, role):
        """Build a role dict with field masking applied."""
        field_selection = self._get_field_selection()

        if field_selection is None:
            return {"id": role.uuid}

        role_data = {}
        role_fields = field_selection.get_nested("role") or field_selection.get_nested("roles")
        for field_name in role_fields:
            if field_name == "id":
                role_data["id"] = role.uuid
            else:
                value = getattr(role, field_name, None)
                if value is not None:
                    role_data[field_name] = value

        return role_data

    def _build_resource_data(self, resource_id, resource_name=None, resource_type=None):
        """Build a resource dict with field masking applied."""
        field_selection = self._get_field_selection()

        if field_selection is None:
            return {"id": resource_id}

        field_values = {"id": resource_id, "name": resource_name, "type": resource_type}
        resource_data = {}
        for field_name in field_selection.get_nested("resource"):
            value = field_values.get(field_name)
            if value is not None:
                resource_data[field_name] = value

        return resource_data

    @staticmethod
    def _extract_nested_fields(prefix, field_paths, obj):
        """Extract attribute values matching field paths with a given prefix.

        Handles the ``user_count`` → ``principalCount`` special case for groups.
        """
        details = {}
        prefix_len = len(prefix)
        for field_path in field_paths:
            if field_path.startswith(prefix):
                attr_name = field_path[prefix_len:]
                if attr_name == "user_count":
                    details[attr_name] = getattr(obj, "principalCount", 0)
                else:
                    value = getattr(obj, attr_name, None)
                    if value is not None:
                        details[attr_name] = value
        return details


class BatchCreateRoleBindingResponseItemSerializer(RoleBindingFieldMaskingMixin, serializers.Serializer):
    """Serializes a single created role binding for the batch create response."""

    role = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def get_role(self, obj):
        """Delegate to ``_build_role_data``."""
        return self._build_role_data(obj["role"])

    def get_subject(self, obj):
        """Delegate to ``_build_subject_data``."""
        return self._build_subject_data(obj["subject_type"], obj["subject"])

    def get_resource(self, obj):
        """Delegate to ``_build_resource_data``."""
        return self._build_resource_data(obj["resource_id"], obj.get("resource_name"), obj["resource_type"])


class UpdateRoleBindingRequestSerializer(RoleBindingInputSerializerMixin, serializers.Serializer):
    """Input serializer for update role binding API.

    Inherits from ``RoleBindingInputSerializerMixin`` for shared NUL-byte
    sanitization (``to_internal_value``) and ``validate_fields``.
    """

    DEFAULT_FIELDS = "resource(id),subject(id),roles(id)"

    # Query parameters
    resource_id = serializers.CharField(required=True, help_text="Resource ID to update bindings for")
    resource_type = serializers.CharField(required=True, help_text="Resource type (e.g., 'workspace')")
    subject_id = serializers.CharField(required=True, help_text="Subject ID (UUID)")
    subject_type = serializers.CharField(required=True, help_text="Subject type (e.g., 'group')")
    fields = serializers.CharField(
        required=False, default="", allow_blank=True, help_text="Control which fields are included"
    )

    # Request body
    roles = RoleIdSerializer(many=True, required=True, help_text="Roles to assign")

    def validate_fields(self, value):
        """Parse and validate fields parameter using by-subject selection."""
        if not value:
            return RoleBindingBySubjectFieldSelection.parse(self.DEFAULT_FIELDS)
        try:
            return RoleBindingBySubjectFieldSelection.parse(value)
        except FieldSelectionValidationError as e:
            raise serializers.ValidationError(e.message)

    def validate_roles(self, value):
        """Validate that at least one role is provided.

        Custom validator instead of allow_empty=False so the error surfaces as
        field="roles" with a clear message, rather than DRF's default
        field="roles.non_field_errors" / "This list may not be empty."
        """
        if not value:
            raise serializers.ValidationError("At least one role is required.")
        return value

    def validate_subject_type(self, value):
        """Validate subject_type is a supported enum value."""
        if not SubjectType.is_valid(value):
            supported = ", ".join(SubjectType.values())
            raise serializers.ValidationError(f"Unsupported subject type: '{value}'. Supported types: {supported}")
        return value

    def save(self):
        """Execute the update via the service layer and return the result.

        Domain exceptions (NotFoundError, InvalidFieldError, RequiredFieldError)
        propagate to the global exception handler which formats them as
        Problem Details responses.
        """
        validated = self.validated_data
        tenant = self.context["request"].tenant
        role_ids = [str(role["id"]) for role in validated["roles"]]
        service = RoleBindingService(tenant=tenant)

        return service.update_role_bindings_for_subject(
            resource_type=validated["resource_type"],
            resource_id=validated["resource_id"],
            subject_type=validated["subject_type"],
            subject_id=validated["subject_id"],
            role_ids=role_ids,
        )


class UpdateRoleBindingResponseSerializer(RoleBindingFieldMaskingMixin, serializers.Serializer):
    """Output serializer for the update role binding API.

    Serializes an ``UpdateRoleBindingResult`` dataclass into the API response.
    Data extraction is result-specific; field masking is delegated to
    ``RoleBindingFieldMaskingMixin``.
    """

    subject = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def get_subject(self, result):
        """Delegate to ``_build_subject_data`` with result's subject info."""
        return self._build_subject_data(result.subject_type, result.subject)

    def get_roles(self, result):
        """Delegate per-role masking to ``_build_role_data``."""
        return [self._build_role_data(role) for role in result.roles]

    def get_resource(self, result):
        """Delegate to ``_build_resource_data`` with result's resource info."""
        return self._build_resource_data(result.resource_id, result.resource_name, result.resource_type)
