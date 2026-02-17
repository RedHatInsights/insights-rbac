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
"""Serializers for role binding management."""

from typing import Optional

from management.models import Group
from management.role.v2_model import RoleV2
from management.role_binding.exceptions import DuplicateBindingError, RolesNotFoundError, SubjectsNotFoundError
from management.role_binding.service import CreateBindingRequest, RoleBindingService
from management.utils import FieldSelection, FieldSelectionValidationError
from rest_framework import serializers


class RoleBindingFieldSelection(FieldSelection):
    """Field selection for role-bindings endpoint."""

    VALID_ROOT_FIELDS = set()
    VALID_NESTED_FIELDS = {
        "subject": {"id", "type", "group.name", "group.description", "group.user_count"},
        "role": {"id", "name"},
        "resource": {"id", "name", "type"},
    }


# --- Shared validation functions  ---


def sanitize_nul_bytes(data: dict) -> dict:
    """Sanitize input data by stripping NUL bytes from string values."""
    return {key: value.replace("\x00", "") if isinstance(value, str) else value for key, value in data.items()}


def validate_required_string(value: str, field_name: str) -> str:
    """Validate that a string value is provided and non-empty."""
    if not value:
        raise serializers.ValidationError(f"{field_name} is required.")
    return value


def validate_optional_string(value: str) -> str | None:
    """Return None for empty string values."""
    return value or None


# --- Serializers using shared validation functions ---


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
    parent_role_bindings = serializers.BooleanField(
        required=False, allow_null=True, help_text="Include role bindings inherited from parent resources"
    )

    def to_internal_value(self, data):
        """Sanitize input data by stripping NUL bytes before field validation."""
        return super().to_internal_value(sanitize_nul_bytes(data))

    def validate_resource_id(self, value):
        """Validate resource_id is provided."""
        return validate_required_string(value, "resource_id")

    def validate_resource_type(self, value):
        """Validate resource_type is provided."""
        return validate_required_string(value, "resource_type")

    def validate_subject_type(self, value):
        """Return None for empty values."""
        return validate_optional_string(value)

    def validate_parent_role_bindings(self, value):
        """Return None for empty values."""
        return value or None

    def validate_subject_id(self, value):
        """Return None for empty values."""
        return validate_optional_string(value)

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
        return validate_optional_string(value)


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
    """

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

        # Base response always includes core objects
        filtered = {
            "subject": ret.get("subject"),
            "roles": ret.get("roles"),
            "resource": ret.get("resource"),
        }

        return filtered

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
        if "id" in field_selection.get_nested("subject"):
            subject["id"] = obj.uuid

        # Extract group sub-object fields
        group_fields = field_selection.get_sub_object_fields("subject", "group")
        if group_fields:
            group_details = {}
            for field_name in group_fields:
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
            # Add explicitly requested fields
            for field_name in field_selection.get_nested("role"):
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

# Centralized mapping from domain exceptions to API error fields
BATCH_CREATE_ERROR_MAPPING = {
    RolesNotFoundError: "role",
    SubjectsNotFoundError: "subject",
    DuplicateBindingError: "detail",
}


class ResourceInputSerializer(serializers.Serializer):
    """Validates the resource portion of a role binding request."""

    id = serializers.UUIDField(help_text="UUID of the resource")
    type = serializers.CharField(help_text="Type of resource")


class SubjectInputSerializer(serializers.Serializer):
    """Validates the subject portion of a role binding request."""

    id = serializers.UUIDField(help_text="UUID of the subject")
    type = serializers.ChoiceField(choices=["user", "group"], help_text="Type of subject")


class RoleIdSerializer(serializers.Serializer):
    """Serializer for a role ID reference."""

    id = serializers.UUIDField(required=True, help_text="Role identifier")


class CreateRoleBindingItemSerializer(serializers.Serializer):
    """Validates a single role binding request item."""

    resource = ResourceInputSerializer()
    subject = SubjectInputSerializer()
    role = RoleIdSerializer()


class BatchCreateRoleBindingRequestSerializer(serializers.Serializer):
    """Validates and processes a batch create role bindings request."""

    service_class = RoleBindingService

    requests = CreateRoleBindingItemSerializer(many=True, min_length=1, max_length=100)
    fields = serializers.CharField(required=False, default="", allow_blank=True, help_text="Response field mask")

    @property
    def service(self):
        """Return the service instance."""
        return self.context.get("role_binding_service") or self.service_class(tenant=self.context["request"].tenant)

    def validate_fields(self, value):
        """Parse and validate the fields query parameter for response field masking."""
        if not value:
            return None
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
        try:
            return self.service.batch_create(requests)
        except tuple(BATCH_CREATE_ERROR_MAPPING.keys()) as e:
            field_name = BATCH_CREATE_ERROR_MAPPING[type(e)]
            raise serializers.ValidationError({field_name: str(e)})


class BatchCreateRoleBindingResponseItemSerializer(serializers.Serializer):
    """Serializes a single created role binding for the batch create response."""

    DEFAULT_FIELDS = {
        "role": {"id"},
        "subject": {"id", "type"},
        "resource": {"id"},
    }

    role = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        """Initialize with dynamic field selection from context."""
        super().__init__(*args, **kwargs)

        allowed = self.context.get("field_selection")
        if allowed is not None:
            requested = set(allowed.nested_fields.keys())
            for field_name in set(self.fields) - requested:
                self.fields.pop(field_name)

    def _get_nested_fields(self, name: str) -> set:
        """Return the set of sub-fields for a nested object."""
        allowed = self.context.get("field_selection")
        if allowed is not None:
            return allowed.get_nested(name)
        return self.DEFAULT_FIELDS.get(name, set())

    def get_role(self, obj):
        """Serialize role data."""
        role = obj["role"]
        fields = self._get_nested_fields("role")
        result = {}
        if "id" in fields:
            result["id"] = str(role.uuid)
        if "name" in fields:
            result["name"] = role.name
        return result

    def get_subject(self, obj):
        """Serialize subject data."""
        fields = self._get_nested_fields("subject")
        subject = obj["subject"]
        result = {}
        if "id" in fields:
            result["id"] = str(subject.uuid)
        if "type" in fields:
            result["type"] = obj["subject_type"]

        field_selection = self.context.get("field_selection")
        if field_selection and obj["subject_type"] == "group":
            group_fields = field_selection.get_sub_object_fields("subject", "group")
            if group_fields:
                group_details = {}
                for field_name in group_fields:
                    if field_name == "user_count":
                        group_details[field_name] = getattr(subject, "principalCount", 0)
                    else:
                        value = getattr(subject, field_name, None)
                        if value is not None:
                            group_details[field_name] = value
                if group_details:
                    result["group"] = group_details

        return result

    def get_resource(self, obj):
        """Serialize resource data."""
        fields = self._get_nested_fields("resource")
        result = {}
        if "id" in fields:
            result["id"] = obj["resource_id"]
        if "type" in fields:
            result["type"] = obj["resource_type"]
        if "name" in fields:
            name = obj.get("resource_name")
            if name is not None:
                result["name"] = name
        return result
