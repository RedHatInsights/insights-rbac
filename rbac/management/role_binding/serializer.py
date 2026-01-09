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
"""Serializers for role binding v2 endpoints."""
from __future__ import annotations

from collections import OrderedDict
from datetime import timezone as dt_timezone
from typing import Any, Iterable, Optional

from django.utils import timezone
from management.group.model import Group
from management.principal.model import Principal
from management.role.v2_model import RoleBinding
from management.workspace.model import Workspace
from rest_framework import serializers


def _isoformat(value):
    """Return an ISO-8601 UTC string for the provided datetime."""
    if value is None:
        return None
    if timezone.is_naive(value):
        value = timezone.make_aware(value, dt_timezone.utc)
    return value.astimezone(dt_timezone.utc).isoformat().replace("+00:00", "Z")


class RoleBindingBySubjectSerializer(serializers.Serializer):
    """Serializer that presents role bindings grouped by subject (group/user)."""

    last_modified = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()
    inherited_from = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        """Allow dynamic field filtering through the `fields` kwarg."""
        requested_fields = kwargs.pop("fields", None)
        super().__init__(*args, **kwargs)
        if requested_fields:
            allowed = set(field.strip() for field in requested_fields.split(",") if field.strip())
            existing = set(self.fields.keys())
            for field_name in existing - allowed:
                self.fields.pop(field_name)

    #
    # Serializer method helpers
    #
    def get_last_modified(self, obj):
        """Return the latest modification timestamp for the aggregated bindings."""
        latest = getattr(obj, "latest_modified", None)
        return _isoformat(latest)

    def get_subject(self, obj):
        """Return subject metadata for groups or principals."""
        if isinstance(obj, Group):
            return self._serialize_group_subject(obj)
        return self._serialize_principal_subject(obj)

    def get_roles(self, obj):
        """Return the roles granted to this subject for the requested resource."""
        bindings = self._subject_bindings(obj)
        roles = []
        seen = set()
        for binding_entry in bindings:
            binding: RoleBinding = binding_entry.binding  # type: ignore[attr-defined]
            if not binding or not binding.role:
                continue
            role_uuid = str(binding.role.uuid)
            if role_uuid in seen:
                continue
            seen.add(role_uuid)
            roles.append({"id": role_uuid, "name": binding.role.name})
        return roles

    def get_resource(self, obj):
        """Return information about the resource being queried."""
        request = self.context.get("request")
        if not request:
            return {}
        return {
            "type": request.resource_type,
            "id": request.resource_id,
            "name": getattr(request, "resource_name", None),
        }

    def get_inherited_from(self, obj):
        """Return parent resources if bindings are inherited."""
        request = self.context.get("request")
        if not request or not getattr(request, "include_inherited", False):
            return None
        return self.get_inherited_parent_resources(obj)

    def get_inherited_parent_resources(self, obj):
        """
        Return distinct parent resources from which this subject inherits bindings.

        This helper centralizes inherited-resource computation so it can be reused
        as the serializer evolves (e.g., if/when to_representation is introduced).
        """
        request = self.context.get("request")
        if not request or not getattr(request, "include_inherited", False):
            return None

        bindings = self._subject_bindings(obj)
        parents: OrderedDict[str, dict] = OrderedDict()
        for binding_entry in bindings:
            binding: RoleBinding = binding_entry.binding  # type: ignore[attr-defined]
            if not binding:
                continue
            if binding.resource_type == request.resource_type and binding.resource_id == request.resource_id:
                continue
            parent_key = f"{binding.resource_type}:{binding.resource_id}"
            if parent_key in parents:
                continue
            parents[parent_key] = {
                "type": binding.resource_type,
                "id": binding.resource_id,
                "name": self._resolve_resource_name(binding.resource_type, binding.resource_id),
            }

        return list(parents.values()) or None

    #
    # Internal helpers
    #
    def _serialize_group_subject(self, group: Group) -> dict:
        """Serialize a group subject payload."""
        return {
            "type": "group",
            "group": {
                "id": str(group.uuid),
                "name": group.name,
                "description": group.description,
                "user_count": getattr(group, "principalCount", None),
            },
        }

    def _serialize_principal_subject(self, principal: Principal) -> dict:
        """Serialize a user subject payload."""
        payload: dict[str, Any] = {
            "type": "user",
            "user": {
                "id": str(principal.uuid),
                "username": principal.username,
                "user_id": principal.user_id,
            },
        }

        groups = []
        for group in getattr(principal, "filtered_groups", []):
            groups.append(
                {
                    "id": str(group.uuid),
                    "name": group.name,
                    "description": group.description,
                }
            )

        if groups:
            payload["groups"] = groups
        return payload

    def _subject_bindings(self, obj) -> Iterable:
        """Return the prefetched binding entries for a subject."""
        if isinstance(obj, Group):
            return getattr(obj, "filtered_bindings", [])

        binding_entries = []
        for group in getattr(obj, "filtered_groups", []):
            binding_entries.extend(getattr(group, "filtered_bindings", []))
        return binding_entries

    def _resolve_resource_name(self, resource_type: str, resource_id: str) -> Optional[str]:
        """Resolve the resource name when possible (currently workspace-only)."""
        # Normalize RBAC-local workspace types so that both "workspace" and
        # "rbac/workspace" behave the same when resolving names.
        if resource_type in {"rbac/workspace"}:
            resource_type = "workspace"

        if resource_type != "workspace":
            return None

        cache = getattr(self, "_workspace_cache", {})
        if resource_id in cache:
            return cache[resource_id]

        tenant = None
        request = self.context.get("request")
        if request:
            tenant = getattr(request, "tenant", None)

        name = None
        if tenant:
            workspace = Workspace.objects.filter(id=resource_id, tenant=tenant).only("id", "name").first()
            if workspace:
                name = workspace.name

        cache[resource_id] = name
        self._workspace_cache = cache
        return name


class RoleBindingByGroupSerializer(serializers.Serializer):
    """
    Backwards-compatible serializer for group-focused role binding responses.

    This serializer exists to support existing unit tests and older response shapes.
    It intentionally returns:
    - last_modified as a datetime (not an ISO string)
    - subject.id and role.id as UUID objects (not strings)
    """

    last_modified = serializers.SerializerMethodField()
    subject = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    resource = serializers.SerializerMethodField()

    def get_last_modified(self, obj):
        """
        Return last modified timestamp.

        - For dict input, prefer "modified" then "latest_modified"
        - For Group input, read obj.latest_modified when available
        """
        if isinstance(obj, dict):
            return obj.get("modified") or obj.get("latest_modified")
        return getattr(obj, "latest_modified", None)

    def get_subject(self, obj):
        """Serialize a Group subject, or return None for non-Group inputs."""
        if not isinstance(obj, Group):
            return None
        return {
            "id": obj.uuid,
            "type": "group",
            "group": {
                "name": obj.name,
                "description": obj.description,
                "user_count": getattr(obj, "principalCount", None),
            },
        }

    def get_roles(self, obj):
        """
        Return roles for a group.

        - For dict input, pass through "roles" if present
        - For Group input, extract from obj.filtered_bindings (prefetched RoleBindingGroup)
        """
        if isinstance(obj, dict):
            return obj.get("roles", []) or []

        roles = []
        seen = set()
        for binding_group in getattr(obj, "filtered_bindings", []) or []:
            binding = getattr(binding_group, "binding", None)
            if not binding:
                continue
            role = getattr(binding, "role", None)
            if not role:
                continue
            if role.uuid in seen:
                continue
            seen.add(role.uuid)
            roles.append({"id": role.uuid, "name": role.name})
        return roles

    def get_resource(self, obj):
        """
        Return the resource being queried.

        - For dict input, pass through "resource" if present
        - For Group input, build from serializer context when "request" is present
        """
        if isinstance(obj, dict):
            return obj.get("resource", {}) or {}

        # Match existing tests: if no request in context, return None
        if "request" not in (self.context or {}):
            return None

        return {
            "id": (self.context or {}).get("resource_id"),
            "name": (self.context or {}).get("resource_name"),
            "type": (self.context or {}).get("resource_type"),
        }
