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

from django.apps import apps
from django.core.exceptions import ValidationError
from api.models import Tenant
from typing import Optional
import uuid


class WorkspaceValidationService:
    """Workspace validator."""

    Workspace = None

    @classmethod
    def get_model(cls):
        """Get the Workspace mode to avoid circular deps."""
        if cls.Workspace is None:
            cls.Workspace = apps.get_model("management", "Workspace")
        return cls.Workspace

    @staticmethod
    def validate_delete(instance: Workspace) -> None:
        """Delete validation."""
        Workspace = WorkspaceValidationService.get_model()
        if Workspace.objects.filter(parent=instance, tenant=instance.tenant).exists():
            raise ValidationError({"workspace": ["Unable to delete due to workspace dependencies."]})

    @staticmethod
    def validate_type(type: str) -> None:
        """Type validation."""
        Workspace = WorkspaceValidationService.get_model()
        if type != Workspace.Types.STANDARD:
            raise ValidationError({"type": [f"Only workspace type '{Workspace.Types.STANDARD}' is allowed."]})

    @staticmethod
    def validate_parent_id(tenant: Optional[Tenant] = None, parent_id: Optional[uuid.UUID] = None) -> None:
        """Parent ID valdiation."""
        Workspace = WorkspaceValidationService.get_model()
        if parent_id and tenant:
            if not Workspace.objects.filter(id=parent_id, tenant=tenant).exists():
                raise ValidationError({"parent_id": (f"Parent workspace '{parent_id}' does not exist in tenant.")})

    @staticmethod
    def root_workspace_validation(instance: Workspace) -> None:
        """Root workspace validation."""
        if instance.type == instance.Types.ROOT:
            if instance.parent is not None:
                raise ValidationError({"parent_id": ("A root workspace must not have a parent.")})

    @staticmethod
    def non_root_workspace_validation(instance: Workspace) -> None:
        """Non-root workspace validation."""
        if instance.parent_id is None:
            raise ValidationError({"parent_id": ("The parent_id field is required for non-root type workspaces.")})

    @staticmethod
    def default_workspace_validation(instance: Workspace) -> None:
        """Default workspace validation."""
        if instance.type == instance.Types.DEFAULT and instance.parent.type != instance.Types.ROOT:
            raise ValidationError({"parent_id": ("Default workspace must have a root workspace for a parent.")})

    @staticmethod
    def parent_validation(instance: Workspace) -> None:
        """Parent workspace validation."""
        if instance.id == instance.parent_id:
            raise ValidationError({"parent_id": ("The parent_id and id values must not be the same.")})
