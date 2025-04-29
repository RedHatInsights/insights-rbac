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
"""Service for workspace management."""
from django.core.exceptions import ValidationError

# from django.db import transaction
from management.models import Workspace

# from management.relation_replicator.relation_replicator import ReplicationEventType
# from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspacepHandler


class WorkspaceService:
    """Workspace service"""

    @staticmethod
    def destroy(instance: Workspace) -> None:
        if instance.type != Workspace.Types.STANDARD:
            raise ValidationError(f"Unable to delete {instance.type} workspace")
        if Workspace.objects.filter(parent=instance, tenant=instance.tenant).exists():
            raise ValidationError("Unable to delete due to workspace dependencies")
