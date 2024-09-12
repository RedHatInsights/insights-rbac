#
# Copyright 2024 Red Hat, Inc.
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
"""Model for workspace management."""
from uuid import uuid4

from django.db import models
from django.utils import timezone
from management.rbac_fields import AutoDateTimeField

from api.models import TenantAwareModel


class Workspace(TenantAwareModel):
    """A workspace."""

    name = models.CharField(max_length=255)
    uuid = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    parent = models.ForeignKey(
        "self", to_field="uuid", on_delete=models.PROTECT, related_name="children", null=True, blank=True
    )
    description = models.CharField(max_length=255, null=True, blank=True, editable=True)
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)

    class Meta:
        ordering = ["name", "modified"]

    def ancestors(self):
        """Return a list of ancestors for a Workspace instance."""
        ancestor_ids = [a.uuid for a in self._ancestry_queryset() if a.uuid != self.uuid]
        ancestors = Workspace.objects.filter(uuid__in=ancestor_ids)
        return ancestors

    def _ancestry_queryset(self):
        """Return a raw queryset on the workspace model for ancestors."""
        return Workspace.objects.raw(
            """
            WITH RECURSIVE ancestors AS
              (SELECT uuid,
                      parent_id
               FROM management_workspace
               WHERE uuid = %s
               UNION SELECT w.uuid,
                                w.parent_id
               FROM management_workspace w
               JOIN ancestors a ON w.uuid = a.parent_id)
            SELECT uuid AS uuid,
                   uuid AS id
            FROM ancestors
        """,
            [self.uuid],
        )
