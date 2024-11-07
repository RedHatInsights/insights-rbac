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
import uuid_utils.compat as uuid
from django.db import models
from django.db.models import Q, UniqueConstraint
from django.utils import timezone
from management.rbac_fields import AutoDateTimeField

from api.models import TenantAwareModel


class Workspace(TenantAwareModel):
    """A workspace."""

    class Types(models.TextChoices):
        STANDARD = "standard"
        DEFAULT = "default"
        ROOT = "root"

    id = models.UUIDField(primary_key=True, default=uuid.uuid7, editable=False, unique=True, null=False)
    name = models.CharField(max_length=255)
    parent = models.ForeignKey("self", on_delete=models.PROTECT, related_name="children", null=True, blank=True)
    description = models.CharField(max_length=255, null=True, blank=True, editable=True)
    type = models.CharField(choices=Types.choices, default=Types.STANDARD, null=False)
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)

    class Meta:
        ordering = ["name", "modified"]
        constraints = [
            UniqueConstraint(
                fields=["tenant_id", "type"],
                name="unique_default_root_workspace_per_tenant",
                condition=Q(type__in=["root", "default"]),
            )
        ]

    def save(self, *args, **kwargs):
        """Override save on model to enforce validations."""
        self.full_clean()
        super().save(*args, **kwargs)

    def ancestors(self):
        """Return a list of ancestors for a Workspace instance."""
        ancestor_ids = [a.id for a in self._ancestry_queryset() if a.id != self.id]
        ancestors = Workspace.objects.filter(id__in=ancestor_ids)
        return ancestors

    def _ancestry_queryset(self):
        """Return a raw queryset on the workspace model for ancestors."""
        return Workspace.objects.raw(
            """
            WITH RECURSIVE ancestors AS
              (SELECT id,
                      parent_id
               FROM management_workspace
               WHERE id = %s
               UNION SELECT w.id,
                                w.parent_id
               FROM management_workspace w
               JOIN ancestors a ON w.id = a.parent_id)
            SELECT id
            FROM ancestors
        """,
            [self.id],
        )
