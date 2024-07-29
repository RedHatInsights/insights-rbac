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
    parent = models.UUIDField(null=True, blank=True, editable=True)
    description = models.CharField(max_length=255, null=True, blank=True, editable=True)
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)

    class Meta:
        ordering = ["name", "modified"]
        constraints = [
            models.UniqueConstraint(
                fields=["name", "tenant", "parent"],
                name="The combination of 'name', 'tenant', and 'parent' must be unique.",
            ),
        ]
