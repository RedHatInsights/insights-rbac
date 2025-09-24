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

"""Model for role V2 management."""

from uuid import uuid4

from django.db import models
from django.utils import timezone
from management.models import Permission, Role
from management.rbac_fields import AutoDateTimeField
from polymorphic.models import PolymorphicModel
from rest_framework import serializers

from api.models import TenantAwareModel


class RoleV2(PolymorphicModel, TenantAwareModel):
    """Base role model."""

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    name = models.CharField(max_length=150, null=False, blank=False)
    display_name = models.CharField(max_length=150, default="")
    description = models.TextField(null=True)
    permissions = models.ManyToManyField(Permission, related_name="v2_roles")
    children = models.ManyToManyField("self", related_name="parents", symmetrical=False)
    v1_source = models.ForeignKey(Role, null=True, related_name="v2_roles", on_delete=models.SET_NULL)
    version = models.PositiveIntegerField(default=1)
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)

    def save(self, *args, **kwargs):
        """Ensure that display_name is populated on save."""
        if not self.display_name:
            self.display_name = self.name
        super().save(*args, **kwargs)

    class Meta:
        ordering = ["name", "modified"]
        constraints = [
            models.UniqueConstraint(fields=["name", "tenant"], name="unique role v2 name per tenant"),
            models.UniqueConstraint(fields=["display_name", "tenant"], name="unique role v2 display name per tenant"),
        ]


class CustomRole(RoleV2):
    """Custom role type."""

    def clean(self):
        """Validate the model."""
        super().clean()
        if self.children.exists():
            raise serializers.ValidationError({"children": "Custom roles cannot have children."})


class SeededRole(RoleV2):
    """Seeded role type."""

    def clean(self):
        """Validate the model."""
        super().clean()
        if self.children.exists():
            raise serializers.ValidationError({"children": "Seeded roles cannot have children."})


class PlatformRole(RoleV2):
    """Platform role type."""
