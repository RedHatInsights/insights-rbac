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

import uuid_utils.compat as uuid
from django.db import models
from django.utils import timezone
from management.models import Permission, Role
from management.rbac_fields import AutoDateTimeField
from rest_framework import serializers

from api.models import TenantAwareModel


class RoleV2(TenantAwareModel):
    """V2 Role model."""

    class Types(models.TextChoices):
        CUSTOM = "custom"
        SEEDED = "seeded"
        PLATFORM = "platform"

    uuid = models.UUIDField(default=uuid.uuid7, editable=False, unique=True, null=False)
    name = models.CharField(max_length=150, null=False, blank=False)
    display_name = models.CharField(max_length=150, default="")
    description = models.TextField(null=True)
    type = models.CharField(
        choices=Types.choices, max_length=20, null=False, blank=False, db_index=True, default=Types.CUSTOM
    )
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


class TypedRoleV2Manager(models.Manager):
    """Manager for RoleV2 with a specific type."""

    _role_type: str

    def __init__(self, role_type: str):
        """Initialize the manager."""
        super().__init__()
        self._role_type = role_type

    def get_queryset(self):
        """Get the queryset for the specific type."""
        return super().get_queryset().filter(type=self._role_type)


class CustomRoleV2(RoleV2):
    """V2 Custom role model."""

    class Meta:
        proxy = True

    _expected_type = RoleV2.Types.CUSTOM
    objects = TypedRoleV2Manager(role_type=_expected_type)

    def __init__(self, *args, **kwargs):
        """Initialize the model."""
        super().__init__(*args, **kwargs)
        if not self.pk:
            self.type = self._expected_type
        elif self.type != self._expected_type:
            raise ValueError(f"Expected role to have type {self._expected_type}, but found {self.type}")

    def clean(self):
        """Validate the model."""
        super().clean()
        if self.children.exists():
            raise serializers.ValidationError({"children": "Custom roles cannot have children."})

    def save(self, **kwargs):
        """Save the model."""
        if self.type:
            if self.type != self._expected_type:
                raise ValueError(f"Expected role to have type {self._expected_type}, but found {self.type}")
        else:
            self.type = self._expected_type

        if (update_fields := kwargs.get("update_fields")) is not None:
            kwargs["update_fields"] = {"type", *update_fields}

        super().save(**kwargs)


class SeededRoleV2(RoleV2):
    """V2 Seeded role model."""

    class Meta:
        proxy = True

    _expected_type = RoleV2.Types.SEEDED
    objects = TypedRoleV2Manager(role_type=_expected_type)

    def __init__(self, *args, **kwargs):
        """Initialize the model."""
        super().__init__(*args, **kwargs)
        if not self.pk:
            self.type = self._expected_type
        elif self.type != self._expected_type:
            raise ValueError(f"Expected role to have type {self._expected_type}, but found {self.type}")

    def clean(self):
        """Validate the model."""
        super().clean()
        if self.children.exists():
            raise serializers.ValidationError({"children": "Seeded roles cannot have children."})

    def save(self, **kwargs):
        """Save the model."""
        if self.type:
            if self.type != self._expected_type:
                raise ValueError(f"Expected role to have type {self._expected_type}, but found {self.type}")
        else:
            self.type = self._expected_type

        if (update_fields := kwargs.get("update_fields")) is not None:
            kwargs["update_fields"] = {"type", *update_fields}

        super().save(**kwargs)


class PlatformRoleV2(RoleV2):
    """V2 Platform role model."""

    class Meta:
        proxy = True

    _expected_type = RoleV2.Types.PLATFORM
    objects = TypedRoleV2Manager(role_type=_expected_type)

    def __init__(self, *args, **kwargs):
        """Initialize the model."""
        super().__init__(*args, **kwargs)
        if not self.pk:
            self.type = self._expected_type
        elif self.type != self._expected_type:
            raise ValueError(f"Expected role to have type {self._expected_type}, but found {self.type}")

    def clean(self):
        """Validate the model."""
        super().clean()
        if self.children.exists():
            non_seeded_children = self.children.exclude(type=RoleV2.Types.SEEDED)
            if non_seeded_children.exists():
                raise serializers.ValidationError(
                    {"children": "Platform roles can only have seeded roles as children."}
                )

    def save(self, **kwargs):
        """Save the model."""
        if self.type:
            if self.type != self._expected_type:
                raise ValueError(f"Expected role to have type {self._expected_type}, but found {self.type}")
        else:
            self.type = self._expected_type

        if (update_fields := kwargs.get("update_fields")) is not None:
            kwargs["update_fields"] = {"type", *update_fields}

        super().save(**kwargs)
