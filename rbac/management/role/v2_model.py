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
from django.db.models import signals
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
    description = models.TextField(null=True, blank=True)
    type = models.CharField(
        choices=Types.choices, max_length=20, null=False, blank=False, db_index=True, default=Types.CUSTOM
    )
    permissions = models.ManyToManyField(Permission, related_name="v2_roles")
    children = models.ManyToManyField("self", related_name="parents", symmetrical=False)
    v1_source = models.ForeignKey(Role, null=True, blank=True, related_name="v2_roles", on_delete=models.SET_NULL)
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)

    class Meta:
        ordering = ["name", "modified"]
        constraints = [
            models.UniqueConstraint(fields=["name", "tenant"], name="unique role v2 name per tenant"),
        ]

    def save(self, *args, **kwargs):
        """Save the model and run all validations from the model."""
        self.full_clean()
        super().save(*args, **kwargs)


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


class TypeValidatedRoleV2Mixin:
    """Mixin for role types that validates type on init and save."""

    _expected_type: str = ""

    def __init__(self, *args, **kwargs):
        """Initialize the model with type validation."""
        type_provided = "type" in kwargs
        provided_type = kwargs.get("type") if type_provided else None

        super().__init__(*args, **kwargs)

        if not self.pk:
            if type_provided and provided_type != self._expected_type:
                raise serializers.ValidationError(
                    f"Expected role to have type {self._expected_type}, but found {provided_type}"
                )
            else:
                self.type = self._expected_type
        elif self.type != self._expected_type:
            raise serializers.ValidationError(
                f"Expected role to have type {self._expected_type}, but found {self.type}"
            )

    def save(self, **kwargs):
        """Save the model with type validation."""
        if self.type and self.type != self._expected_type:
            raise serializers.ValidationError(
                f"Expected role to have type {self._expected_type}, but found {self.type}"
            )
        else:
            self.type = self._expected_type

        if (update_fields := kwargs.get("update_fields")) is not None:
            kwargs["update_fields"] = {"type", *update_fields}

        self.full_clean()
        super().save(**kwargs)


class CustomRoleV2(TypeValidatedRoleV2Mixin, RoleV2):
    """V2 Custom role model."""

    class Meta:
        proxy = True

    _expected_type = RoleV2.Types.CUSTOM
    objects = TypedRoleV2Manager(role_type=_expected_type)


class SeededRoleV2(TypeValidatedRoleV2Mixin, RoleV2):
    """V2 Seeded role model."""

    class Meta:
        proxy = True

    _expected_type = RoleV2.Types.SEEDED
    objects = TypedRoleV2Manager(role_type=_expected_type)


class PlatformRoleV2(TypeValidatedRoleV2Mixin, RoleV2):
    """V2 Platform role model."""

    class Meta:
        proxy = True

    _expected_type = RoleV2.Types.PLATFORM
    objects = TypedRoleV2Manager(role_type=_expected_type)


def validate_role_children_on_m2m_change(sender, instance, action, pk_set, **kwargs):
    """
    Signal handler to validate role children relationships on M2M changes.
    This validates BEFORE the M2M relationship is written to the database.
    """
    if action != "pre_add":
        return

    parent_type = instance.type

    if parent_type == RoleV2.Types.PLATFORM:
        if pk_set:
            invalid_children = RoleV2.objects.filter(pk__in=pk_set).exclude(type=RoleV2.Types.SEEDED)
            if invalid_children.exists():
                raise serializers.ValidationError(
                    {"children": "Platform roles can only have seeded roles as children."}
                )
    else:
        raise serializers.ValidationError({"children": f"{parent_type.capitalize()} roles cannot have children."})


# Connect the signal handler to the RoleV2.children through model
signals.m2m_changed.connect(validate_role_children_on_m2m_change, sender=RoleV2.children.through)
