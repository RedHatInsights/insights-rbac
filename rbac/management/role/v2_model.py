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

from typing import Iterable, Optional

from django.db import models
from django.db.models import QuerySet, signals
from django.utils import timezone
from management.models import Group, Permission, Principal, Role
from management.rbac_fields import AutoDateTimeField
from migration_tool.models import V2boundresource, V2role, V2rolebinding
from rest_framework import serializers
from uuid_utils.compat import UUID, uuid7

from api.models import TenantAwareModel


class RoleV2(TenantAwareModel):
    """V2 Role model."""

    class Types(models.TextChoices):
        CUSTOM = "custom"
        SEEDED = "seeded"
        PLATFORM = "platform"

    uuid = models.UUIDField(default=uuid7, editable=False, unique=True, null=False)
    name = models.CharField(max_length=175, null=False, blank=False)
    description = models.TextField(null=True, blank=True)
    type = models.CharField(
        choices=Types.choices, max_length=20, null=False, blank=False, db_index=True, default=Types.CUSTOM
    )
    permissions = models.ManyToManyField(Permission, related_name="v2_roles")
    children = models.ManyToManyField("self", related_name="parents", symmetrical=False)
    v1_source = models.ForeignKey(Role, null=True, blank=True, related_name="v2_roles", on_delete=models.CASCADE)
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

    def as_migration_value(self) -> V2role:
        """Get the V2role representing to this role's daya."""
        if self.type == RoleV2.Types.PLATFORM:
            raise ValueError("V2roles are not supported for PLATFORM roles.")

        if self.type == RoleV2.Types.SEEDED:
            return V2role.for_system_role(id=str(self.uuid))

        if self.type == RoleV2.Types.CUSTOM:
            return V2role(
                id=str(self.uuid),
                is_system=False,
                permissions=frozenset(p.v2_string() for p in self.permissions.all()),
            )

        raise ValueError(f"Unexpected type of role: {self.type} for {self}")


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


class RoleBinding(TenantAwareModel):
    """A role binding."""

    uuid = models.UUIDField(default=uuid7, editable=False, unique=True, null=False)
    role = models.ForeignKey(RoleV2, on_delete=models.CASCADE, related_name="bindings")

    resource_type = models.CharField(max_length=256, null=False)
    resource_id = models.CharField(max_length=256, null=False)

    def bound_groups(self) -> QuerySet:
        """Get a QuerySet for all groups bound to this RoleBinding."""
        return Group.objects.filter(role_binding_entries__in=self.group_entries.all())

    def update_groups(self, groups: Iterable[Group]):
        """Update the groups bound to this RoleBinding."""
        self.group_entries.all().delete()
        RoleBindingGroup.objects.bulk_create([RoleBindingGroup(binding=self, group=g) for g in set(groups)])

    def update_groups_by_uuid(self, uuids: Iterable[UUID | str]):
        """
        Update the groups bound to this RoleBinding by UUID.

        Raises a ValueError if one of the UUIDs cannot be found.
        """
        uuids = set(str(u) for u in uuids)

        groups = Group.objects.filter(uuid__in=uuids).only("id", "uuid")
        found_uuids = {str(g.uuid) for g in groups}

        if found_uuids != uuids:
            missing_uuids = uuids.difference(found_uuids)
            raise ValueError(f"Not all expected groups could be found. Missing UUIDs: {missing_uuids}")

        assert len(groups) == len(uuids)
        self.update_groups(groups)

    def bound_principals(self) -> QuerySet:
        """Get a QuerySet for all principals bound to this RoleBinding."""
        return Principal.objects.filter(role_binding_entries__in=self.principal_entries.all()).distinct()

    def update_principals(self, principals_by_source: Iterable[tuple[str, Principal]]):
        """
        Update the principals bound to this RoleBinding.

        principals_by_source is an iterable of pairs of the source string and the principal added from that source.
        """
        self.principal_entries.all().delete()

        RoleBindingPrincipal.objects.bulk_create(
            [RoleBindingPrincipal(binding=self, principal=p, source=s) for s, p in set(principals_by_source)]
        )

    def update_principals_by_user_id(self, user_ids_by_source: Iterable[tuple[str, str]]):
        """
        Update the principals bound to this RoleBinding by user_id.

        principals_by_source is an iterable of pairs of the source string and the user_id of the principal added from
        that source.

        A ValueError is raised if one of the user IDs cannot be found or if multiple principals are associated with
        one of the provided user IDs.
        """
        user_ids_by_source = set(user_ids_by_source)
        user_ids = set(entry[1] for entry in user_ids_by_source)

        if None in user_ids:
            raise TypeError("None user IDs are not supported.")

        principals = Principal.objects.filter(user_id__in=user_ids)
        found_user_ids: set[str] = {p.user_id for p in principals}

        if found_user_ids != user_ids:
            missing_user_ids = user_ids.difference(found_user_ids)
            raise ValueError(f"Not all expected principals could be found. Missing user IDs: {missing_user_ids}")

        # This should hold because principal user_ids are unique.
        assert len(principals) == len(user_ids)

        principals_by_id = {p.user_id: p for p in principals}
        assert len(principals_by_id) == len(user_ids)

        self.update_principals((s, principals_by_id[u]) for s, u in user_ids_by_source)

    def as_migration_value(self, force_group_uuids: Optional[list[str]] = None) -> V2rolebinding:
        """
        Return the V2rolebinding equivalent of this role binding.

        group_uuids is provided in the case where
        """
        if force_group_uuids is None:
            force_group_uuids = [str(u) for u in self.bound_groups().values_list("uuid", flat=True)]

        return V2rolebinding(
            id=str(self.uuid),
            role=self.role.as_migration_value(),
            resource=V2boundresource(
                # TODO: we currently assume all resources types are in namespace "rbac". This is currently true for
                #  all the types we care about, but is not necessarily true in general. The semantics of the
                #  Inventory API (which we will eventually have to migrate to) are different and do not have a
                #  resource type namespace, per se.
                resource_type=("rbac", self.resource_type),
                resource_id=self.resource_id,
            ),
            groups=force_group_uuids,
            users={},
        )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["role", "resource_type", "resource_id", "tenant"],
                name="unique role binding per role resource pair per tenant",
            ),
        ]


class RoleBindingGroup(models.Model):
    """The relationship between a RoleBinding and one of its group subjects."""

    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="role_binding_entries")
    binding = models.ForeignKey(RoleBinding, on_delete=models.CASCADE, related_name="group_entries")

    class Meta:
        constraints = [models.UniqueConstraint(fields=["group", "binding"], name="unique group binding pair")]


class RoleBindingPrincipal(models.Model):
    """The relationship between a RoleBinding and one of its principal subjects."""

    principal = models.ForeignKey(Principal, on_delete=models.CASCADE, related_name="role_binding_entries")
    binding = models.ForeignKey(RoleBinding, on_delete=models.CASCADE, related_name="principal_entries")
    source = models.CharField(max_length=128, default=None, null=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["principal", "binding", "source"], name="unique principal binding source triple"
            )
        ]


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
