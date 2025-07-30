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

"""Model for role bindings."""
from typing import Optional
from uuid import uuid4

from django.db import models
from django.db.models import F, Q
from kessel.relations.v1beta1.common_pb2 import Relationship
from management.group.model import Group
from management.models import Principal
from management.role.model import BindingMapping, RoleV2, SourceKey
from migration_tool.models import (
    V2boundresource,
    V2rolebinding,
    role_binding_group_subject_tuple,
    role_binding_user_subject_tuple,
)

from api.models import TenantAwareModel


class RoleBinding(TenantAwareModel):
    """A role binding."""

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    role = models.ForeignKey(RoleV2, on_delete=models.CASCADE, related_name="bindings")

    resource_type_namespace = models.CharField(max_length=256, null=False)
    resource_type_name = models.CharField(max_length=256, null=False)
    resource_id = models.CharField(max_length=256, null=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["role", "resource_type_namespace", "resource_type_name", "resource_id"],
                name="unique role binding per role resource pair",
            ),
        ]

    @property
    def resource(self) -> V2boundresource:
        """Return the V2boundresource for the resource referenced by this RoleBinding."""
        return V2boundresource(
            resource_type=(self.resource_type_namespace, self.resource_type_name),
            resource_id=self.resource_id,
        )

    @resource.setter
    def resource(self, new_resource: V2boundresource):
        """Set the V2boundresource for the resource referenced by this RoleBinding."""
        self.resource_type_namespace = new_resource.resource_type[0]
        self.resource_type_name = new_resource.resource_type[1]
        self.resource_id = new_resource.resource_id

    def as_migration_rolebinding(self) -> V2rolebinding:
        """Get the V2rolebinding equivalent of this RoleBinding."""
        binding_groups = [str(e.group.uuid) for e in self.group_entries.all()]
        principal_entries = list(self.principal_entries.all())

        # A dict (from sources to user UUIDs) is the updated representation of a BindingMapping. A list of user UUIDs is
        # the old form. Use the updated form if and only if we have a source for all principals.
        binding_users = (
            {p.source: str(p.principal.user_id) for p in principal_entries}
            if not any(p.source is None for p in principal_entries)
            else [str(p.principal.user_id) for p in principal_entries]
        )

        return V2rolebinding(
            id=str(self.uuid),
            role=self.role.as_migration_role(),
            resource=self.resource,
            groups=binding_groups,
            users=binding_users,
        )

    def id_matches(self, binding_mapping: BindingMapping) -> bool:
        """Determine whether this RoleBinding has the same UUID as the passing BindingMapping."""
        if self.id is None or self.uuid is None:
            raise ValueError("Cannot call id_matches on an unsaved RoleBinding")

        return str(self.uuid) == binding_mapping.mappings["id"]

    def pop_group(self, group_uuid: str) -> Optional[Relationship]:
        """
        Pop the group from mappings.

        The group may still be bound to the role in other ways, so the group may still be included in the binding
        more than once after this method returns.

        If the group is no longer assigned at all, the Relationship is returned to be removed.

        This has the same meaning as BindingMapping.pop_group_from_bindings, but note that the effects of this method
        are applied immediately (*not* when save() is called).
        """
        to_delete: list[RoleBindingGroup] = list(self.group_entries.filter(group__uuid=group_uuid))

        if len(to_delete) > 0:
            to_delete[0].delete()

        if len(to_delete) > 1:
            return None

        return role_binding_group_subject_tuple(role_binding_id=str(self.uuid), group_uuid=group_uuid)

    def assign_group(self, group_uuid: str) -> Optional[Relationship]:
        """
        Assign group to mappings.

        If the group entry already exists, skip it.

        This has the same meaning as BindingMapping.assign_group, but note that the effects of this method are
        applied immediately (*not* when save() is called).
        """
        if not self.group_entries.filter(group__uuid=group_uuid).exists():
            return self.add_group(group_uuid=group_uuid)

        return role_binding_group_subject_tuple(role_binding_id=str(self.uuid), group_uuid=group_uuid)

    def add_group(self, group_uuid: str) -> Optional[Relationship]:
        """
        Add group to mappings.

        This adds an additional entry for the group, even if the group is already assigned, to account for multiple
        possible sources that may have assigned the group for the same role and resource.

        This has the same meaning as BindingMapping.add_group, but note that the effects of this method are
        applied immediately (*not* when save() is called).
        """
        self.group_entries.create(group=Group.objects.get(uuid=group_uuid))
        return role_binding_group_subject_tuple(role_binding_id=str(self.uuid), group_uuid=group_uuid)

    def unassign_group(self, group_uuid: str) -> Optional[Relationship]:
        """
        Completely unassign this group from the mapping, even if it is assigned more than once.

        Returns the Relationship for this Group.

        This has the same meaning as BindingMapping.unassign_group, but note that the effects of this method are
        applied immediately (*not* when save() is called).
        """
        self.group_entries.filter(group__uuid=group_uuid).delete()
        return role_binding_group_subject_tuple(role_binding_id=str(self.uuid), group_uuid=group_uuid)

    def assign_user(self, user_id: str, source: Optional[SourceKey]) -> Relationship:
        """
        Assign user to mappings.

        This has the same meaning as BindingMapping.assign_user_to_bindings, but note that the effects of this
        method are applied immediately (*not* when save() is called).
        """
        principal = Principal.objects.filter(user_id=user_id).get()

        # We maintain the invariant that, for a given RoleBinding, either all principals have no source or all
        # principals have a source. This mirrors the list/dict representation in BindingMapping.

        if self.principal_entries.filter(source=None).exists():
            self.principal_entries.create(principal=principal)
        else:
            if source is None:
                raise ValueError(
                    "Cannot add a principal entry with no source unless such a principal entry already exists."
                )

            self.principal_entries.get_or_create(principal=principal, source=source)

        return role_binding_user_subject_tuple(str(self.uuid), user_id)

    def unassign_user(self, user_id: str, source: Optional[SourceKey]) -> Optional[Relationship]:
        """
        Unassign user from mappings.

        This has the same meaning as BindingMapping.unassign_user_from_bindings, but note that the effects of this
        method are applied immediately (*not* when save() is called).
        """
        # We maintain the invariant that all sources are null or no sources are null.

        to_delete: Optional["RoleBindingPrincipal"]

        if source is not None:
            # It is acceptable to delete an entry with a null source. Source an entry existing means that all sources
            # are none.
            to_delete = (
                self.principal_entries.filter(principal__user_id=user_id)
                .filter(Q(source=None) | Q(source=source))
                .order_by(F("source").asc(nulls_last=True))
                .first()
            )
        else:
            # In this case, BindingMapping would delete any entry. We are more conservative: an entry with a source
            # cannot be deleted from a call without a source.
            to_delete = (
                self.principal_entries.filter(principal__user_id=user_id)
                .order_by(F("source").asc(nulls_last=True))
                .first()
            )

        if to_delete is not None:
            if (source is None) and (to_delete.source is not None):
                raise ValueError("Cannot delete an entry with a source unless a source is provided.")

            to_delete.delete()

        if self.principal_entries.filter(principal__user_id=user_id).exists():
            return None

        return role_binding_user_subject_tuple(str(self.uuid), user_id)

    def update_data_format(self, all_relations_to_remove):
        """
        Update data format for users in mappings.

        This has the same meaning as BindingMapping.update_data_format_for_user, but note that the effects of this
        method are applied immediately (*not* when save() is called).
        """
        entries_to_remove = self.principal_entries.filter(source=None)
        removed_user_ids = set(entry.principal.user_id for entry in entries_to_remove)

        entries_to_remove.delete()

        for user_id in removed_user_ids:
            all_relations_to_remove.append(role_binding_user_subject_tuple(str(self.uuid), user_id))

    def is_unassigned(self) -> bool:
        """Return true if mapping is not assigned to any groups or users."""
        return (not self.group_entries.exists()) and (not self.principal_entries.exists())


class RoleBindingPrincipal(models.Model):
    """The relationship between a RoleBinding and one of its principal subjects."""

    principal = models.ForeignKey(Principal, on_delete=models.CASCADE, related_name="role_binding_entries")
    binding = models.ForeignKey(RoleBinding, on_delete=models.CASCADE, related_name="principal_entries")
    source = models.CharField(max_length=128, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["principal", "binding", "source"], name="unique principal binding source triple"
            )
        ]


class RoleBindingGroup(models.Model):
    """The relationship between a RoleBinding and one of its group subjects."""

    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="role_binding_entries")
    binding = models.ForeignKey(RoleBinding, on_delete=models.CASCADE, related_name="group_entries")
