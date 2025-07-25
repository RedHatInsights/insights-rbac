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
from kessel.relations.v1beta1.common_pb2 import Relationship
from typing import Optional
from uuid import uuid4

from django.db import models
from management.group.model import Group
from management.models import Principal
from management.role.model import BindingMapping, RoleV2

from api.models import TenantAwareModel
from migration_tool.models import V2boundresource, V2rolebinding, role_binding_group_subject_tuple


class RoleBinding(TenantAwareModel):
    """A role binding."""

    id = models.UUIDField(default=uuid4, primary_key=True, editable=False, unique=True, null=False)
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
        return V2boundresource(
            resource_type=(self.resource_type_namespace, self.resource_type_name),
            resource_id=self.resource_id,
        )

    @resource.setter
    def resource(self, new_resource: V2boundresource):
        self.resource_type_namespace = new_resource.resource_type[0]
        self.resource_type_name = new_resource.resource_type[1]
        self.resource_id = new_resource.resource_id

    def as_migration_rolebinding(self) -> V2rolebinding:
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
            id=str(self.id),
            role=self.role.as_migration_role(),
            resource=self.resource,
            groups=binding_groups,
            users=binding_users,
        )

    def id_matches(self, binding_mapping: BindingMapping) -> bool:
        """Determine whether this RoleBinding has the same UUID as the passing BindingMapping."""

        if self.id is None:
            raise ValueError("Cannot call id_matches on an unsaved RoleBinding")

        return str(self.id) == binding_mapping.mappings["id"]

    def pop_group(self, group_uuid: str) -> Optional[Relationship]:
        """
        Pop the group from mappings.

        The group may still be bound to the role in other ways, so the group may still be included in the binding
        more than once after this method returns.

        If the group is no longer assigned at all, the Relationship is returned to be removed.

        This has the same meaning as BindingMapping.pop_group_from_bindings, but note that the effects of this method
        are applied immediately (*not* when save() is called).
        """

        entry_ids: list[int] = list(
            self.group_entries.filter(group__uuid=group_uuid).values_list("id", flat=True).order_by("id")
        )

        if len(entry_ids) > 0:
            deleted_count, _ = self.group_entries.filter(id=entry_ids[0]).delete()
            assert deleted_count == 1

        if len(entry_ids) > 1:
            return None

        return role_binding_group_subject_tuple(role_binding_id=str(self.id), group_uuid=group_uuid)

    def assign_group(self, group_uuid: str) -> Optional[Relationship]:
        """
        Assign group to mappings.

        If the group entry already exists, skip it.

        This has the same meaning as BindingMapping.assign_group, but note that the effects of this method are
        applied immediately (*not* when save() is called).
        """

        if not self.group_entries.filter(group__uuid=group_uuid).exists():
            return self.add_group(group_uuid=group_uuid)

        return role_binding_group_subject_tuple(role_binding_id=str(self.id), group_uuid=group_uuid)

    def add_group(self, group_uuid: str) -> Optional[Relationship]:
        """
        Add group to mappings.

        This adds an additional entry for the group, even if the group is already assigned, to account for multiple
        possible sources that may have assigned the group for the same role and resource.

        This has the same meaning as BindingMapping.add_group, but note that the effects of this method are
        applied immediately (*not* when save() is called).
        """

        self.group_entries.create(group=Group.objects.get(uuid=group_uuid))
        return role_binding_group_subject_tuple(role_binding_id=str(self.id), group_uuid=group_uuid)

    def unassign_group(self, group_uuid: str) -> Optional[Relationship]:
        """
        Completely unassign this group from the mapping, even if it is assigned more than once.

        Returns the Relationship for this Group.

        This has the same meaning as BindingMapping.unassign_group, but note that the effects of this method are
        applied immediately (*not* when save() is called).
        """

        self.group_entries.filter(group__uuid=group_uuid).delete()
        return role_binding_group_subject_tuple(role_binding_id=str(self.id), group_uuid=group_uuid)

    def is_unassigned(self) -> bool:
        """Return true if mapping is not assigned to any groups or users."""
        return (not self.group_entries.exists()) and (not self.principal_entries.exists())


class RoleBindingPrincipal(models.Model):
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
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="role_binding_entries")
    binding = models.ForeignKey(RoleBinding, on_delete=models.CASCADE, related_name="group_entries")
