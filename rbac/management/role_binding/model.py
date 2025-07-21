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

from uuid import uuid4

from django.db import models
from management.group.model import Group
from management.models import Principal
from management.role.model import RoleV2

from api.models import TenantAwareModel
from migration_tool.models import V2boundresource, V2rolebinding


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
            {p.source: str(p.user.uuid) for p in principal_entries}
            if not any(p.source is None for p in principal_entries)
            else [str(p.user.uuid) for p in principal_entries]
        )

        return V2rolebinding(
            id=str(self.id),
            role=self.role.as_migration_role(),
            resource=self.resource,
            groups=binding_groups,
            users=binding_users,
        )


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
