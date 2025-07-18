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

    groups = models.ManyToManyField(Group)
    principals = models.ManyToManyField(Principal)

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
        return V2rolebinding(
            id=str(self.id),
            role=self.role.as_migration_role(),
            resource=self.resource,
            groups=[str(group.uuid) for group in self.groups.all()],
            users=[str(principal.uuid) for principal in self.principals.all()],
        )
