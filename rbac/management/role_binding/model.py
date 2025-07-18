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
