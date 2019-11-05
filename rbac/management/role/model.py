#
# Copyright 2019 Red Hat, Inc.
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

"""Model for role management."""
from uuid import uuid4

from django.contrib.postgres.fields import JSONField
from django.db import models
from django.utils import timezone
from management.rbac_fields import AutoDateTimeField


class Role(models.Model):
    """A role."""

    uuid = models.UUIDField(default=uuid4, editable=False,
                            unique=True, null=False)
    name = models.CharField(max_length=150, unique=True)
    description = models.TextField(null=True)
    system = models.BooleanField(default=False)
    version = models.PositiveIntegerField(default=1)
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)

    class Meta:
        ordering = ['name', 'modified']


class Access(models.Model):
    """An access object."""

    permission = models.TextField(null=False)
    role = models.ForeignKey(Role, null=True, on_delete=models.CASCADE, related_name='access')


class ResourceDefinition(models.Model):
    """A resource definition."""

    attributeFilter = JSONField(default=dict)
    access = models.ForeignKey(Access, null=True, on_delete=models.CASCADE,
                               related_name='resourceDefinitions')
