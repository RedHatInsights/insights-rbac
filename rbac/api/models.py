#
# Copyright 2019 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""API models for import organization."""
from uuid import uuid4

from django.db import models
from tenant_schemas.models import TenantMixin

from api.status.models import Status  # noqa: F401


class Tenant(TenantMixin):
    """The model used to create a tenant schema."""

    # Override the mixin domain url to make it nullable, non-unique
    domain_url = None

    # Delete all schemas when a tenant is removed
    auto_drop_schema = True


class User(models.Model):
    """A request User."""

    uuid = models.UUIDField(default=uuid4, editable=False,
                            unique=True, null=False)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(blank=True)
    is_active = models.NullBooleanField(default=True)
    tenant = models.ForeignKey('Tenant', null=True, on_delete=models.CASCADE)

    class Meta:
        ordering = ['username']
