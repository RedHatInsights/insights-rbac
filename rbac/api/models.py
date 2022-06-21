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
from django.db import models

from api.cross_access.model import CrossAccountRequest  # noqa: F401
from api.status.model import Status  # noqa: F401


class Tenant(models.Model):
    """The model used to create a tenant schema."""

    ready = models.BooleanField(default=False)
    tenant_name = models.CharField(max_length=63, db_index=True)
    account_id = models.CharField(max_length=36, default=None, null=True)
    org_id = models.CharField(max_length=36, unique=True, default=None, null=True)

    def __str__(self):
        """Get string representation of Tenant."""
        return f"Tenant ({self.tenant_name})"


class TenantAwareModel(models.Model):
    """Abstract model for inheriting `Tenant`."""

    tenant = models.ForeignKey(Tenant, blank=True, null=True, on_delete=models.CASCADE)

    class Meta:
        abstract = True


class User:
    """A request User."""

    username = None
    account = None
    admin = False
    access = {}
    system = False
    is_active = True
    org_id = None
