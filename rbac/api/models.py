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
from django.conf import settings
from django.db import models
from tenant_schemas.models import TenantMixin
from werkzeug.local import Local

from api.cross_access.model import CrossAccountRequest  # noqa: F401
from api.status.model import Status  # noqa: F401

_local = Local()

class Tenant(TenantMixin):
    """The model used to create a tenant schema."""

    ready = models.BooleanField(default=False)

    # Override the mixin domain url to make it nullable, non-unique
    domain_url = None

    # Delete all schemas when a tenant is removed
    auto_drop_schema = True
    auto_create_schema = False

    def __str__(self):
        """Get string representation of Tenant."""
        return f"Tenant ({self.schema_name})"


class TenantModelManager(models.Manager):
    """Manager for auto-filtering on tenant."""
    def get_queryset(self):
        req = getattr(_local, 'request', None)
        if req:
            qs = super().get_queryset().filter(tenant=req.tenant)
        else:
            qs = super().get_queryset()
        
        return qs

class TenantAwareModel(models.Model):
    """Abstract model for inheriting `Tenant`."""

    tenant = models.ForeignKey(Tenant, blank=True, null=True, on_delete=models.CASCADE)
    if settings.SERVE_FROM_PUBLIC_SCHEMA:   
        objects = TenantModelManager()

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
