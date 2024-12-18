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
from typing import Optional

from django.db import models
from django.db.models import Q

from api.cross_access.model import CrossAccountRequest  # noqa: F401
from api.status.model import Status  # noqa: F401


class TenantModifiedQuerySet(models.QuerySet):
    """Queryset for modified tenants."""

    def modified_only(self):
        """Return only modified tenants."""
        return (
            self.filter(Q(group__system=False) | Q(role__system=False))
            .prefetch_related("group_set", "role_set")
            .distinct()
        )


class Tenant(models.Model):
    """The model used to create a tenant schema."""

    ready = models.BooleanField(default=False)
    tenant_name = models.CharField(max_length=63)
    account_id = models.CharField(max_length=36, default=None, null=True)
    org_id = models.CharField(max_length=36, unique=True, default=None, db_index=True, null=True)
    objects = TenantModifiedQuerySet.as_manager()

    def __str__(self):
        """Get string representation of Tenant."""
        return f"Tenant ({self.org_id})"

    class Meta:
        indexes = [
            models.Index(fields=["ready"]),
        ]


class TenantAwareModel(models.Model):
    """Abstract model for inheriting `Tenant`."""

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)

    class Meta:
        abstract = True


class User:
    """A request User. Might also represent a service account."""

    _username: Optional[str] = None

    @property
    def username(self) -> Optional[str]:
        """Return the username."""
        return self._username

    @username.setter
    def username(self, value: Optional[str]) -> None:
        """
        Set the username.

        Lower-cases the username due to case insensitivity.
        """
        self._username = value.lower() if value else None

    account: Optional[str] = None
    admin: bool = False
    access = {}
    system: bool = False
    is_active: bool = True
    org_id: Optional[str] = None
    user_id: Optional[str] = None
    # Service account properties.
    bearer_token: str = ""
    client_id: str = ""
    is_service_account: bool = False


class FilterQuerySet(models.QuerySet):
    """Queryset for filtering."""

    _public_tenant = None

    @classmethod
    def _get_public_tenant(cls) -> Tenant:
        """Get or set public tenant."""
        if cls._public_tenant is None:
            cls._public_tenant = Tenant.objects.get(tenant_name="public")
        return cls._public_tenant

    def non_custom_only(self):
        """Filter queryset by returning only non-custom results."""
        return self.filter(system=True, tenant=FilterQuerySet._get_public_tenant())
