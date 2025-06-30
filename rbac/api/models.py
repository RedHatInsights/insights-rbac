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
from typing import Any, Optional

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

    _public_tenant = None

    ready = models.BooleanField(default=False)
    tenant_name = models.CharField(max_length=63)
    account_id = models.CharField(max_length=36, default=None, null=True)
    org_id = models.CharField(max_length=36, unique=True, default=None, db_index=True, null=True)
    objects = TenantModifiedQuerySet.as_manager()

    def __str__(self):
        """Get string representation of Tenant."""
        return f"Tenant ({self.org_id})"

    @classmethod
    def _get_public_tenant(cls):
        """Get or set public tenant."""
        if cls._public_tenant is None:
            cls._public_tenant = Tenant.objects.get(tenant_name="public")
        return cls._public_tenant

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

    def __init__(self, **kwargs: Any):
        """
        Initialize User with optional parameters.

        :param kwargs: Optional parameters to set on the User instance.
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

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

    def __eq__(self, other):
        """Check equality of User instances."""
        if not isinstance(other, User):
            return NotImplemented
        return (
            self.username == other.username
            and self.account == other.account
            and self.admin == other.admin
            and self.access == other.access
            and self.system == other.system
            and self.is_active == other.is_active
            and self.org_id == other.org_id
            and self.user_id == other.user_id
            and self.bearer_token == other.bearer_token
            and self.client_id == other.client_id
            and self.is_service_account == other.is_service_account
        )

    def __hash__(self):
        """Hash the User instance."""
        return hash((self.username, self.user_id, self.client_id))

    def __repr__(self):
        """Return a string representation of the User instance."""
        return (
            f"User(username={self.username!r}, account={self.account!r}, admin={self.admin!r}, "
            f"system={self.system!r}, is_active={self.is_active!r}, org_id={self.org_id!r}, "
            f"user_id={self.user_id!r}, bearer_token={'***' if self.bearer_token else ''}, "
            f"client_id={self.client_id!r}, is_service_account={self.is_service_account!r})"
        )


class FilterQuerySet(models.QuerySet):
    """Queryset for filtering."""

    def public_tenant_only(self):
        """Filter queryset by returning only non-custom results."""
        return self.filter(system=True, tenant=Tenant._get_public_tenant())
