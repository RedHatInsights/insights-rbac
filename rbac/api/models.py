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
from tenant_schemas.models import TenantMixin

from api.cross_access.model import CrossAccountRequest  # noqa: F401
from api.permission.model import Permission  # noqa: F401
from api.role.model import Access, Role  # noqa: F401
from api.status.model import Status  # noqa: F401


class Tenant(TenantMixin):
    """The model used to create a tenant schema."""

    # Override the mixin domain url to make it nullable, non-unique
    domain_url = None

    # Delete all schemas when a tenant is removed
    auto_drop_schema = True

    def __str__(self):
        """Get string representation of Tenant."""
        return f"Tenant ({self.schema_name})"


class User:
    """A request User."""

    username = None
    account = None
    admin = False
    access = {}
    system = False
    is_active = True
