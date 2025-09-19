#
# Copyright 2024 Red Hat, Inc.
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
"""TenantMapping model."""

import logging
import uuid

from django.db import models

from api.models import Tenant


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class TenantMapping(models.Model):
    """Tenant mappings to V2 domain concepts."""

    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE, related_name="tenant_mapping")

    # Default group UUID specific to a Tenant. This is used for adding members of the Tenant to the access graph.
    # It is also used for custom default group UUID, so that the custom roles get bound to the default group
    # members.
    default_group_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)
    # The admin default group UUID, for the same purpose as above, except for admin users.
    default_admin_group_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)

    # UUIDs for the role bindings that bind the user default and admin default groups to the appropriate platform
    # groups. One such role binding exists for each of the scopes that has default roles: the tenant itself, the
    # tenant's root workspace, and the tenant's default workspace.
    default_role_binding_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)
    default_admin_role_binding_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)
    root_scope_default_role_binding_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)
    root_scope_default_admin_role_binding_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)
    tenant_scope_default_role_binding_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)
    tenant_scope_default_admin_role_binding_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)
