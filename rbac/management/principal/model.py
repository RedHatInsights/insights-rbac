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

"""Model for principal management."""
from uuid import uuid4

from django.db import models

from api.models import TenantAwareModel


class Principal(TenantAwareModel):
    """A principal."""

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    username = models.CharField(max_length=150, unique=True)
    cross_account = models.BooleanField(default=False)

    class Meta:
        ordering = ["username"]
        constraints = [
            models.UniqueConstraint(fields=['username', 'tenant'], name='unique principal username per tenant')
        ]

