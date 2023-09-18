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

"""Model for Service management."""
from uuid import uuid4
from django.utils import timezone
from django.db import models

from api.models import Tenant


class Service(models.Model):
    """A service."""

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    name = models.CharField(max_length=150)

    class Meta:
        ordering = ["name"]

class ServiceAccess(models.Model):
    """Service Access"""

    service = models.ForeignKey(Service, related_name='service_access', on_delete=models.CASCADE, null=True)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    start_date = models.DateTimeField(default=timezone.now)
    end_date = models.DateTimeField(null=False, blank=False, default=None)
    access = models.BooleanField(default=False)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["service", "tenant"], name="unique service access per tenant")]