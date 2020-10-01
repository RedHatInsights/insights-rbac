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

"""Models to store cross account access request."""
import datetime
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from management.rbac_fields import AutoDateTimeField


STATUS_LIST = ["pending", "cancelled", "approved", "denied", "expired"]


class CrossAccountRequest(models.Model):
    """Cross account access request."""

    request_id = models.UUIDField(default=uuid4, editable=False, unique=True, null=False, primary_key=True)
    target_account = models.CharField(max_length=15, default=None)
    userId = models.CharField(max_length=15, default=None)
    created = models.DateTimeField(default=timezone.now)
    startDate = models.DateTimeField(default=timezone.now)
    endDate = models.DateTimeField(null=False, blank=False, default=None)
    modified = AutoDateTimeField(default=timezone.now)
    status = models.CharField(max_length=10, default="pending")

    def validate_input_value(self):
        """Validate status is valid, and date is valid."""
        if self.status not in STATUS_LIST:
            raise ValidationError(f'Unknown status "{self.status}" specified, {STATUS_LIST} are valid inputs.')

        if isinstance(self.endDate, datetime.datetime) and self.endDate <= timezone.now():
            raise ValidationError("Please verify the end date, it should not be a past value.")

        if (
            isinstance(self.endDate, datetime.datetime)
            and isinstance(self.startDate, datetime.datetime)
            and self.startDate >= self.endDate
        ):
            raise ValidationError("Start date must be earlier than end date.")

    def save(self, *args, **kwargs):
        """Override save method to validate some input."""
        self.validate_input_value()

        super(CrossAccountRequest, self).save(*args, **kwargs)
