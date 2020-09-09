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
from uuid import uuid4

from django.db import models
from django.utils import timezone
from management.rbac_fields import AutoDateTimeField

STATUS_LIST = ["requested", "cancelled", "approved", "denied"]


class Employee(models.Model):
    """Info of employee."""

    account = models.CharField(max_length=15)
    username = models.CharField(max_length=150, unique=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    email = models.CharField(max_length=150)


class CrossAccountRequest(models.Model):
    """Cross account access request."""

    request_id = models.UUIDField(default=uuid4, editable=False, unique=True, null=False, primary_key=True)
    target_account = models.CharField(max_length=15)
    employee = models.ForeignKey(Employee, null=False, on_delete=models.CASCADE, related_name="employee")
    created = models.DateTimeField(default=timezone.now)
    startDate = models.DateTimeField(default=timezone.now)
    endDate = models.DateTimeField()
    modified = AutoDateTimeField(default=timezone.now)
    status = models.CharField(max_length=10, default="requested")

    def validate_input_value(self):
        """Validate status is valid, and date is valid."""
        if self.status not in STATUS_LIST:
            raise Exception(f'Unknown status "{self.status}" specified, {STATUS_LIST} are valid inputs.')

        if self.startDate >= self.endDate:
            raise Exception("Start date must be earlier than end date.")

    def save(self, *args, **kwargs):
        """Override save method to validate some input."""
        self.validate_input_value()

        super(CrossAccountRequest, self).save(*args, **kwargs)
