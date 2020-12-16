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
    user_id = models.CharField(max_length=15, default=None)
    created = models.DateTimeField(default=timezone.now)
    start_date = models.DateTimeField(default=timezone.now)
    end_date = models.DateTimeField(null=False, blank=False, default=None)
    modified = AutoDateTimeField(default=timezone.now)
    status = models.CharField(max_length=10, default="pending")
    roles = models.ManyToManyField("management.Role", through="RequestsRoles")

    def validate_input_value(self):
        """Validate status is valid, and date is valid."""
        if self.status not in STATUS_LIST:
            raise ValidationError(f'Unknown status "{self.status}" specified, {STATUS_LIST} are valid inputs.')

        if isinstance(self.end_date, datetime.datetime) and self.end_date <= timezone.now():
            raise ValidationError("Please verify the end date, it should not be a past value.")

        if (
            isinstance(self.end_date, datetime.datetime)
            and isinstance(self.start_date, datetime.datetime)
            and self.start_date >= self.end_date
        ):
            raise ValidationError("Start date must be earlier than end date.")

    def save(self, *args, **kwargs):
        """Override save method to validate some input."""
        self.validate_input_value()

        super(CrossAccountRequest, self).save(*args, **kwargs)


class RequestsRoles(models.Model):
    """Model to associate the cross account access request and role."""

    cross_account_request = models.ForeignKey(CrossAccountRequest, on_delete=models.CASCADE)
    role = models.ForeignKey(
        "management.Role", on_delete=models.CASCADE, to_field="uuid", related_name="cross_account_requests"
    )


class CrossAccountRequestHistory(models.Model):
    """Cross account access request history."""

    cross_account_request = models.ForeignKey(CrossAccountRequest, on_delete=models.CASCADE, related_name="histories")
    target_account = models.CharField(max_length=15, default=None)
    created = models.DateTimeField(default=timezone.now)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    status = models.CharField(max_length=10)
    roles = models.ManyToManyField("management.Role", through="RequestHistoriesRoles")

    def save(self, *args, **kwargs):
        """Override save method to get values from ."""
        self.target_account = self.cross_account_request.target_account
        self.created = self.cross_account_request.modified
        self.start_date = self.cross_account_request.start_date
        self.end_date = self.cross_account_request.end_date
        self.status = self.cross_account_request.status

        super(CrossAccountRequestHistory, self).save(*args, **kwargs)
        self.roles.set(self.cross_account_request.roles.all())


class RequestHistoriesRoles(models.Model):
    """Model to associate the cross account access history request and role."""

    cross_account_request = models.ForeignKey(CrossAccountRequestHistory, on_delete=models.CASCADE)
    role = models.ForeignKey(
        "management.Role", on_delete=models.CASCADE, to_field="uuid", related_name="cross_account_request_histories"
    )
