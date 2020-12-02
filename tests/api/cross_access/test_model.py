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
"""Test the cross account request model."""
from api.models import CrossAccountRequest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from datetime import timedelta


class CrossAccountRequestModelTests(TestCase):
    """Test the cross account request model."""

    def setUp(self):
        """Set up the cross account request model tests."""
        super().setUp()

        self.ref_time = timezone.now()
        self.request = CrossAccountRequest.objects.create(
            target_account="123456", user_id="567890", end_date=self.ref_time + timedelta(10)
        )

    def tearDown(self):
        """Tear down cross account request model tests."""
        CrossAccountRequest.objects.all().delete()

    def test_request_creation_success(self):
        """Test the creation of cross account request."""
        self.assertEqual(self.request.target_account, "123456")
        self.assertEqual(self.request.user_id, "567890")
        self.assertIsNotNone(self.request.start_date)
        self.assertEqual(self.request.end_date, self.ref_time + timedelta(10))
        self.assertEqual(self.request.status, "pending")

    def test_request_creation_fail_without_target(self):
        """Test the creation of cross account request fail without target."""
        with transaction.atomic():
            self.assertRaises(
                IntegrityError,
                CrossAccountRequest.objects.create,
                user_id="567890",
                end_date=self.ref_time + timedelta(10),
            )

    def test_request_with_unknown_status_fail(self):
        """Test the creation of cross account request with unknown status fail."""
        # Can't create
        self.assertRaises(
            ValidationError,
            CrossAccountRequest.objects.create,
            target_account="123456",
            user_id="567890",
            end_date=self.ref_time + timedelta(10),
            status="unknown",
        )
        # Can't update
        self.request.status = "unknown"
        self.assertRaises(ValidationError, self.request.save)

    def test_request_with_invalid_date(self):
        """Test the start date must be earlier than end date."""
        # Can't create
        self.assertRaises(
            ValidationError,
            CrossAccountRequest.objects.create,
            target_account="123456",
            user_id="567890",
            end_date=self.ref_time - timedelta(10),
        )
        # Can't update
        self.request.end_date = self.ref_time - timedelta(10)
        self.assertRaises(ValidationError, self.request.save)

        # Omitted end date
        with transaction.atomic():
            self.assertRaises(
                IntegrityError, CrossAccountRequest.objects.create, target_account="123456", user_id="567890"
            )

        # Invalid end_date, omitted start date
        with transaction.atomic():
            self.assertRaises(
                ValidationError,
                CrossAccountRequest.objects.create,
                target_account="33823827",
                user_id="567890",
                end_date="RSTLNE118",
            )

        # Invalid start and end date
        with transaction.atomic():
            self.assertRaises(
                ValidationError,
                CrossAccountRequest.objects.create,
                target_account="8888888",
                user_id="567890",
                start_date="INVALID",
                end_date="INVALID",
            )

        # End date earlier than now
        self.assertRaises(
            ValidationError,
            CrossAccountRequest.objects.create,
            target_account="8888888",
            user_id="567890",
            end_date=timezone.now() - timedelta(1),
        )
