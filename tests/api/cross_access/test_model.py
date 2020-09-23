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
from api.models import CrossAccountRequest, Employee
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone
from tenant_schemas.utils import tenant_context

from datetime import timedelta
from unittest.mock import Mock
from tests.identity_request import IdentityRequest


class CrossAccountRequestModelTests(IdentityRequest):
    """Test the cross account request model."""

    def setUp(self):
        """Set up the cross account request model tests."""
        super().setUp()

        self.ref_time = timezone.now()
        self.employee = Employee.objects.create(
            account="654321",
            username="requestor_test",
            first_name="requestor",
            last_name="test",
            email="requestor@redhat.com",
        )
        self.request = CrossAccountRequest.objects.create(
            target_account="123456", employee=self.employee, endDate=self.ref_time + timedelta(10)
        )

    def tearDown(self):
        """Tear down cross account request model tests."""
        Employee.objects.all().delete()
        CrossAccountRequest.objects.all().delete()

    def test_request_creation_success(self):
        """Test the creation of cross account request."""
        self.assertEqual(self.request.target_account, "123456")
        self.assertEqual(self.request.employee.account, "654321")
        self.assertEqual(self.request.employee.username, "requestor_test")
        self.assertIsNotNone(self.request.startDate)
        self.assertEqual(self.request.endDate, self.ref_time + timedelta(10))
        self.assertEqual(self.request.status, "requested")

    def test_request_with_invalid_dates(self):
        """Confirm that an invalid start or end date is rejected."""
        # Invalid start date, omitted end date
        self.assertRaises(
            Exception,
            CrossAccountRequest.objects.create,
            target_account="123456",
            employee=self.employee,
            startDate="ABC123"
        )

        # Invalid endDate, omitted start date
        self.assertRaises(
            Exception,
            CrossAccountRequest.objects.create,
            target_account="33823827",
            employee=self.employee,
            endDate="RSTLNE118"
        )

        # Invalid start and end date
        self.assertRaises(
            Exception,
            CrossAccountRequest.objects.create,
            target_account="8888888",
            employee=self.employee,
            startDate="INVALID",
            endDate="INVALID"
        )

        # TODO: Can we be more specific about the exception that we want raised?

    def test_request_with_unknown_status_fail(self):
        """Test the creation of cross account request with unknown status fail."""
        # Can't create
        self.assertRaises(
            Exception,
            CrossAccountRequest.objects.create,
            target_account="123456",
            employee=self.employee,
            endDate=self.ref_time + timedelta(10),
            status="unknown",
        )
        # Can't update
        self.request.status = "unknown"
        self.assertRaises(Exception, self.request.save)

    def test_request_with_invalid_date(self):
        """Test the start date must be earlier than end date."""
        # Can't create
        self.assertRaises(
            Exception,
            CrossAccountRequest.objects.create,
            target_account="123456",
            employee=self.employee,
            endDate=self.ref_time - timedelta(10),
        )
        # Can't update
        self.request.endDate = self.ref_time - timedelta(10)
        self.assertRaises(Exception, self.request.save)

    def test_employee_unique_username(self):
        """Test the username of employee must be unique."""
        # Can't create
        with transaction.atomic():
            self.assertRaises(
                IntegrityError,
                Employee.objects.create,
                account="654321",
                username="requestor_test",
                first_name="requestor2",
                last_name="test2",
                email="requestor2@redhat.com",
            )

    def test_employee_removal(self):
        """Test the employee removal will remove the corresponding requests."""
        employee_temp = Employee.objects.create(
            account="654321",
            username="requestor_test_temp",
            first_name="requestor_temp",
            last_name="test_temp",
            email="requestor_temp@redhat.com",
        )
        request_temp = CrossAccountRequest.objects.create(
            target_account="123456", employee=employee_temp, endDate=self.ref_time + timedelta(10)
        )
        request_id = request_temp.request_id

        employee_temp.delete()

        self.assertRaises(Exception, Employee.objects.get, username="requestor_test_temp")
        self.assertRaises(Exception, CrossAccountRequest.objects.get, request_id=request_id)
