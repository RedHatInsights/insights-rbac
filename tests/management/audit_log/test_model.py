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
"""Test the Audit Logs Model."""
from django.test import TestCase
from unittest.mock import Mock

from management.models import AuditLog
from tests.identity_request import IdentityRequest


class AuditLogModelTests(IdentityRequest):
    """ "Test the Audit Log Model."""

    def setUp(self):
        """Set up the audit log model tests."""
        super().setUp()

        self.auditLogs = AuditLog.objects.create(
            requester="testing123",
            description="Created a role asdf1234",
            resource=AuditLog.ROLE,
            action=AuditLog.CREATE,
        )
        self.auditLogs.save()

    def tearDown(self):
        """Tear down group model tests."""
        AuditLog.objects.all().delete()

    def test_count_audit_log(self):
        """Test whether log was created through model."""
        self.assert_(self.auditLogs, 1)
