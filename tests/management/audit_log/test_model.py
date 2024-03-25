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

        self.audit_log = AuditLog.objects.create(
            principal_id="1",
            principal_username="test_user",
            resource_type=AuditLog.ROLE,
            resource_id="1",
            description="Created a role asdf1234",
            action=AuditLog.CREATE,
            tenant_id="2",
        )

    def tearDown(self):
        """Tear down group model tests."""
        AuditLog.objects.all().delete()

    def test_audit_log_creation(self):
        """Test whether log was created through model."""
        self.assertEqual(self.audit_log.principal_id, "1")
        self.assertEqual(self.audit_log.principal_username, "test_user")
        self.assertEqual(self.audit_log.resource_type, "role")
        self.assertEqual(self.audit_log.resource_id, "1")
        self.assertEqual(self.audit_log.description, "Created a role asdf1234")
        self.assertEqual(self.audit_log.action, "create")
        self.assertEqual(self.audit_log.tenant_id, "2")
