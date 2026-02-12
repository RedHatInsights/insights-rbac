#
# Copyright 2026 Red Hat, Inc.
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
"""Tests for the SubjectService and SubjectType."""

import uuid

from management.exceptions import NotFoundError, RequiredFieldError
from management.group.model import Group
from management.principal.model import Principal
from management.subject import SubjectService, SubjectType, UnsupportedSubjectTypeError
from tests.identity_request import IdentityRequest


class SubjectTypeTests(IdentityRequest):
    """Tests for the SubjectType enum."""

    def test_values_returns_all_types(self):
        """Test that values() returns all valid subject types."""
        values = SubjectType.values()

        self.assertEqual(set(values), {"group", "user"})

    def test_is_valid_returns_true_for_valid_types(self):
        """Test that is_valid returns True for valid subject types."""
        test_cases = [
            ("group", True),
            ("user", True),
            (SubjectType.GROUP, True),
            (SubjectType.USER, True),
        ]

        for value, expected in test_cases:
            with self.subTest(value=value):
                self.assertEqual(SubjectType.is_valid(value), expected)

    def test_is_valid_returns_false_for_invalid_types(self):
        """Test that is_valid returns False for invalid subject types."""
        test_cases = ["invalid", "", "GROUP", "USER", "principal"]

        for value in test_cases:
            with self.subTest(value=value):
                self.assertFalse(SubjectType.is_valid(value))


class SubjectServiceTests(IdentityRequest):
    """Tests for the SubjectService."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        # Create a group
        self.group = Group.objects.create(
            name="Test Group",
            tenant=self.tenant,
        )

        # Create a principal
        self.principal = Principal.objects.create(
            username="testuser",
            tenant=self.tenant,
            type=Principal.Types.USER,
        )

        self.service = SubjectService(tenant=self.tenant)

    def tearDown(self):
        """Clean up test data."""
        Group.objects.filter(tenant=self.tenant).delete()
        Principal.objects.filter(tenant=self.tenant).delete()
        super().tearDown()


class GetGroupTests(SubjectServiceTests):
    """Tests for SubjectService.get_group()."""

    def test_get_group_returns_group(self):
        """Test that get_group returns the group for a valid UUID."""
        result = self.service.get_group(str(self.group.uuid))

        self.assertEqual(result.uuid, self.group.uuid)
        self.assertEqual(result.name, self.group.name)

    def test_get_group_annotates_principal_count(self):
        """Test that get_group annotates the group with principal count."""
        # Add a principal to the group
        self.group.principals.add(self.principal)

        result = self.service.get_group(str(self.group.uuid))

        self.assertTrue(hasattr(result, "principalCount"))
        self.assertEqual(result.principalCount, 1)

    def test_get_group_raises_not_found_for_invalid_uuid(self):
        """Test that get_group raises NotFoundError for non-existent group."""
        fake_uuid = str(uuid.uuid4())

        with self.assertRaises(NotFoundError) as context:
            self.service.get_group(fake_uuid)

        self.assertEqual(context.exception.resource_type, "group")
        self.assertEqual(context.exception.resource_id, fake_uuid)


class GetPrincipalTests(SubjectServiceTests):
    """Tests for SubjectService.get_principal()."""

    def test_get_principal_returns_principal(self):
        """Test that get_principal returns the principal for a valid UUID."""
        result = self.service.get_principal(str(self.principal.uuid))

        self.assertEqual(result.uuid, self.principal.uuid)
        self.assertEqual(result.username, self.principal.username)

    def test_get_principal_raises_not_found_for_invalid_uuid(self):
        """Test that get_principal raises NotFoundError for non-existent principal."""
        fake_uuid = str(uuid.uuid4())

        with self.assertRaises(NotFoundError) as context:
            self.service.get_principal(fake_uuid)

        self.assertEqual(context.exception.resource_type, "user")
        self.assertEqual(context.exception.resource_id, fake_uuid)

    def test_get_principal_respects_tenant_isolation(self):
        """Test that get_principal only finds principals in the same tenant."""
        # Create a principal in a different tenant
        from api.models import Tenant

        other_tenant = Tenant.objects.create(
            tenant_name="other_tenant",
            org_id="other_org",
            ready=True,
        )
        other_principal = Principal.objects.create(
            username="otheruser",
            tenant=other_tenant,
            type=Principal.Types.USER,
        )

        try:
            with self.assertRaises(NotFoundError):
                self.service.get_principal(str(other_principal.uuid))
        finally:
            other_principal.delete()
            other_tenant.delete()


class GetSubjectTests(SubjectServiceTests):
    """Tests for SubjectService.get_subject()."""

    def test_get_subject_returns_group_for_group_type(self):
        """Test that get_subject returns a Group for subject_type='group'."""
        result = self.service.get_subject("group", str(self.group.uuid))

        self.assertIsInstance(result, Group)
        self.assertEqual(result.uuid, self.group.uuid)

    def test_get_subject_returns_principal_for_user_type(self):
        """Test that get_subject returns a Principal for subject_type='user'."""
        result = self.service.get_subject("user", str(self.principal.uuid))

        self.assertIsInstance(result, Principal)
        self.assertEqual(result.uuid, self.principal.uuid)

    def test_get_subject_raises_required_field_error_for_empty_subject_id(self):
        """Test that get_subject raises RequiredFieldError for empty subject_id."""
        with self.assertRaises(RequiredFieldError) as context:
            self.service.get_subject("group", "")

        self.assertEqual(context.exception.field_name, "subject_id")

    def test_get_subject_raises_unsupported_subject_type_error(self):
        """Test that get_subject raises UnsupportedSubjectTypeError for invalid types."""
        test_cases = ["invalid", "", "principal", "GROUP"]

        for subject_type in test_cases:
            with self.subTest(subject_type=subject_type):
                with self.assertRaises(UnsupportedSubjectTypeError) as context:
                    self.service.get_subject(subject_type, str(self.group.uuid))

                self.assertEqual(context.exception.subject_type, subject_type)
                self.assertIn("group", context.exception.supported)
                self.assertIn("user", context.exception.supported)

    def test_get_subject_raises_not_found_for_invalid_group(self):
        """Test that get_subject raises NotFoundError for non-existent group."""
        fake_uuid = str(uuid.uuid4())

        with self.assertRaises(NotFoundError) as context:
            self.service.get_subject("group", fake_uuid)

        self.assertEqual(context.exception.resource_type, "group")
        self.assertEqual(context.exception.resource_id, fake_uuid)

    def test_get_subject_raises_not_found_for_invalid_principal(self):
        """Test that get_subject raises NotFoundError for non-existent principal."""
        fake_uuid = str(uuid.uuid4())

        with self.assertRaises(NotFoundError) as context:
            self.service.get_subject("user", fake_uuid)

        self.assertEqual(context.exception.resource_type, "user")
        self.assertEqual(context.exception.resource_id, fake_uuid)
