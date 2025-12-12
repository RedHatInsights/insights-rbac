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
"""Test the remove_duplicate_principals internal API."""
import json
from unittest.mock import patch, MagicMock

from django.test import override_settings
from rest_framework import status
from rest_framework.test import APIClient

from api.models import Tenant
from management.models import Group, Principal
from tests.identity_request import IdentityRequest
from tests.management.role.test_dual_write import RbacFixture
from tests.internal.test_views import valid_destructive_time


@override_settings(
    LOGGING={
        "version": 1,
        "disable_existing_loggers": False,
        "loggers": {
            "management.relation_replicator.outbox_replicator": {
                "level": "INFO",
            },
        },
    },
)
class RemoveDuplicatePrincipalsTests(IdentityRequest):
    """Test the remove_duplicate_principals endpoint."""

    def setUp(self):
        """Set up the tests."""
        super().setUp()
        self.client = APIClient()
        self.customer = self.customer_data
        self.internal_request_context = self._create_request_context(self.customer, self.user_data, is_internal=True)
        self.request = self.internal_request_context["request"]
        self.url = "/_private/api/utils/remove_duplicate_principals/"

        # Bootstrap tenant for replication tests
        self.fixture = RbacFixture()
        self.fixture.bootstrap_tenant(self.tenant)

    def tearDown(self):
        """Tear down the tests."""
        Group.objects.all().delete()
        Principal.objects.all().delete()

    def test_missing_user_ids_parameter(self):
        """Test that missing user_ids parameter returns 400."""
        response = self.client.get(self.url, **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Missing required parameter", response.content.decode())

    def test_empty_user_ids_parameter(self):
        """Test that empty user_ids parameter returns 400."""
        response = self.client.get(f"{self.url}?user_ids=", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Missing required parameter", response.content.decode())

    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_get_no_duplicates(self, mock_proxy):
        """Test GET when no duplicates exist."""
        # Create single principal with user_id
        principal = Principal.objects.create(
            username="testuser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Mock BOP response
        mock_proxy.return_value = {
            "status_code": 200,
            "data": [{"username": "testuser", "user_id": 12345, "org_id": self.tenant.org_id}],
        }

        response = self.client.get(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.content)
        self.assertEqual(data["total_duplicate_sets"], 0)
        self.assertEqual(len(data["duplicates"]), 0)

    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_get_with_duplicates(self, mock_proxy):
        """Test GET when duplicates exist."""
        # Create duplicate principals with same user_id
        principal1 = Principal.objects.create(
            username="correctuser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )
        principal2 = Principal.objects.create(
            username="wronguser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Create group and add principals
        group = Group.objects.create(name="TestGroup", tenant=self.tenant)
        group.principals.add(principal1, principal2)

        # Mock BOP response with org_id matching the tenant
        mock_proxy.return_value = {
            "status_code": 200,
            "data": [{"username": "correctuser", "user_id": 12345, "org_id": self.tenant.org_id}],
        }

        response = self.client.get(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.content)
        self.assertEqual(data["total_duplicate_sets"], 1)
        self.assertEqual(len(data["duplicates"]), 1)

        duplicate_set = data["duplicates"][0]
        self.assertEqual(duplicate_set["user_id"], "12345")
        self.assertEqual(duplicate_set["duplicate_count"], 2)
        self.assertEqual(duplicate_set["bop_username"], "correctuser")
        self.assertEqual(duplicate_set["bop_org_id"], self.tenant.org_id)
        self.assertTrue(duplicate_set["bop_verified"])

        # Check that correct principal is marked as will_be_kept
        principals_data = duplicate_set["principals"]
        correct_principal = next(p for p in principals_data if p["username"] == "correctuser")
        wrong_principal = next(p for p in principals_data if p["username"] == "wronguser")

        self.assertTrue(correct_principal["is_correct_username"])
        self.assertTrue(correct_principal["is_correct_org"])
        self.assertTrue(correct_principal["will_be_kept"])
        self.assertFalse(wrong_principal["is_correct_username"])
        self.assertFalse(wrong_principal["will_be_kept"])

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_post_bop_query_failure(self, mock_proxy):
        """Test POST when BOP query fails returns 500."""
        # Mock BOP failure
        mock_proxy.return_value = {
            "status_code": 500,
            "errors": [{"detail": "BOP service unavailable"}],
        }

        response = self.client.post(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        data = json.loads(response.content)
        self.assertIn("BOP query failed", data["error"])

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_post_bop_query_exception(self, mock_proxy):
        """Test POST when BOP query raises exception returns 500."""
        # Mock BOP exception
        mock_proxy.side_effect = Exception("Connection timeout")

        response = self.client.post(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        data = json.loads(response.content)
        self.assertIn("BOP query failed", data["error"])
        self.assertIn("Connection timeout", data["details"])

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator._save_replication_event")
    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_post_user_id_not_in_bop_deletes_all(self, mock_proxy, mock_replicator):
        """Test POST when user_id not found in BOP deletes all principals."""
        # Create principals
        principal1 = Principal.objects.create(
            username="user1",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )
        principal2 = Principal.objects.create(
            username="user2",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Mock BOP response - user_id not found
        mock_proxy.return_value = {
            "status_code": 200,
            "data": [],  # No user found
        }

        response = self.client.post(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.content)

        self.assertEqual(data["total_removed"], 2)
        self.assertEqual(data["total_kept"], 0)
        self.assertIn("12345", data["user_ids_not_found_in_bop"])

        # Verify principals were deleted
        self.assertEqual(Principal.objects.filter(user_id="12345").count(), 0)

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator._save_replication_event")
    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_post_username_mismatch_deletes_incorrect(self, mock_proxy, mock_replicator):
        """Test POST when username doesn't match BOP deletes incorrect principal."""
        # Create principals
        correct_principal = Principal.objects.create(
            username="correctuser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )
        wrong_principal = Principal.objects.create(
            username="wronguser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Mock BOP response
        mock_proxy.return_value = {
            "status_code": 200,
            "data": [{"username": "correctuser", "user_id": 12345, "org_id": self.tenant.org_id}],
        }

        response = self.client.post(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.content)

        self.assertEqual(data["total_removed"], 1)
        self.assertEqual(data["total_kept"], 1)

        # Verify correct principal kept
        self.assertTrue(Principal.objects.filter(uuid=correct_principal.uuid).exists())
        # Verify wrong principal deleted
        self.assertFalse(Principal.objects.filter(uuid=wrong_principal.uuid).exists())

        # Check kept principal data
        kept = data["kept_principals"][0]
        self.assertEqual(kept["username"], "correctuser")
        self.assertTrue(kept["verified_with_bop"])
        self.assertTrue(kept["username_matches_bop"])
        self.assertTrue(kept["org_id_matches_bop"])

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator._save_replication_event")
    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_post_no_matching_username_deletes_all(self, mock_proxy, mock_replicator):
        """Test POST when no principal matches BOP username deletes all."""
        # Create principals with wrong usernames
        principal1 = Principal.objects.create(
            username="wrong1",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )
        principal2 = Principal.objects.create(
            username="wrong2",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Mock BOP response with different username
        mock_proxy.return_value = {
            "status_code": 200,
            "data": [{"username": "expecteduser", "user_id": 12345}],
        }

        response = self.client.post(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.content)

        self.assertEqual(data["total_removed"], 2)
        self.assertEqual(data["total_kept"], 0)

        # Verify all principals deleted
        self.assertEqual(Principal.objects.filter(user_id="12345").count(), 0)

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator._save_replication_event")
    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_post_migrates_group_memberships(self, mock_proxy, mock_replicator):
        """Test POST migrates group memberships from incorrect to correct principal."""
        # Create principals
        correct_principal = Principal.objects.create(
            username="correctuser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )
        wrong_principal = Principal.objects.create(
            username="wronguser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Create groups
        group1 = Group.objects.create(name="Group1", tenant=self.tenant)
        group2 = Group.objects.create(name="Group2", tenant=self.tenant)
        group3 = Group.objects.create(name="Group3", tenant=self.tenant)

        # Add correct principal to group1 and group2
        group1.principals.add(correct_principal)
        group2.principals.add(correct_principal)

        # Add wrong principal to group2 and group3
        group2.principals.add(wrong_principal)
        group3.principals.add(wrong_principal)

        # Mock BOP response
        mock_proxy.return_value = {
            "status_code": 200,
            "data": [{"username": "correctuser", "user_id": 12345, "org_id": self.tenant.org_id}],
        }

        response = self.client.post(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.content)

        self.assertEqual(data["total_removed"], 1)
        self.assertEqual(data["total_kept"], 1)
        self.assertEqual(data["affected_groups_count"], 2)  # group2 and group3

        # Verify group memberships
        # Group1: should still have correct_principal
        self.assertTrue(group1.principals.filter(uuid=correct_principal.uuid).exists())

        # Group2: should have correct_principal (was in both)
        self.assertTrue(group2.principals.filter(uuid=correct_principal.uuid).exists())
        self.assertFalse(group2.principals.filter(uuid=wrong_principal.uuid).exists())

        # Group3: should now have correct_principal (migrated from wrong)
        self.assertTrue(group3.principals.filter(uuid=correct_principal.uuid).exists())
        self.assertFalse(group3.principals.filter(uuid=wrong_principal.uuid).exists())

        # Verify replication was called
        self.assertTrue(mock_replicator.called)
        # Should be called for: removal from group2, removal from group3, addition to group3
        # (group2 already had correct_principal so no addition needed)
        self.assertGreaterEqual(mock_replicator.call_count, 2)

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator._save_replication_event")
    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_post_only_processes_user_type(self, mock_proxy, mock_replicator):
        """Test POST only processes USER type principals, not service accounts."""
        # Create user principal with duplicate
        user1 = Principal.objects.create(
            username="user1",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )
        user2 = Principal.objects.create(
            username="user2",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Create service account with same user_id (should be ignored)
        sa = Principal.objects.create(
            username="service-account-abc",
            user_id="12345",
            type=Principal.Types.SERVICE_ACCOUNT,
            service_account_id="abc",
            tenant=self.tenant,
        )

        # Mock BOP response
        mock_proxy.return_value = {
            "status_code": 200,
            "data": [{"username": "user1", "user_id": 12345, "org_id": self.tenant.org_id}],
        }

        response = self.client.post(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.content)

        # Should only process USER type principals
        self.assertEqual(data["total_removed"], 1)  # user2 removed
        self.assertEqual(data["total_kept"], 1)  # user1 kept

        # Verify service account was not touched
        self.assertTrue(Principal.objects.filter(uuid=sa.uuid).exists())

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator._save_replication_event")
    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_post_multiple_user_ids(self, mock_proxy, mock_replicator):
        """Test POST with multiple user_ids."""
        # Create principals for user_id 12345
        user1_correct = Principal.objects.create(
            username="user1",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )
        user1_wrong = Principal.objects.create(
            username="user1wrong",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Create principals for user_id 67890
        user2_correct = Principal.objects.create(
            username="user2",
            user_id="67890",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )
        user2_wrong = Principal.objects.create(
            username="user2wrong",
            user_id="67890",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Mock BOP response for both users
        mock_proxy.return_value = {
            "status_code": 200,
            "data": [
                {"username": "user1", "user_id": 12345, "org_id": self.tenant.org_id},
                {"username": "user2", "user_id": 67890, "org_id": self.tenant.org_id},
            ],
        }

        response = self.client.post(f"{self.url}?user_ids=12345,67890", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.content)

        self.assertEqual(data["total_removed"], 2)  # Both wrong principals
        self.assertEqual(data["total_kept"], 2)  # Both correct principals

        # Verify correct principals kept
        self.assertTrue(Principal.objects.filter(uuid=user1_correct.uuid).exists())
        self.assertTrue(Principal.objects.filter(uuid=user2_correct.uuid).exists())

        # Verify wrong principals deleted
        self.assertFalse(Principal.objects.filter(uuid=user1_wrong.uuid).exists())
        self.assertFalse(Principal.objects.filter(uuid=user2_wrong.uuid).exists())

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator._save_replication_event")
    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_post_verifies_replication_event_details(self, mock_proxy, mock_replicator):
        """Test POST verifies that replication events are created with correct details."""
        # Create principals
        correct_principal = Principal.objects.create(
            username="correctuser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )
        wrong_principal = Principal.objects.create(
            username="wronguser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Create group and add wrong principal
        group = Group.objects.create(name="TestGroup", tenant=self.tenant)
        group.principals.add(wrong_principal)

        # Mock BOP response
        mock_proxy.return_value = {
            "status_code": 200,
            "data": [{"username": "correctuser", "user_id": 12345, "org_id": self.tenant.org_id}],
        }

        response = self.client.post(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify replication was called
        self.assertTrue(mock_replicator.called, "Replication should have been called")
        # Should be called at least twice: once for removal, once for addition
        self.assertGreaterEqual(mock_replicator.call_count, 2, "Should have multiple replication calls")

    @override_settings(INTERNAL_DESTRUCTIVE_API_OK_UNTIL=valid_destructive_time())
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator._save_replication_event")
    @patch("internal.utils.PROXY.request_filtered_principals")
    def test_post_handles_multiple_tenants_separately(self, mock_proxy, mock_replicator):
        """Test POST handles same user_id in different tenants separately."""
        # Create another tenant
        other_tenant = Tenant.objects.create(
            tenant_name="other_tenant",
            account_id="67890",
            org_id="67890",
        )

        # Create principals in first tenant
        principal_t1_correct = Principal.objects.create(
            username="correctuser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )
        principal_t1_wrong = Principal.objects.create(
            username="wronguser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=self.tenant,
        )

        # Create principals in second tenant with same user_id
        principal_t2_correct = Principal.objects.create(
            username="correctuser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=other_tenant,
        )
        principal_t2_wrong = Principal.objects.create(
            username="wronguser",
            user_id="12345",
            type=Principal.Types.USER,
            tenant=other_tenant,
        )

        # Mock BOP response - returns org_id matching self.tenant
        # This means only principals in self.tenant will match
        mock_proxy.return_value = {
            "status_code": 200,
            "data": [{"username": "correctuser", "user_id": 12345, "org_id": self.tenant.org_id}],
        }

        response = self.client.post(f"{self.url}?user_ids=12345", **self.request.META)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.content)

        # Should remove wrong principal from self.tenant and all principals from other_tenant
        # (since other_tenant org_id doesn't match BOP response)
        self.assertEqual(data["total_removed"], 3)  # principal_t1_wrong + both principal_t2_*
        self.assertEqual(data["total_kept"], 1)  # Only principal_t1_correct matches

        # Verify correct principal in self.tenant kept
        self.assertTrue(Principal.objects.filter(uuid=principal_t1_correct.uuid).exists())
        # Verify wrong principal in self.tenant deleted
        self.assertFalse(Principal.objects.filter(uuid=principal_t1_wrong.uuid).exists())
        # Verify all principals in other_tenant deleted (org_id doesn't match BOP)
        self.assertFalse(Principal.objects.filter(uuid=principal_t2_correct.uuid).exists())
        self.assertFalse(Principal.objects.filter(uuid=principal_t2_wrong.uuid).exists())
