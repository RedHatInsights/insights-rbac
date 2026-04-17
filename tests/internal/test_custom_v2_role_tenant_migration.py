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

"""Tests for replicating custom V2 role owner tuples."""

from unittest.mock import MagicMock

from django.test import TestCase, override_settings
from internal.custom_v2_role_tenant_migration import (
    TenantResourceIdMissingError,
    replicate_custom_v2_role_owner_relationships,
)
from management.models import Permission
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.role.relations import role_owner_relationship
from management.role.v2_model import CustomRoleV2
from tests.v2_util import bootstrap_tenant_for_v2_test

from api.models import Tenant


@override_settings(ATOMIC_RETRY_DISABLED=True)
class ReplicateCustomV2RoleOwnerTests(TestCase):
    """Tests for replicate_custom_v2_role_owner_relationships."""

    def setUp(self):
        """Set up tenants."""
        self.public_tenant = Tenant.objects.get(tenant_name=Tenant.PUBLIC_TENANT_NAME)
        self.org_tenant = Tenant.objects.create(
            tenant_name="owner_tuple_tenant",
            account_id="acc-ot",
            org_id="org-owner-001",
            ready=True,
        )
        bootstrap_tenant_for_v2_test(self.org_tenant)

        self.perm = Permission.objects.create(
            tenant=self.public_tenant,
            application="inventory",
            resource_type="hosts",
            verb="read",
            permission="inventory:hosts:read",
        )

    def test_replicates_owner_tuple_using_tenant_resource_id(self):
        """Each custom role with an org tenant gets one owner tuple replicated."""
        role = CustomRoleV2.objects.create(name="custom_a", tenant=self.org_tenant)
        role.permissions.add(self.perm)

        replicator = MagicMock()
        result = replicate_custom_v2_role_owner_relationships(replicator=replicator)

        self.assertEqual(result["replicated_count"], 1)
        replicator.replicate.assert_called_once()
        event = replicator.replicate.call_args[0][0]
        self.assertEqual(event.event_type, ReplicationEventType.UPDATE_CUSTOM_ROLE)
        self.assertEqual(len(event.add), 1)
        self.assertEqual(event.remove, [])
        expected = role_owner_relationship(role.uuid, self.org_tenant.tenant_resource_id())
        self.assertEqual(event.add[0], expected)

    def test_raises_when_tenant_has_no_resource_id(self):
        """Non-public tenant without org_id has no tenant_resource_id; migration fails."""
        no_org = Tenant.objects.create(
            tenant_name="no_org_id_tenant",
            account_id="acc-none",
            org_id=None,
            ready=True,
        )
        CustomRoleV2.objects.create(name="no_res_id", tenant=no_org).permissions.add(self.perm)

        replicator = MagicMock()
        with self.assertRaises(TenantResourceIdMissingError):
            replicate_custom_v2_role_owner_relationships(replicator=replicator)

        replicator.replicate.assert_not_called()

    def test_raises_for_custom_role_on_public_tenant(self):
        """Public tenant has no tenant_resource_id; migration fails."""
        CustomRoleV2.objects.create(name="on_public", tenant=self.public_tenant).permissions.add(self.perm)

        replicator = MagicMock()
        with self.assertRaises(TenantResourceIdMissingError):
            replicate_custom_v2_role_owner_relationships(replicator=replicator)

        replicator.replicate.assert_not_called()

    def test_processes_all_non_public_org_tenants(self):
        """All custom roles on distinct non-public tenants are replicated."""
        other = Tenant.objects.create(
            tenant_name="owner_tuple_other",
            account_id="acc-ot2",
            org_id="org-owner-002",
            ready=True,
        )
        bootstrap_tenant_for_v2_test(other)

        CustomRoleV2.objects.create(name="r1", tenant=self.org_tenant).permissions.add(self.perm)
        CustomRoleV2.objects.create(name="r2", tenant=other).permissions.add(self.perm)

        replicator = MagicMock()
        result = replicate_custom_v2_role_owner_relationships(replicator=replicator)

        self.assertEqual(result["replicated_count"], 2)
        self.assertEqual(replicator.replicate.call_count, 2)
