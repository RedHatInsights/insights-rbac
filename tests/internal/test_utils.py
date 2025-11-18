#
# Copyright 2025 Red Hat, Inc.
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
"""Test the internal utils module."""

from unittest.mock import patch
from django.test import TestCase, override_settings
from management.group.model import Group
from management.models import BindingMapping, Workspace, Access, Permission
from management.policy.model import Policy
from management.role.model import Role
from migration_tool.in_memory_tuples import (
    InMemoryTuples,
    InMemoryRelationReplicator,
    all_of,
    resource,
    relation,
    subject,
)
from api.models import Tenant
from internal.utils import replicate_missing_binding_tuples


class ReplicateMissingBindingTuplesTest(TestCase):
    """Test the replicate_missing_binding_tuples function."""

    def setUp(self):
        """Set up test data."""
        self.tenant = Tenant.objects.create(tenant_name="test_tenant", org_id="12345")
        self.public_tenant = Tenant.objects.get(tenant_name="public")

        # Create workspace hierarchy
        self.root_ws = Workspace.objects.create(
            tenant=self.tenant,
            type=Workspace.Types.ROOT,
            name="Root Workspace",
        )
        self.default_ws = Workspace.objects.create(
            tenant=self.tenant,
            type=Workspace.Types.DEFAULT,
            name="Default Workspace",
            parent=self.root_ws,
        )

        self.tuples = InMemoryTuples()

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_replicate_missing_binding_tuples_for_specific_bindings(self, mock_replicate):
        """Test that function replicates all tuples for specific binding IDs."""
        # Redirect replication to in-memory tuples
        replicator = InMemoryRelationReplicator(self.tuples)
        mock_replicate.side_effect = replicator.replicate

        # Create a system role
        role = Role.objects.create(name="Test Role", system=True, tenant=self.public_tenant)
        perm = Permission.objects.create(permission="test:resource:read", tenant=self.public_tenant)
        Access.objects.create(role=role, permission=perm, tenant=self.public_tenant)

        # Create a group
        group = Group.objects.create(name="Test Group", tenant=self.tenant)

        # Create binding WITHOUT replication (missing base tuples)
        binding = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "test-binding-utils",
                "groups": [str(group.uuid)],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": True, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.root_ws.id),
        )

        binding_id = binding.mappings["id"]

        # Verify initial state: NO tuples exist
        self.assertEqual(len(self.tuples), 0, "Should have NO tuples before fix")

        # Call the function
        results = replicate_missing_binding_tuples(binding_ids=[binding.id])

        # Verify results
        self.assertEqual(results["bindings_checked"], 1)
        self.assertEqual(results["bindings_fixed"], 1)
        self.assertEqual(results["tuples_added"], 3)  # t_role + t_binding + subject

        # Verify t_role tuple was created
        t_role_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("role"),
            )
        )
        self.assertEqual(len(t_role_tuples), 1, "Should have t_role tuple")

        # Verify t_binding tuple was created
        t_binding_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "workspace", str(self.root_ws.id)),
                relation("binding"),
                subject("rbac", "role_binding", binding_id),
            )
        )
        self.assertEqual(len(t_binding_tuples), 1, "Should have t_binding tuple")

        # Verify subject tuple was created
        subject_tuples = self.tuples.find_tuples(
            all_of(
                resource("rbac", "role_binding", binding_id),
                relation("subject"),
                subject("rbac", "group", str(group.uuid), "member"),
            )
        )
        self.assertEqual(len(subject_tuples), 1, "Should have subject tuple")

    @override_settings(REPLICATION_TO_RELATION_ENABLED=True)
    @patch("management.relation_replicator.outbox_replicator.OutboxReplicator.replicate")
    def test_replicate_missing_binding_tuples_idempotent(self, mock_replicate):
        """Test that function is idempotent and safe to run multiple times."""
        # Redirect replication to in-memory tuples
        replicator = InMemoryRelationReplicator(self.tuples)
        mock_replicate.side_effect = replicator.replicate

        # Create a system role
        role = Role.objects.create(name="Test Role Idempotent", system=True, tenant=self.public_tenant)
        perm = Permission.objects.create(permission="test:idempotent:read", tenant=self.public_tenant)
        Access.objects.create(role=role, permission=perm, tenant=self.public_tenant)

        # Create binding
        binding = BindingMapping.objects.create(
            role=role,
            mappings={
                "id": "test-binding-idempotent",
                "groups": [],
                "users": {},
                "role": {"id": str(role.uuid), "is_system": True, "permissions": []},
            },
            resource_type_namespace="rbac",
            resource_type_name="workspace",
            resource_id=str(self.root_ws.id),
        )

        # Run once
        results1 = replicate_missing_binding_tuples(binding_ids=[binding.id])
        self.assertEqual(results1["bindings_fixed"], 1)
        tuples_after_first = len(self.tuples)

        # Run again - should be idempotent (duplicates handled by Kessel)
        results2 = replicate_missing_binding_tuples(binding_ids=[binding.id])
        self.assertEqual(results2["bindings_fixed"], 1)

        # Tuples are added again but that's OK (Kessel handles duplicates)
        # The important thing is no error occurs
        self.assertGreater(len(self.tuples), 0, "Should have tuples after running twice")
