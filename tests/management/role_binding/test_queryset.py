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
"""Tests for RoleBindingQuerySet."""

import uuid

from api.models import Tenant
from management.group.model import Group
from management.role.v2_model import RoleV2
from management.role_binding.model import RoleBinding, RoleBindingGroup
from tests.identity_request import IdentityRequest


class RoleBindingQuerySetTest(IdentityRequest):
    """Tests for RoleBinding.objects.for_tenant()."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

        self.role_a = RoleV2.objects.create(name="role_a", tenant=self.tenant)
        self.role_b = RoleV2.objects.create(name="role_b", tenant=self.tenant)

        self.group = Group.objects.create(name="test_group", tenant=self.tenant)

        self.binding_a = RoleBinding.objects.create(
            role=self.role_a,
            resource_type="workspace",
            resource_id="res-1",
            tenant=self.tenant,
        )
        self.binding_b = RoleBinding.objects.create(
            role=self.role_b,
            resource_type="workspace",
            resource_id="res-2",
            tenant=self.tenant,
        )
        RoleBindingGroup.objects.create(group=self.group, binding=self.binding_a)
        RoleBindingGroup.objects.create(group=self.group, binding=self.binding_b)

    def tearDown(self):
        """Tear down test data."""
        RoleBindingGroup.objects.all().delete()
        RoleBinding.objects.filter(tenant=self.tenant).delete()
        Group.objects.filter(tenant=self.tenant).delete()
        RoleV2.objects.filter(tenant=self.tenant).delete()
        super().tearDown()

    # --- Tenant filtering ---

    def test_returns_bindings_for_tenant(self):
        """Test that for_tenant returns all bindings belonging to the tenant."""
        qs = RoleBinding.objects.for_tenant(tenant=self.tenant)
        self.assertEqual(set(qs), {self.binding_a, self.binding_b})

    def test_excludes_other_tenant_bindings(self):
        """Test that for_tenant excludes bindings from other tenants."""
        other_tenant = Tenant.objects.create(tenant_name="other", org_id="other_org")
        other_role = RoleV2.objects.create(name="other_role", tenant=other_tenant)
        other_binding = RoleBinding.objects.create(
            role=other_role,
            resource_type="workspace",
            resource_id="other-res",
            tenant=other_tenant,
        )

        try:
            qs = RoleBinding.objects.for_tenant(tenant=self.tenant)
            self.assertNotIn(other_binding, qs)
            self.assertEqual(qs.count(), 2)
        finally:
            other_binding.delete()
            other_role.delete()
            other_tenant.delete()

    def test_returns_empty_for_tenant_with_no_bindings(self):
        """Test that for_tenant returns empty queryset for a tenant with no bindings."""
        empty_tenant = Tenant.objects.create(tenant_name="empty", org_id="empty_org")
        try:
            qs = RoleBinding.objects.for_tenant(tenant=empty_tenant)
            self.assertEqual(qs.count(), 0)
        finally:
            empty_tenant.delete()

    # --- role_id filtering ---

    def test_role_id_filtering(self):
        """Test that role_id filters correctly for various inputs."""
        cases = [
            ("match_role_a", self.role_a.uuid, 1, {self.binding_a}),
            ("match_role_b", self.role_b.uuid, 1, {self.binding_b}),
            ("no_match", uuid.uuid4(), 0, set()),
            ("none_returns_all", None, 2, {self.binding_a, self.binding_b}),
        ]
        for label, role_id, expected_count, expected_set in cases:
            with self.subTest(label=label):
                qs = RoleBinding.objects.for_tenant(tenant=self.tenant, role_id=role_id)
                self.assertEqual(qs.count(), expected_count)
                self.assertEqual(set(qs), expected_set)

    # --- Eager loading ---

    def test_eager_loading(self):
        """Test that role and group relations are eagerly loaded (no extra queries)."""
        qs = RoleBinding.objects.for_tenant(tenant=self.tenant)
        binding = list(qs)[0]  # evaluate queryset to trigger prefetch

        cases = [
            ("select_related_role", lambda b: b.role.name),
            (
                "prefetch_group_entries",
                lambda b: [e.group.name for e in b.group_entries.all()],
            ),
        ]
        for label, access_fn in cases:
            with self.subTest(label=label):
                with self.assertNumQueries(0):
                    access_fn(binding)

    # --- Annotation ---

    def test_annotates_role_created(self):
        """Test that role_created annotation is present and correct."""
        qs = RoleBinding.objects.for_tenant(tenant=self.tenant)
        for binding, role in [
            (self.binding_a, self.role_a),
            (self.binding_b, self.role_b),
        ]:
            with self.subTest(role=role.name):
                result = qs.get(pk=binding.pk)
                self.assertEqual(result.role_created, role.created)
