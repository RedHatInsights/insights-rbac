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
"""Test the cross access util module."""

from api.cross_access import util
from api.models import CrossAccountRequest, Tenant
from api.cross_access.util import get_cross_principal_name
from django.urls import reverse
from django.utils import timezone
from management.models import Role, Principal
from management.notifications.notification_handlers import EVENT_TYPE_RH_TAM_REQUEST_CREATED
from rest_framework import status
from rest_framework.test import APIClient

from datetime import timedelta
from unittest.mock import patch
from management.workspace.model import Workspace
from migration_tool.in_memory_tuples import (
    all_of,
    one_of,
    relation,
    resource,
    resource_id,
    subject,
)
from tests.api.cross_access.fixtures import CrossAccountRequestTest


URL_LIST = reverse("v1_api:cross-list")


class CrossAccountRequestUtilTests(CrossAccountRequestTest):
    """Test the cross access util module."""

    def test_expired_cross_account_requests_remove_bindings(self):
        """Test that there are no bindings after a CAR expires."""

        # Start by approving a CAR with roles

        # Modify pending request such that it includes roles
        farmer = self.fixture.new_system_role("Farmer", ["farm:soil:rake"])
        fisher = self.fixture.new_system_role("Fisher", ["stream:fish:catch"])

        # Assume tenant bootstrapped for v2
        self.fixture.bootstrap_tenant(self.tenant)

        # Add roles to request for user 2222222 and approve it.
        self.add_roles_to_request(self.request_4, [farmer, fisher])
        self.approve_request(self.request_4)

        after_expiration = self.request_4.end_date + timedelta(seconds=1)
        with patch("django.utils.timezone.now", return_value=after_expiration):
            util.check_cross_request_expiry()

        # Check that the bindings for the tenant's resources are gone
        # Check that the roles are now bound to the user in the target account (default workspace)
        default_workspace_id = Workspace.objects.get(tenant__org_id=self.org_id, type=Workspace.Types.DEFAULT).id
        default_bindings = self.relations.find_tuples(
            # Tuples for bindings to the deafult workspace
            all_of(resource("rbac", "workspace", default_workspace_id), relation("binding"))
        )

        cross_account_bindings, _ = self.relations.find_group_with_tuples(
            # Tuples which are...
            # grouped by resource
            group_by=lambda t: (t.resource_type_namespace, t.resource_type_name, t.resource_id),
            # where the resource is one of the default role bindings...
            group_filter=lambda group: group[0] == "rbac"
            and group[1] == "role_binding"
            and group[2] in {str(binding.resource_id) for binding in default_bindings},
            # and where one of the tuples from that binding has...
            predicates=all_of(
                # a subject relation
                relation("subject"),
                # to the user in the CAR
                subject("rbac", "principal", "localhost/2222222"),
            ),
        )

        self.assertEqual(
            len(cross_account_bindings), 0, f"Expected no cross account bindings, found {cross_account_bindings}"
        )
