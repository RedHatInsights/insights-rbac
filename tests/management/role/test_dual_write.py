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
"""Test dual write logic."""

from django.test import TestCase, override_settings
from management.group.model import Group
from management.permission.model import Permission
from management.policy.model import Policy
from management.principal.model import Principal
from management.role.model import Access, ResourceDefinition, Role
from management.role.relation_api_dual_write_handler import RelationApiDualWriteHandler, ReplicationEventType
from migration_tool.in_memory_tuples import (
    InMemoryRelationReplicator,
    InMemoryTuples,
    all_of,
    relation,
    resource_type,
)


from api.models import Tenant


@override_settings(REPLICATION_TO_RELATION_ENABLED=True)
class DualWriteTestCase(TestCase):
    """Base TestCase for testing dual write logic."""

    _tuples = InMemoryTuples()

    def setUp(self):
        """Set up the dual write tests."""
        super().setUp()
        self.fixture = RbacFixture()
        self.tenant = self.fixture.new_tenant(name="tenant", org_id="1234567")

    def dual_write_handler(self, role: Role, event_type: ReplicationEventType) -> RelationApiDualWriteHandler:
        """Create a RelationApiDualWriteHandler for the given role and event type."""
        return RelationApiDualWriteHandler(role, event_type, replicator=InMemoryRelationReplicator(self._tuples))

    def given_v1_system_role(self, id: str, permissions: list[str]) -> Role:
        """Create a new system role with the given ID and permissions."""
        return self.fixture.new_system_role(name=id, permissions=permissions)

    def given_v1_role(self, id: str, default: list[str], **kwargs: list[str]) -> Role:
        """Create a new custom role with the given ID and workspace permissions."""
        role = self.fixture.new_custom_role(
            name=id,
            tenant=self.tenant,
            resource_access=[
                (default, {}),
                *[
                    (permissions, {"key": "group.id", "operation": "equal", "value": workspace})
                    for workspace, permissions in kwargs.items()
                ],
            ],
        )
        dual_write = self.dual_write_handler(role, ReplicationEventType.CREATE_CUSTOM_ROLE)
        dual_write.replicate_new_or_updated_role(role)
        return role

    def given_group(self, name: str, users: list[str]) -> Group:
        """Create a new group with the given name and users."""
        # TODO: replicate group membership
        return self.fixture.new_group(name=name, users=users, tenant=self.tenant)

    def given_policy(self, group: Group, roles: list[Role]) -> Policy:
        """Assign the [roles] to the [group]."""
        # TODO: replicate role assignment
        return self.fixture.add_role_to_group(roles[0], group, self.tenant)

    def expect_1_v2_role_like(self, permissions: list[str]) -> str:
        """Assert there is a role matching the given permissions and return its ID."""
        perm_tuples = self._tuples.find_like(
            [
                all_of(resource_type("rbac", "role"), relation(permission.replace(":", "_")))
                for permission in permissions
            ]
        )
        self.assertNotEqual(
            len(perm_tuples), 0, f"No matching role found for permissions: {permissions} in tuples: \n{self._tuples}"
        )
        return perm_tuples[0].resource_id


class DualWriteSystemRolesTestCase(TestCase):
    """Test dual write logic when there is no prior state for access binding."""

    def setUp(self):
        """Set up the dual write tests."""
        super().setUp()

        self.fixture = RbacFixture()

        # Set up system role
        self.system_role = self.fixture.new_system_role(
            name="system_role", permissions=["app1:hosts:read", "inventory:hosts:write"]
        )

        # Set up group
        self.tenant = self.fixture.new_tenant(name="tenant", org_id="1234567")
        self.group_a2 = self.fixture.new_group(name="group_a2", users=["principal1", "principal2"], tenant=self.tenant)

    def test_system_role_grants_access_to_default_workspace(self):
        """Test the dual write."""
        handler = RelationApiDualWriteHandler(self.system_role, ReplicationEventType.ASSIGN_ROLE)
        handler.load_relations_from_current_state_of_role()

        self.fixture.add_role_to_group(self.system_role, self.group_a2, self.tenant)
        new = Role.objects.get(uuid=self.system_role.uuid)

        handler.replicate_new_or_updated_role(new)


class DualWriteCustomRolesTestCase(DualWriteTestCase):
    """Test dual write logic when we are working with custom roles."""

    def setUp(self):
        """Set up the dual write tests."""
        super().setUp()

    def test_dual_write(self):
        """Test the dual write."""

        role = self.given_v1_role(
            "1",
            default=["app1:hosts:read", "inventory:hosts:write"],
            ws_2=["app1:hosts:read", "inventory:hosts:write"],
        )

        group = self.given_group("group_a2", ["principal1", "principal2"])
        self.given_policy(group, roles=[role])

        self.expect_1_v2_role_like(["app1:hosts:read", "inventory:hosts:write"])
        # self.expect_1_role_binding(resource=default_workspace(), v2_role=id, groups=["group_a2"])
        # self.expect_1_role_binding(resource=workspace("2"), v2_role=id, groups=["group_a2"])


class RbacFixture:
    """RBAC Fixture."""

    def __init__(self):
        """Initialize the RBAC fixture."""
        self.public_tenant = Tenant.objects.create(tenant_name="public")

    def new_tenant(self, name: str, org_id: str) -> Tenant:
        """Create a new tenant with the given name and organization ID."""
        return Tenant.objects.create(tenant_name=name, org_id=org_id)

    def new_system_role(self, name: str, permissions: list[str]) -> Role:
        """Create a new system role with the given name and permissions."""
        role = Role.objects.create(name=name, system=True, tenant=self.public_tenant)

        access_list = [
            Access(
                permission=Permission.objects.get_or_create(permission=permission, tenant=self.public_tenant)[0],
                role=role,
            )
            for permission in permissions
        ]

        Access.objects.bulk_create(access_list)

        return role

    def new_custom_role(self, name: str, resource_access: list[tuple[list[str], dict]], tenant: Tenant) -> Role:
        """
        Create a new custom role.

        [resource_access] is a list of tuples of the form (permissions, attribute_filter).
        """
        role = Role.objects.create(name=name, system=True, tenant=tenant)

        for permissions, attribute_filter in resource_access:
            access_list = [
                Access(
                    permission=Permission.objects.get_or_create(permission=permission, tenant=tenant)[0],
                    role=role,
                    tenant=tenant,
                )
                for permission in permissions
            ]

            Access.objects.bulk_create(access_list)

            if attribute_filter:
                for access in access_list:
                    ResourceDefinition.objects.create(attributeFilter=attribute_filter, access=access, tenant=tenant)

        return role

    def new_group(self, name: str, users: list[str], tenant: Tenant) -> Group:
        """Create a new group with the given name, users, and tenant."""
        group = Group.objects.create(name=name, tenant=tenant)

        principals = [Principal.objects.get_or_create(username=username, tenant=tenant)[0] for username in users]

        group.principals.add(*principals)

        return group

    def add_role_to_group(self, role: Role, group: Group, tenant: Tenant) -> Policy:
        """Add a role to a group for a given tenant and return the policy."""
        policy, _ = Policy.objects.get_or_create(name=f"System Policy_{group.name}", group=group, tenant=tenant)
        policy.roles.add(role)
        policy.save()
        return policy
