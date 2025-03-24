"""
Copyright 2019 Red Hat, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from typing import Iterable

from kessel.relations.v1beta1 import common_pb2
from management.role.model import BindingMapping, Role
from management.workspace.model import Workspace
from migration_tool.models import V2rolebinding
from migration_tool.sharedSystemRolesReplicatedRoleBindings import v1_role_to_v2_bindings
from migration_tool.utils import create_relationship


def get_kessel_relation_tuples(
    v2_role_bindings: Iterable[V2rolebinding],
    default_workspace: Workspace,
) -> list[common_pb2.Relationship]:
    """Generate a set of relationships and BindingMappings for the given set of v2 role bindings."""
    relationships: list[common_pb2.Relationship] = list()

    for v2_role_binding in v2_role_bindings:
        relationships.extend(v2_role_binding.as_tuples())

        bound_resource = v2_role_binding.resource

        # Is this a workspace binding, but not to the root workspace?
        # If so, ensure this workspace is a child of the root workspace.
        # All other resource-resource or resource-workspace relations
        # which may be implied or necessary are intentionally ignored.
        # These should come from the apps that own the resource.
        if bound_resource.resource_type == ("rbac", "workspace") and not bound_resource.resource_id == str(
            default_workspace.id
        ):
            # This is not strictly necessary here and the relation may be a duplicate.
            # Once we have more Workspace API / Inventory Group migration progress,
            # this block can and probably should be removed.
            # One of those APIs will add it themselves.
            relationships.append(
                create_relationship(
                    bound_resource.resource_type,
                    bound_resource.resource_id,
                    ("rbac", "workspace"),
                    str(default_workspace.id),
                    "parent",
                )
            )

    return relationships


def migrate_role(
    role: Role,
    default_workspace: Workspace,
    current_bindings: Iterable[BindingMapping] = [],
) -> tuple[list[common_pb2.Relationship], list[BindingMapping]]:
    """
    Migrate a role from v1 to v2, returning the tuples and mappings.

    The mappings are returned so that we can reconstitute the corresponding tuples for a given role.
    This is needed so we can remove those tuples when the role changes if needed.
    """
    v2_role_bindings = v1_role_to_v2_bindings(role, default_workspace, current_bindings)
    relationships = get_kessel_relation_tuples([m.get_role_binding() for m in v2_role_bindings], default_workspace)
    return relationships, v2_role_bindings
