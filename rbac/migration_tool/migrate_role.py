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
from migration_tool.models import V2boundresource, V2rolebinding
from migration_tool.sharedSystemRolesReplicatedRoleBindings import v1_role_to_v2_bindings


def _get_kessel_relation_tuples(
    v2_role_bindings: Iterable[V2rolebinding],
) -> list[common_pb2.Relationship]:
    relationships: list[common_pb2.Relationship] = list()

    for v2_role_binding in v2_role_bindings:
        relationships.extend(v2_role_binding.as_tuples())

    return relationships


def relation_tuples_for_bindings(bindings: Iterable[BindingMapping]) -> list[common_pb2.Relationship]:
    """Generate a set of relationships for a given set of BindingMappings."""
    return _get_kessel_relation_tuples([m.get_role_binding() for m in bindings])


def migrate_role(
    role: Role,
    default_resource: V2boundresource,
    current_bindings: Iterable[BindingMapping] = [],
) -> tuple[list[common_pb2.Relationship], list[BindingMapping]]:
    """
    Migrate a role from v1 to v2, returning the tuples and mappings.

    The mappings are returned so that we can reconstitute the corresponding tuples for a given role.
    This is needed so we can remove those tuples when the role changes if needed.
    """
    v2_role_bindings = v1_role_to_v2_bindings(role, default_resource, current_bindings)
    relationships = relation_tuples_for_bindings(v2_role_bindings)
    return relationships, v2_role_bindings
