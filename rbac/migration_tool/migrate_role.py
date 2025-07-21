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
from management.workspace.model import Workspace
from migration_tool.models import V2rolebinding


def get_kessel_relation_tuples(
    v2_role_bindings: Iterable[V2rolebinding],
    default_workspace: Workspace,
) -> list[common_pb2.Relationship]:
    """Generate a set of relationships and BindingMappings for the given set of v2 role bindings."""
    relationships: list[common_pb2.Relationship] = list()

    for v2_role_binding in v2_role_bindings:
        relationships.extend(v2_role_binding.as_tuples())

    return relationships
