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
"""Contains utilities for handling relations between V2 roles."""
from uuid import UUID
from kessel.relations.v1beta1.common_pb2 import Relationship
from migration_tool.utils import create_relationship


def role_child_relationship(parent_uuid: UUID | str, child_uuid: UUID | str) -> Relationship:
    """Get the relationship to for a parent-child relationship between the provided roles."""
    return create_relationship(
        resource_name=("rbac", "role"),
        resource_id=str(parent_uuid),
        subject_name=("rbac", "role"),
        subject_id=str(child_uuid),
        relation="child",
    )
