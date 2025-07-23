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

"""Helpers for performing operations on BindingMappings and RoleBindings simultaneously."""
from kessel.relations.v1beta1.common_pb2 import Relationship
from typing import Optional

from management.role.model import BindingMapping
from management.role_binding.model import RoleBinding


def _dual_call(left_fn, right_fn, *args, **kwargs):
    """Call the two functions with the provided arguments, assert that the results are equal, then return the result."""
    left_result = left_fn(*args, **kwargs)
    right_result = right_fn(*args, **kwargs)

    assert left_result == right_result

    return left_result


def _dual_call_pure(left_fn, right_fn, *args, **kwargs):
    left_result = left_fn(*args, **kwargs)

    # If the functions are pure, we only have to call the second function if we are going to actually verify the result.
    # So, we put the call in the assert statement.
    assert left_result == right_fn(*args, **kwargs)

    return left_result


def dual_binding_add_group(mapping: BindingMapping, binding: RoleBinding, group_uuid: str) -> Optional[Relationship]:
    """Call BindingMapping.add_group_to_bindings and RoleBinding.add_group and assert they have the same result."""
    return _dual_call(mapping.add_group_to_bindings, binding.add_group, group_uuid=group_uuid)


def dual_binding_pop_group(mapping: BindingMapping, binding: RoleBinding, group_uuid: str) -> Optional[Relationship]:
    """Call BindingMapping.pop_group_from_bindings and RoleBinding.pop_group and assert they have the same result."""
    return _dual_call(mapping.pop_group_from_bindings, binding.pop_group, group_uuid=group_uuid)


def dual_binding_assign_group(
    mapping: BindingMapping, binding: RoleBinding, group_uuid: str
) -> Optional[Relationship]:
    """Call BindingMapping.assign_group_to_bindings and RoleBinding.assign_group and assert they have the same
    result."""
    return _dual_call(mapping.assign_group_to_bindings, binding.assign_group, group_uuid=group_uuid)


def dual_binding_unassign_group(
    mapping: BindingMapping, binding: RoleBinding, group_uuid: str
) -> Optional[Relationship]:
    """Call BindingMapping.unassign_group and RoleBinding.unassign_group and assert they have the same result."""
    return _dual_call(mapping.unassign_group, binding.unassign_group, group_uuid=group_uuid)


def dual_binding_is_unassigned(mapping: BindingMapping, binding: RoleBinding) -> bool:
    """Call BindingMapping.is_unassigned and RoleBinding.is_unassigned and assert they have the same result."""
    return _dual_call_pure(mapping.is_unassigned, binding.is_unassigned)
