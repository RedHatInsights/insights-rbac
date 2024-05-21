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

from typing import Tuple

from management.role.model import Role
from migration_tool.models import V1permission, V1resourcedef, V1role


def extract_info_into_v1_role(role: Role):
    """Extract the information from the role and returns a V1role object."""
    perm_res_defs: dict[Tuple[str, str], list[V1resourcedef]] = {}
    roles: dict[str, list[str]] = {}
    role_id = f"{role.id}"
    for access in role.access.all():
        for resource_def in access.resourceDefinitions.all():
            attri_filter = resource_def.attributeFilter
            res_def = V1resourcedef(attri_filter["key"], attri_filter["operation"], str(attri_filter["value"]))
            if res_def.resource_id != "":
                add_element(perm_res_defs, (role_id, access.permission.permission), res_def)
        extend_unique(roles, role_id, access.permission.permission)
    v1_roles = []
    for role_id, perm_list in roles.items():
        v1_perms = []
        for perm in perm_list:
            perm_parts = perm.split(":")
            res_defs = [res_def for res_def in perm_res_defs.get((role_id, perm), [])]
            v1_perm = V1permission(perm_parts[0], perm_parts[1], perm_parts[2], frozenset(res_defs))
            v1_perms.append(v1_perm)
        v1_role = V1role(role_id, frozenset(v1_perms), frozenset())  # we don't get groups from the sheet
        v1_roles.append(v1_role)
    return v1_roles


def add_element(dict, key, value):
    """Add append value to dictionnary according to key."""
    if key not in dict:
        dict[key] = []
    dict[key].append(value)


def extend_unique(dict, key, value):
    """Add value to dictionnary according to key, values for each key is unique."""
    if key not in dict:
        dict[key] = []
    existing = set(dict[key])
    incoming = {value}
    existing |= incoming
    dict[key] = list(existing)
