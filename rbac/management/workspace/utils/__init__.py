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
"""Workspace utilities - public API exports."""

from .access import (
    get_access_permission_tuples,
    is_user_allowed,
    is_user_allowed_v1,
    is_user_allowed_v2,
    workspace_permission_tuple_set,
)
from .lookup import get_default_workspace_id, workspace_from_request
from .permission_map import PERM_MAP, operation_from_request, permission_from_request

__all__ = [
    # Permission mapping
    "PERM_MAP",
    "operation_from_request",
    "permission_from_request",
    # Workspace lookup
    "get_default_workspace_id",
    "workspace_from_request",
    # Access checking
    "is_user_allowed",
    "is_user_allowed_v1",
    "is_user_allowed_v2",
    "get_access_permission_tuples",
    "workspace_permission_tuple_set",
]
