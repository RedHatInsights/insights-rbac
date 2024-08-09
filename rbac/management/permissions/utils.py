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
"""Defines the Access Permissions Utility Class."""

from rest_framework import permissions

SCOPE_KEY = "scope"
ORG_ID_SCOPE = "org_id"
PRINCIPAL_SCOPE = "principal"


def is_scope_principal(request):
    """Check permission based on the defined scope principal query param."""
    if request.method not in permissions.SAFE_METHODS:
        return False

    scope = request.query_params.get(SCOPE_KEY, ORG_ID_SCOPE)
    return scope == PRINCIPAL_SCOPE
