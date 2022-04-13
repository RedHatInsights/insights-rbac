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
"""Defines the Admin Access Permissions class."""
from django.urls import reverse
from management.utils import validate_and_get_key
from rest_framework import permissions

QUERY_BY_KEY = "query_by"
USER_ID = "user_id"
ACCOUNT = "target_account"
ORG_ID = "target_org"
VALID_QUERY_BY_KEY = [ACCOUNT, USER_ID]


class CrossAccountRequestAccessPermission(permissions.BasePermission):
    """Determines if a user is an Account Admin."""

    def has_permission(self, request, view):
        """Check permission based on identity and query by."""
        if request._request.path.startswith(reverse("cross-list")):
            if request.method == "POST":
                # Only allow associates create the request
                return request.user.internal

            if request.method in ["PUT", "PATCH"]:
                # The permission depends on the object to be updated, strict permission check in view.
                return True

            # For list
            query_by = validate_and_get_key(request.query_params, QUERY_BY_KEY, VALID_QUERY_BY_KEY, ACCOUNT)
            if query_by == ACCOUNT:
                return request.user.admin
            elif query_by == USER_ID:
                return request.user.internal
            return False

        if request.method not in permissions.SAFE_METHODS:
            return False

        return True
