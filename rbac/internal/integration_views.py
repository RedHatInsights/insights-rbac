#
# Copyright 2020 Red Hat, Inc.
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

"""View for OCM group/role API."""

import logging

from management.cache import TenantCache
from management.group.view import GroupViewSet
from management.role.view import RoleViewSet


logger = logging.getLogger(__name__)
TENANTS = TenantCache()


def groups(request, org_id):
    """Format and pass internal groups request to /groups/ API."""
    view = GroupViewSet.as_view({"get": "list"})
    return view(request)


def roles(request, org_id):
    """Format and pass internal roles request to /roles/ API."""
    view = RoleViewSet.as_view({"get": "list"})
    return view(request)


def groups_for_principal(request, org_id, principals):
    """Format and pass /principal/<username>/groups/ request to /groups/ API."""
    view = GroupViewSet.as_view({"get": "list"})
    return view(request, principals=principals)


def roles_for_group(request, org_id, uuid):
    """Pass internal /groups/<uuid>/roles/ request to /groups/ API."""
    view = GroupViewSet.as_view({"get": "roles"})
    return view(request, uuid=uuid)


def roles_for_group_principal(request, org_id, principals, uuid):
    """Pass internal /principal/<username>/groups/<uuid>/roles/ request to /groups/ API."""
    view = GroupViewSet.as_view({"get": "roles"})
    return view(request, uuid=uuid, principals=principals)
