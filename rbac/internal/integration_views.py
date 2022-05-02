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

from django.http import HttpResponseBadRequest
from django.shortcuts import redirect, reverse
from management.cache import TenantCache


logger = logging.getLogger(__name__)
TENANTS = TenantCache()


def groups(request, account_number):
    """Formant and pass internal groups request to /groups/ API."""
    username = request.GET.get("username")
    if username:
        base_url = reverse("group-list")
        url = f"{base_url}?principals={username}"
        return redirect(url)
    else:
        return HttpResponseBadRequest("Username must be supplied.")


def groups_for_principal(request, account_number, username):
    """Format and pass internal groups for principal request to /groups/ API."""
    base_url = reverse("group-list")
    url = f"{base_url}?principals={username}"
    return redirect(url)


def roles_from_group(request, account_number, uuid):
    """Pass internal /groups/<uuid>/roles/ request to /groups/ API."""
    return redirect("group-roles", uuid=uuid)


def roles_for_group_principal(request, account_number, username, uuid):
    """Pass internal /principal/<username>/groups/<uuid>/roles/ request to /groups/ API."""
    base_url = reverse("group-roles", kwargs={"uuid": uuid})
    url = f"{base_url}?principals={username}"
    return redirect(url)
