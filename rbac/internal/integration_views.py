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
from audioop import reverse
import datetime
import json
import logging

import pytz
from django.conf import settings
from django.db import transaction
from django.db.migrations.recorder import MigrationRecorder
from django.http import Http404, HttpResponse
from django.shortcuts import redirect, reverse
from management import views
from management.cache import TenantCache
from management.models import Group, Role


from api.models import Tenant


logger = logging.getLogger(__name__)
TENANTS = TenantCache()

def groups(request, account_number):
    username = request.GET.get("username")
    if username:
        base_url = reverse("group-list")
        url = f'{base_url}?principals={username}'
        return redirect(url)
    else:
        return Http404

def groups_for_principal(request, account_number, username):
    base_url = reverse("group-list")
    url = f'{base_url}?principals={username}'
    return redirect(url)

def roles_from_group(request, account_number, uuid):
    return redirect("group-roles", uuid=uuid)

def roles_for_group(request, account_number, username, uuid):
    base_url = reverse("group-roles", kwargs={'uuid': uuid})
    url = f'{base_url}?principals={username}'
    return redirect(url)