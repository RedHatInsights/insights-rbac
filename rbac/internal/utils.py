#
# Copyright 2022 Red Hat, Inc.
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

"""Utilities for Internal RBAC use."""

import logging

from django.http import HttpResponseForbidden
from django.urls import resolve

from api.models import User


logger = logging.getLogger(__name__)


def build_internal_user(request, json_rh_auth):
    """Build user object for internal requests."""
    user = User()
    try:
        if not json_rh_auth["identity"]["type"] == "Associate":
            return HttpResponseForbidden()
        user.username = json_rh_auth["identity"]["associate"]["email"]
        user.admin = True
        user.org_id = resolve(request.path).kwargs.get("org_id")
        if not user.org_id:
            user.org_id = json_rh_auth["identity"]["org_id"]
        return user
    except KeyError:
        logger.error("Malformed X-RH-Identity header.")
        return HttpResponseForbidden()
