# Copyright 2024 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""URL configuration for the V2 management API.

This module aggregates all V2 resource-level URL configurations.
Each resource (role, workspace, etc.) defines its own urls.py with its routes.
"""

from django.urls import include, path

# pylint: disable=invalid-name
urlpatterns = [
    path("", include("management.api.v2.role.urls")),
    path("", include("management.api.v2.role_binding.urls")),
    path("", include("management.api.v2.workspace.urls")),
]
